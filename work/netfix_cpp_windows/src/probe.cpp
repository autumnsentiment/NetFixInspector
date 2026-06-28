#include "probe.h"

#include <array>
#include <algorithm>
#include <chrono>
#include <iterator>
#include <random>
#include <sstream>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "util.h"

namespace netfix {
namespace {

struct Endpoint {
    std::string host;
    int port = 443;
    std::string label;
};

struct TcpResult {
    bool ok = false;
    std::string family;
    std::string host;
    int port = 0;
    std::string label;
    std::string remote;
    std::string local;
    std::string error;
    uint64_t duration_ms = 0;
};

struct PortStats {
    std::string key;
    std::string family;
    std::string host;
    int port = 0;
    int attempts = 0;
    int successes = 0;
    int timeouts = 0;
    int icmp_unreachables = 0;
    uint64_t total_ms = 0;
    std::string last_error;
    std::vector<std::string> remotes;
};

std::vector<Endpoint> default_v4_targets() {
    return {{"1.1.1.1", 443, "Cloudflare HTTPS"}, {"8.8.8.8", 53, "Google DNS TCP"}, {"223.5.5.5", 443, "AliDNS HTTPS"}};
}

std::vector<Endpoint> default_v6_targets() {
    return {{"2606:4700:4700::1111", 443, "Cloudflare IPv6 HTTPS"}, {"2001:4860:4860::8888", 53, "Google IPv6 DNS TCP"}, {"2400:3200::1", 443, "AliDNS IPv6 HTTPS"}};
}

std::vector<std::string> default_dns_names(const Options& options) {
    if (!options.dns_names.empty()) return options.dns_names;
    return {"example.com", "cloudflare.com"};
}

Endpoint parse_endpoint(const std::string& raw, int default_port) {
    Endpoint ep;
    std::string value = raw;
    ep.label = raw;
    auto eq = value.find('=');
    if (eq != std::string::npos) {
        ep.label = value.substr(0, eq);
        value = value.substr(eq + 1);
    }
    if (!value.empty() && value[0] == '[') {
        auto end = value.find(']');
        ep.host = value.substr(1, end - 1);
        ep.port = default_port;
        if (end != std::string::npos && end + 2 < value.size() && value[end + 1] == ':') {
            ep.port = std::stoi(value.substr(end + 2));
        }
        return ep;
    }
    if (std::count(value.begin(), value.end(), ':') == 1) {
        auto pos = value.rfind(':');
        ep.host = value.substr(0, pos);
        ep.port = std::stoi(value.substr(pos + 1));
    } else {
        ep.host = value;
        ep.port = default_port;
    }
    return ep;
}

std::string endpoint_key(const Endpoint& ep, const std::string& family) {
    return family + "|" + ep.host + "|" + std::to_string(ep.port);
}

bool wants_ipv4(const Options& options) {
    return options.port_family == "both" || options.port_family == "ipv4" || options.port_family == "4";
}

bool wants_ipv6(const Options& options) {
    return options.port_family == "both" || options.port_family == "ipv6" || options.port_family == "6";
}

std::string socket_error_text(int code = WSAGetLastError()) {
    LPWSTR message = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   reinterpret_cast<LPWSTR>(&message), 0, nullptr);
    std::string text = message ? wide_to_utf8(message) : ("WSA error " + std::to_string(code));
    if (message) LocalFree(message);
    while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == '.')) text.pop_back();
    return text;
}

TcpResult tcp_probe(const Endpoint& ep, int family, double timeout_seconds) {
    auto start = std::chrono::steady_clock::now();
    TcpResult result;
    result.family = family == AF_INET6 ? "IPv6" : "IPv4";
    result.host = ep.host;
    result.port = ep.port;
    result.label = ep.label;
    addrinfo hints{};
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* infos = nullptr;
    std::string port = std::to_string(ep.port);
    int gai = getaddrinfo(ep.host.c_str(), port.c_str(), &hints, &infos);
    if (gai != 0) {
        result.error = "getaddrinfo failed: " + std::to_string(gai);
        result.duration_ms = elapsed_ms(start);
        return result;
    }
    for (addrinfo* ai = infos; ai; ai = ai->ai_next) {
        SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        u_long nonblocking = 1;
        ioctlsocket(s, FIONBIO, &nonblocking);
        int rc = connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        if (rc == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set write_set;
            FD_ZERO(&write_set);
            FD_SET(s, &write_set);
            timeval tv{};
            tv.tv_sec = static_cast<long>(timeout_seconds);
            tv.tv_usec = static_cast<long>((timeout_seconds - tv.tv_sec) * 1000000);
            rc = select(0, nullptr, &write_set, nullptr, &tv);
            if (rc > 0) {
                int err = 0;
                int len = sizeof(err);
                getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
                if (err == 0) {
                    result.ok = true;
                } else {
                    result.error = socket_error_text(err);
                }
            } else if (rc == 0) {
                result.error = "timed out";
            } else {
                result.error = socket_error_text();
            }
        } else if (rc == 0) {
            result.ok = true;
        } else {
            result.error = socket_error_text();
        }
        if (result.ok) {
            char remote[INET6_ADDRSTRLEN]{};
            if (ai->ai_family == AF_INET) {
                inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(ai->ai_addr)->sin_addr, remote, sizeof(remote));
            } else {
                inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(ai->ai_addr)->sin6_addr, remote, sizeof(remote));
            }
            sockaddr_storage local{};
            int local_len = sizeof(local);
            if (getsockname(s, reinterpret_cast<sockaddr*>(&local), &local_len) == 0) {
                char local_buf[INET6_ADDRSTRLEN]{};
                if (local.ss_family == AF_INET) inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(&local)->sin_addr, local_buf, sizeof(local_buf));
                if (local.ss_family == AF_INET6) inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(&local)->sin6_addr, local_buf, sizeof(local_buf));
                result.local = local_buf;
            }
            result.remote = remote;
            closesocket(s);
            break;
        }
        closesocket(s);
    }
    freeaddrinfo(infos);
    result.duration_ms = elapsed_ms(start);
    return result;
}

TcpResult udp_probe(const Endpoint& ep, int family, double timeout_seconds) {
    auto start = std::chrono::steady_clock::now();
    TcpResult result;
    result.family = family == AF_INET6 ? "IPv6" : "IPv4";
    result.host = ep.host;
    result.port = ep.port;
    result.label = ep.label;
    addrinfo hints{};
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    addrinfo* infos = nullptr;
    std::string port = std::to_string(ep.port);
    int gai = getaddrinfo(ep.host.c_str(), port.c_str(), &hints, &infos);
    if (gai != 0) {
        result.error = "getaddrinfo failed: " + std::to_string(gai);
        result.duration_ms = elapsed_ms(start);
        return result;
    }
    for (addrinfo* ai = infos; ai; ai = ai->ai_next) {
        SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        DWORD timeout_ms = static_cast<DWORD>(timeout_seconds * 1000);
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
        const char payload[] = "\x00";
        int sent = sendto(s, payload, 1, 0, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        if (sent == SOCKET_ERROR) {
            result.error = "sendto failed: " + socket_error_text();
            closesocket(s);
            continue;
        }
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(s, &read_set);
        timeval tv{};
        tv.tv_sec = static_cast<long>(timeout_seconds);
        tv.tv_usec = static_cast<long>((timeout_seconds - tv.tv_sec) * 1000000);
        int rc = select(0, &read_set, nullptr, nullptr, &tv);
        if (rc > 0 && FD_ISSET(s, &read_set)) {
            char buf[256];
            int received = recvfrom(s, buf, sizeof(buf), 0, nullptr, nullptr);
            if (received >= 0) {
                result.ok = true;
                result.remote = ep.host + ":" + std::to_string(ep.port);
            } else {
                int err = WSAGetLastError();
                if (err == WSAECONNRESET) {
                    result.error = "ICMP port unreachable";
                } else {
                    result.error = socket_error_text(err);
                }
            }
        } else if (rc == 0) {
            result.error = "timeout (open/filtered/silent)";
        } else {
            result.error = "select failed: " + socket_error_text();
        }
        closesocket(s);
        result.duration_ms = elapsed_ms(start);
        if (result.ok) break;
    }
    freeaddrinfo(infos);
    if (result.duration_ms == 0) result.duration_ms = elapsed_ms(start);
    return result;
}

std::vector<uint8_t> encode_dns_name(const std::string& name) {
    std::vector<uint8_t> out;
    size_t pos = 0;
    while (pos < name.size()) {
        size_t dot = name.find('.', pos);
        if (dot == std::string::npos) dot = name.size();
        size_t len = dot - pos;
        out.push_back(static_cast<uint8_t>(len));
        out.insert(out.end(), name.begin() + static_cast<ptrdiff_t>(pos), name.begin() + static_cast<ptrdiff_t>(dot));
        pos = dot + 1;
    }
    out.push_back(0);
    return out;
}

bool read_dns_name(const std::vector<uint8_t>& packet, size_t& offset, std::string& name, int depth = 0) {
    if (depth > 8) return false;
    std::vector<std::string> labels;
    size_t pos = offset;
    bool jumped = false;
    while (pos < packet.size()) {
        uint8_t len = packet[pos];
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= packet.size()) return false;
            uint16_t ptr = static_cast<uint16_t>(((len & 0x3F) << 8) | packet[pos + 1]);
            size_t ptr_offset = ptr;
            std::string suffix;
            if (!read_dns_name(packet, ptr_offset, suffix, depth + 1)) return false;
            labels.push_back(suffix);
            pos += 2;
            jumped = true;
            break;
        }
        if (len == 0) {
            ++pos;
            break;
        }
        ++pos;
        if (pos + len > packet.size()) return false;
        labels.emplace_back(reinterpret_cast<const char*>(packet.data() + pos), reinterpret_cast<const char*>(packet.data() + pos + len));
        pos += len;
    }
    name = join(labels, ".");
    if (!jumped || offset < pos) offset = pos;
    return true;
}

struct DnsQueryResult {
    bool ok = false;
    std::string server;
    std::string name;
    std::string qtype;
    std::vector<std::string> answers;
    std::string error;
    uint64_t duration_ms = 0;
};

DnsQueryResult direct_dns_query(const std::string& server, const std::string& name, uint16_t qtype, double timeout_seconds) {
    auto start = std::chrono::steady_clock::now();
    DnsQueryResult result;
    result.server = server;
    result.name = name;
    result.qtype = qtype == 28 ? "AAAA" : "A";
    int family = server.find(':') == std::string::npos ? AF_INET : AF_INET6;
    SOCKET s = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        result.error = socket_error_text();
        return result;
    }
    DWORD timeout_ms = static_cast<DWORD>(timeout_seconds * 1000);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    sockaddr_storage addr{};
    int addr_len = family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    if (family == AF_INET) {
        auto* a = reinterpret_cast<sockaddr_in*>(&addr);
        a->sin_family = AF_INET;
        a->sin_port = htons(53);
        inet_pton(AF_INET, server.c_str(), &a->sin_addr);
    } else {
        auto* a = reinterpret_cast<sockaddr_in6*>(&addr);
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(53);
        inet_pton(AF_INET6, server.c_str(), &a->sin6_addr);
    }
    std::mt19937 rng(static_cast<unsigned>(std::chrono::steady_clock::now().time_since_epoch().count()));
    uint16_t id = static_cast<uint16_t>(rng());
    std::vector<uint8_t> packet;
    auto push16 = [&](uint16_t v) { packet.push_back(static_cast<uint8_t>(v >> 8)); packet.push_back(static_cast<uint8_t>(v & 0xff)); };
    push16(id); push16(0x0100); push16(1); push16(0); push16(0); push16(0);
    auto encoded = encode_dns_name(name);
    packet.insert(packet.end(), encoded.begin(), encoded.end());
    push16(qtype); push16(1);
    int sent = sendto(s, reinterpret_cast<const char*>(packet.data()), static_cast<int>(packet.size()), 0, reinterpret_cast<sockaddr*>(&addr), addr_len);
    if (sent == SOCKET_ERROR) {
        result.error = socket_error_text();
        closesocket(s);
        result.duration_ms = elapsed_ms(start);
        return result;
    }
    std::array<uint8_t, 4096> buf{};
    int received = recvfrom(s, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0, nullptr, nullptr);
    if (received == SOCKET_ERROR) {
        result.error = socket_error_text();
        closesocket(s);
        result.duration_ms = elapsed_ms(start);
        return result;
    }
    closesocket(s);
    std::vector<uint8_t> response(buf.begin(), buf.begin() + received);
    if (response.size() < 12) {
        result.error = "short DNS response";
        result.duration_ms = elapsed_ms(start);
        return result;
    }
    uint16_t ancount = static_cast<uint16_t>((response[6] << 8) | response[7]);
    size_t offset = 12;
    std::string ignored;
    if (!read_dns_name(response, offset, ignored) || offset + 4 > response.size()) {
        result.error = "invalid DNS question";
        result.duration_ms = elapsed_ms(start);
        return result;
    }
    offset += 4;
    for (uint16_t i = 0; i < ancount && offset + 12 <= response.size(); ++i) {
        std::string answer_name;
        if (!read_dns_name(response, offset, answer_name) || offset + 10 > response.size()) break;
        uint16_t type = static_cast<uint16_t>((response[offset] << 8) | response[offset + 1]);
        uint16_t rdlen = static_cast<uint16_t>((response[offset + 8] << 8) | response[offset + 9]);
        offset += 10;
        if (offset + rdlen > response.size()) break;
        char text[INET6_ADDRSTRLEN]{};
        if (type == 1 && rdlen == 4) {
            inet_ntop(AF_INET, response.data() + offset, text, sizeof(text));
            result.answers.push_back(text);
        } else if (type == 28 && rdlen == 16) {
            inet_ntop(AF_INET6, response.data() + offset, text, sizeof(text));
            result.answers.push_back(text);
        }
        offset += rdlen;
    }
    result.ok = !result.answers.empty() || ancount > 0;
    if (!result.ok) result.error = "no answers";
    result.duration_ms = elapsed_ms(start);
    return result;
}

struct StunResult {
    bool ok = false;
    std::string host;
    std::string mapped_ip;
    uint16_t mapped_port = 0;
    std::string error;
};

StunResult stun_binding(const std::string& host, int port, double timeout_seconds, SOCKET shared_socket) {
    StunResult result;
    result.host = host;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* infos = nullptr;
    int gai = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &infos);
    if (gai != 0 || !infos) {
        result.error = "getaddrinfo failed: " + std::to_string(gai);
        return result;
    }
    std::array<uint8_t, 20> packet{};
    packet[1] = 0x01;
    packet[4] = 0x21; packet[5] = 0x12; packet[6] = 0xA4; packet[7] = 0x42;
    std::mt19937 rng(static_cast<unsigned>(std::chrono::steady_clock::now().time_since_epoch().count()));
    for (size_t i = 8; i < packet.size(); ++i) packet[i] = static_cast<uint8_t>(rng());
    DWORD timeout_ms = static_cast<DWORD>(timeout_seconds * 1000);
    setsockopt(shared_socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    int sent = sendto(shared_socket, reinterpret_cast<const char*>(packet.data()), static_cast<int>(packet.size()), 0, infos->ai_addr, static_cast<int>(infos->ai_addrlen));
    freeaddrinfo(infos);
    if (sent == SOCKET_ERROR) {
        result.error = socket_error_text();
        return result;
    }
    std::array<uint8_t, 1024> buf{};
    int received = recvfrom(shared_socket, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0, nullptr, nullptr);
    if (received == SOCKET_ERROR) {
        result.error = socket_error_text();
        return result;
    }
    if (received < 20) {
        result.error = "short STUN response";
        return result;
    }
    size_t offset = 20;
    while (offset + 4 <= static_cast<size_t>(received)) {
        uint16_t attr_type = static_cast<uint16_t>((buf[offset] << 8) | buf[offset + 1]);
        uint16_t attr_len = static_cast<uint16_t>((buf[offset + 2] << 8) | buf[offset + 3]);
        offset += 4;
        if (offset + attr_len > static_cast<size_t>(received)) break;
        if ((attr_type == 0x0020 || attr_type == 0x0001) && attr_len >= 8 && buf[offset + 1] == 0x01) {
            uint16_t xport = static_cast<uint16_t>((buf[offset + 2] << 8) | buf[offset + 3]);
            std::array<uint8_t, 4> ip{};
            for (int i = 0; i < 4; ++i) ip[i] = buf[offset + 4 + i];
            if (attr_type == 0x0020) {
                xport ^= 0x2112;
                ip[0] ^= 0x21; ip[1] ^= 0x12; ip[2] ^= 0xA4; ip[3] ^= 0x42;
            }
            char text[INET_ADDRSTRLEN]{};
            inet_ntop(AF_INET, ip.data(), text, sizeof(text));
            result.ok = true;
            result.mapped_ip = text;
            result.mapped_port = xport;
            return result;
        }
        offset += attr_len + ((4 - (attr_len % 4)) % 4);
    }
    result.error = "mapped address not found";
    return result;
}

}  // namespace

void winsock_startup() {
    WSADATA data{};
    WSAStartup(MAKEWORD(2, 2), &data);
}

void winsock_cleanup() {
    WSACleanup();
}

void connectivity_check(Report& report, const Options& options) {
    std::vector<Endpoint> v4 = default_v4_targets();
    std::vector<Endpoint> v6 = default_v6_targets();
    for (const auto& raw : options.target_v4) v4.push_back(parse_endpoint(raw, 443));
    for (const auto& raw : options.target_v6) v6.push_back(parse_endpoint(raw, 443));
    std::vector<TcpResult> results;
    for (const auto& ep : v4) results.push_back(tcp_probe(ep, AF_INET, options.timeout_seconds));
    for (const auto& ep : v6) results.push_back(tcp_probe(ep, AF_INET6, options.timeout_seconds));
    bool v4_ok = false;
    bool v6_ok = false;
    Check check;
    check.name = "Connectivity";
    for (const auto& r : results) {
        if (r.ok && r.family == "IPv4") v4_ok = true;
        if (r.ok && r.family == "IPv6") v6_ok = true;
        check.highlights.push_back(r.family + " " + r.label + " " + r.host + ":" + std::to_string(r.port) + " " + (r.ok ? "ok" : ("fail (" + r.error + ")")));
    }
    check.status = Status::OK;
    if (!v4_ok && !v6_ok) {
        check.status = Status::FAIL;
        check.recommendations.push_back("No IPv4 or IPv6 TCP target was reachable. Check link state, gateway, firewall, or upstream outage.");
    } else if (!v4_ok || !v6_ok) {
        check.status = Status::WARN;
        if (!v4_ok) check.recommendations.push_back("IPv4 connectivity failed while IPv6 had at least one success.");
        if (!v6_ok) check.recommendations.push_back("IPv6 outbound connectivity failed or is not provisioned.");
    }
    check.summary = "IPv4 outbound=" + std::string(v4_ok ? "ok" : "failed") + ", IPv6 outbound=" + (v6_ok ? "ok" : "failed") + ".";
    add_check(report, std::move(check));
}

void port_ping_check(Report& report, const Options& options) {
    std::vector<Endpoint> targets;
    if (options.port_targets.empty()) {
        Endpoint ep;
        ep.host = options.port_host.empty() ? "example.com" : options.port_host;
        ep.port = options.port_number;
        ep.label = ep.host + ":" + std::to_string(ep.port);
        targets.push_back(ep);
    } else {
        for (const auto& raw : options.port_targets) {
            targets.push_back(parse_endpoint(raw, options.port_number));
        }
    }

    Check check;
    check.name = "Port ping";
    check.details["protocol"] = options.port_protocol;
    check.details["family"] = options.port_family;
    check.details["count"] = std::to_string(options.port_count);
    check.details["timeout_seconds"] = std::to_string(options.timeout_seconds);

    if (targets.empty()) {
        check.status = Status::FAIL;
        check.summary = "No TCP port target was provided.";
        check.recommendations.push_back("Use --host HOST --port N or --target HOST:PORT.");
        add_check(report, std::move(check));
        return;
    }

    std::vector<PortStats> stats;
    std::vector<std::string> attempt_highlights;
    auto record = [&](const TcpResult& result) {
        const std::string key = result.family + "|" + result.host + "|" + std::to_string(result.port);
        auto it = std::find_if(stats.begin(), stats.end(), [&](const PortStats& item) {
            return item.key == key;
        });
        if (it == stats.end()) {
            PortStats item;
            item.key = key;
            item.family = result.family;
            item.host = result.host;
            item.port = result.port;
            stats.push_back(item);
            it = std::prev(stats.end());
        }
        it->attempts++;
        if (result.ok) {
            it->successes++;
            it->total_ms += result.duration_ms;
            if (!result.remote.empty() &&
                std::find(it->remotes.begin(), it->remotes.end(), result.remote) == it->remotes.end()) {
                it->remotes.push_back(result.remote);
            }
        } else {
            if (result.error == "ICMP port unreachable") ++it->icmp_unreachables;
            else if (result.error.find("timeout") != std::string::npos) ++it->timeouts;
            it->last_error = result.error;
        }
        attempt_highlights.push_back(result.family + " " + result.host + ":" + std::to_string(result.port) +
                                     " attempt " + std::to_string(it->attempts) + "/" +
                                     std::to_string(options.port_count) + " " +
                                     (result.ok ? ("ok " + std::to_string(result.duration_ms) + "ms") :
                                                  ("fail (" + result.error + ")")));
    };

    for (const auto& target : targets) {
        for (int i = 0; i < options.port_count; ++i) {
            auto probe_fn = (options.port_protocol == "udp") ? udp_probe : tcp_probe;
            if (wants_ipv4(options)) {
                record(probe_fn(target, AF_INET, options.timeout_seconds));
            }
            if (wants_ipv6(options)) {
                record(probe_fn(target, AF_INET6, options.timeout_seconds));
            }
        }
    }

    int total_attempts = 0;
    int total_successes = 0;
    int reachable_groups = 0;
    for (const auto& item : stats) {
        total_attempts += item.attempts;
        total_successes += item.successes;
        if (item.successes > 0) ++reachable_groups;
        const uint64_t avg = item.successes > 0 ? item.total_ms / static_cast<uint64_t>(item.successes) : 0;
        std::string line = item.family + " " + item.host + ":" + std::to_string(item.port) +
                           " success=" + std::to_string(item.successes) + "/" + std::to_string(item.attempts);
        if (item.successes > 0) {
            line += " avg=" + std::to_string(avg) + "ms";
            if (!item.remotes.empty()) line += " remote=" + join(item.remotes, ",");
        } else if (!item.last_error.empty()) {
            line += " last_error=" + item.last_error;
        }
        check.highlights.push_back(line);
    }
    check.highlights.insert(check.highlights.end(), attempt_highlights.begin(), attempt_highlights.end());

    if (total_attempts == 0) {
        check.status = Status::FAIL;
        check.summary = std::string(options.port_protocol == "udp" ? "No UDP" : "No TCP") + " port probe was executed.";
        check.recommendations.push_back("Check --family, --host, --port, and --target arguments.");
    } else if (total_successes == 0) {
        int udp_timeouts = 0;
        int udp_icmp = 0;
        for (const auto& item : stats) {
            udp_timeouts += item.timeouts;
            udp_icmp += item.icmp_unreachables;
        }
        if (options.port_protocol == "udp" && udp_icmp > 0 && udp_timeouts == 0) {
            check.status = Status::FAIL;
            check.summary = "UDP port reported closed (ICMP unreachable).";
            check.recommendations.push_back("The target returned ICMP port-unreachable; the UDP port is likely closed.");
        } else if (options.port_protocol == "udp" && udp_timeouts > 0) {
            check.status = Status::WARN;
            check.summary = "UDP port did not respond (open/filtered/silent).";
            check.recommendations.push_back("UDP probes timed out. The port may be open but silent, filtered by a firewall, or the packet was dropped. Try a service-specific payload if possible.");
        } else {
            check.status = Status::FAIL;
            check.summary = std::string(options.port_protocol == "udp" ? "UDP" : "TCP") + " port unreachable over selected address family.";
            check.recommendations.push_back("Check DNS records, firewall policy, service listener, route, and whether the target supports the selected IP family.");
        }
    } else if (reachable_groups < static_cast<int>(stats.size()) || total_successes < total_attempts) {
        check.status = Status::WARN;
        check.summary = std::string(options.port_protocol == "udp" ? "UDP" : "TCP") + " port partially reachable.";
        check.recommendations.push_back("One address family or one attempt failed. Compare IPv4/IPv6 DNS, firewall, ISP filtering, and service bind addresses.");
    } else {
        check.status = Status::OK;
        check.summary = std::string(options.port_protocol == "udp" ? "UDP" : "TCP") + " port reachable over selected address family.";
    }

    check.details["targets"] = std::to_string(targets.size());
    check.details["attempts"] = std::to_string(total_attempts);
    check.details["successes"] = std::to_string(total_successes);
    add_check(report, std::move(check));
}

void dns_direct_check(Report& report, const Options& options) {
    std::vector<std::string> servers = dns_provider_servers(options.provider);
    for (const auto& server : options.dns_servers) {
        if (std::find(servers.begin(), servers.end(), server) == servers.end()) servers.push_back(server);
    }
    auto names = default_dns_names(options);
    int total = 0;
    int ok = 0;
    Check check;
    check.name = "DNS";
    for (const auto& server : servers) {
        for (const auto& name : names) {
            for (uint16_t qtype : {static_cast<uint16_t>(1), static_cast<uint16_t>(28)}) {
                ++total;
                auto result = direct_dns_query(server, name, qtype, options.timeout_seconds);
                if (result.ok) ++ok;
                check.highlights.push_back(server + " " + result.qtype + " " + name + ": " +
                                           (result.ok ? join(result.answers, ", ") : result.error));
            }
        }
    }
    check.status = Status::OK;
    if (ok == 0) {
        check.status = Status::FAIL;
        check.recommendations.push_back("Direct DNS queries to tested resolvers all failed; UDP/53 may be blocked or DNS is intercepted.");
    } else if (ok < total / 2) {
        check.status = Status::WARN;
        check.recommendations.push_back("Some direct DNS tests failed; compare IPv4/IPv6 resolver reachability and firewall policy.");
    }
    check.summary = "Direct DNS successes=" + std::to_string(ok) + "/" + std::to_string(total) + ".";
    check.details["successes"] = std::to_string(ok);
    check.details["total"] = std::to_string(total);
    add_check(report, std::move(check));
}

void nat_check(Report& report, const Options& options) {
    std::vector<Endpoint> servers = {{"stun.l.google.com", 19302, "stun.l.google.com"}, {"stun1.l.google.com", 19302, "stun1.l.google.com"}, {"stun.cloudflare.com", 3478, "stun.cloudflare.com"}};
    for (const auto& raw : options.stun_servers) servers.push_back(parse_endpoint(raw, 19302));
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = 0;
    bind(s, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr));
    std::vector<StunResult> results;
    for (const auto& ep : servers) results.push_back(stun_binding(ep.host, ep.port, options.timeout_seconds, s));
    closesocket(s);
    std::vector<std::string> mappings;
    Check check;
    check.name = "IPv4 NAT";
    for (const auto& result : results) {
        if (result.ok) {
            std::string mapping = result.mapped_ip + ":" + std::to_string(result.mapped_port);
            mappings.push_back(mapping);
            check.highlights.push_back(result.host + ": " + mapping);
        } else {
            check.highlights.push_back(result.host + ": " + result.error);
        }
    }
    std::sort(mappings.begin(), mappings.end());
    mappings.erase(std::unique(mappings.begin(), mappings.end()), mappings.end());
    if (mappings.empty()) {
        check.status = Status::FAIL;
        check.summary = "UDP blocked or STUN unreachable";
        check.recommendations.push_back("IPv4 UDP STUN failed. Check UDP filtering, captive portal, VPN, or upstream firewall.");
    } else if (mappings.size() > 1) {
        check.status = Status::WARN;
        check.summary = "Symmetric NAT / address-port dependent mapping";
        check.recommendations.push_back("Mapped IPv4 endpoint changed across STUN servers; peer-to-peer inbound UDP will usually need relay/TURN or port forwarding.");
    } else {
        check.status = Status::OK;
        check.summary = "Endpoint-independent IPv4 NAT mapping (cone-like; filtering not classified)";
        check.recommendations.push_back("This test classifies mapping behavior. Full-cone vs restricted-cone filtering needs a cooperative STUN server.");
    }
    check.details["unique_mappings"] = join(mappings, ",");
    add_check(report, std::move(check));
}

void ipv6_check(Report& report, const Options& options, const std::vector<InterfaceInfo>& interfaces) {
    auto global_v6 = global_ipv6_addresses(interfaces);
    auto targets = default_v6_targets();
    bool outbound_ok = false;
    Check check;
    check.name = "IPv6 stack";
    check.highlights.push_back("Global IPv6 addresses: " + (global_v6.empty() ? "-" : join(global_v6, ", ")));
    for (const auto& ep : targets) {
        auto result = tcp_probe(ep, AF_INET6, options.timeout_seconds);
        if (result.ok) outbound_ok = true;
        check.highlights.push_back("IPv6 outbound " + ep.label + ": " + (result.ok ? "ok" : result.error));
    }
    check.status = outbound_ok ? Status::OK : Status::WARN;
    if (global_v6.empty()) {
        check.status = Status::WARN;
        check.recommendations.push_back("No global IPv6 address was detected; inbound IPv6 cannot work without one.");
    }
    if (!outbound_ok) {
        check.recommendations.push_back("IPv6 outbound failed. Verify router advertisement, DHCPv6/prefix delegation, firewall, and DNS AAAA reachability.");
    }
    if (options.no_external_inbound) {
        check.highlights.push_back("IPv6 inbound external checker: skipped by --no-external-inbound");
    } else {
        check.highlights.push_back("IPv6 inbound external checker: not enabled in this native C++ build; use --no-external-inbound to suppress this note.");
        check.recommendations.push_back("C++ v1 starts with outbound/global IPv6 checks. External inbound API probing can be added on top of WinHTTP.");
    }
    check.summary = "Outbound=" + std::string(outbound_ok ? "ok" : "failed") + ", inbound=not verified.";
    add_check(report, std::move(check));
}

}  // namespace netfix
