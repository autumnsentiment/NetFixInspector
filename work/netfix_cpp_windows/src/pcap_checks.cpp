#include "pcap_checks.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <map>
#include <random>
#include <sstream>
#include <thread>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include "util.h"

namespace netfix {
namespace {

constexpr int kPcapErrbufSize = 256;
constexpr unsigned int kPcapNetmaskUnknown = 0xffffffffU;

using bpf_u_int32 = unsigned int;

struct pcap;
using pcap_t = pcap;

struct pcap_addr {
    pcap_addr* next;
    sockaddr* addr;
    sockaddr* netmask;
    sockaddr* broadaddr;
    sockaddr* dstaddr;
};

struct pcap_if {
    pcap_if* next;
    char* name;
    char* description;
    pcap_addr* addresses;
    bpf_u_int32 flags;
};
using pcap_if_t = pcap_if;

struct bpf_insn;
struct bpf_program {
    unsigned int bf_len;
    bpf_insn* bf_insns;
};

struct pcap_pkthdr {
    timeval ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};

using pcap_findalldevs_fn = int (*)(pcap_if_t**, char*);
using pcap_freealldevs_fn = void (*)(pcap_if_t*);
using pcap_open_live_fn = pcap_t* (*)(const char*, int, int, int, char*);
using pcap_close_fn = void (*)(pcap_t*);
using pcap_compile_fn = int (*)(pcap_t*, bpf_program*, const char*, int, bpf_u_int32);
using pcap_setfilter_fn = int (*)(pcap_t*, bpf_program*);
using pcap_freecode_fn = void (*)(bpf_program*);
using pcap_geterr_fn = const char* (*)(pcap_t*);
using pcap_next_ex_fn = int (*)(pcap_t*, pcap_pkthdr**, const unsigned char**);
using pcap_sendpacket_fn = int (*)(pcap_t*, const unsigned char*, int);

std::string windows_error_text(DWORD code) {
    if (code == 0) return "0";
    wchar_t* message = nullptr;
    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<wchar_t*>(&message),
        0,
        nullptr);
    std::string text = std::to_string(code);
    if (size && message) {
        text += " ";
        text += wide_to_utf8(message);
        while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ')) {
            text.pop_back();
        }
    }
    if (message) LocalFree(message);
    return text;
}

std::string local_ansi_to_utf8(const char* value) {
    if (!value || !*value) return {};
    int wide_len = MultiByteToWideChar(CP_ACP, 0, value, -1, nullptr, 0);
    if (wide_len <= 0) return value;
    std::wstring wide(static_cast<size_t>(wide_len), L'\0');
    MultiByteToWideChar(CP_ACP, 0, value, -1, wide.data(), wide_len);
    if (!wide.empty() && wide.back() == L'\0') {
        wide.pop_back();
    }
    return wide_to_utf8(wide);
}

struct PcapApi {
    HMODULE module = nullptr;
    bool attempted = false;
    std::string loaded_from;
    std::string error;

    pcap_findalldevs_fn pcap_findalldevs = nullptr;
    pcap_freealldevs_fn pcap_freealldevs = nullptr;
    pcap_open_live_fn pcap_open_live = nullptr;
    pcap_close_fn pcap_close = nullptr;
    pcap_compile_fn pcap_compile = nullptr;
    pcap_setfilter_fn pcap_setfilter = nullptr;
    pcap_freecode_fn pcap_freecode = nullptr;
    pcap_geterr_fn pcap_geterr = nullptr;
    pcap_next_ex_fn pcap_next_ex = nullptr;
    pcap_sendpacket_fn pcap_sendpacket = nullptr;

    template <typename T>
    bool load_symbol(T& target, const char* name) {
        target = reinterpret_cast<T>(GetProcAddress(module, name));
        if (!target) {
            error = std::string("Npcap function missing: ") + name;
            return false;
        }
        return true;
    }

    bool load() {
        if (attempted) return module != nullptr;
        attempted = true;

        const std::vector<std::wstring> candidates = {
            L"C:\\Windows\\System32\\Npcap\\wpcap.dll",
            L"C:\\Windows\\System32\\wpcap.dll",
            L"wpcap.dll",
        };

        DWORD last_error = 0;
        for (const auto& candidate : candidates) {
            HMODULE handle = nullptr;
            if (candidate.find(L"\\") != std::wstring::npos) {
                handle = LoadLibraryExW(candidate.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
            } else {
                handle = LoadLibraryW(candidate.c_str());
            }
            if (handle) {
                module = handle;
                loaded_from = wide_to_utf8(candidate);
                break;
            }
            last_error = GetLastError();
        }

        if (!module) {
            error = "Npcap runtime was not found. Install Npcap and enable WinPcap-compatible mode. Last Windows error=" +
                    windows_error_text(last_error);
            return false;
        }

        if (!load_symbol(pcap_findalldevs, "pcap_findalldevs") ||
            !load_symbol(pcap_freealldevs, "pcap_freealldevs") ||
            !load_symbol(pcap_open_live, "pcap_open_live") ||
            !load_symbol(pcap_close, "pcap_close") ||
            !load_symbol(pcap_compile, "pcap_compile") ||
            !load_symbol(pcap_setfilter, "pcap_setfilter") ||
            !load_symbol(pcap_freecode, "pcap_freecode") ||
            !load_symbol(pcap_geterr, "pcap_geterr") ||
            !load_symbol(pcap_next_ex, "pcap_next_ex")) {
            FreeLibrary(module);
            module = nullptr;
            loaded_from.clear();
            return false;
        }

        pcap_sendpacket = reinterpret_cast<pcap_sendpacket_fn>(GetProcAddress(module, "pcap_sendpacket"));
        return true;
    }
};

PcapApi& pcap_api() {
    static PcapApi api;
    return api;
}

void write_u32_be(std::vector<uint8_t>& packet, size_t offset, uint32_t value) {
    packet[offset] = static_cast<uint8_t>((value >> 24) & 0xff);
    packet[offset + 1] = static_cast<uint8_t>((value >> 16) & 0xff);
    packet[offset + 2] = static_cast<uint8_t>((value >> 8) & 0xff);
    packet[offset + 3] = static_cast<uint8_t>(value & 0xff);
}

template <size_t N>
void write_u32_be(std::array<uint8_t, N>& packet, size_t offset, uint32_t value) {
    packet[offset] = static_cast<uint8_t>((value >> 24) & 0xff);
    packet[offset + 1] = static_cast<uint8_t>((value >> 16) & 0xff);
    packet[offset + 2] = static_cast<uint8_t>((value >> 8) & 0xff);
    packet[offset + 3] = static_cast<uint8_t>(value & 0xff);
}

std::string u32_ip_text(uint32_t value) {
    in_addr addr{};
    addr.s_addr = htonl(value);
    char buffer[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &addr, buffer, sizeof(buffer));
    return buffer;
}

std::vector<std::string> active_dhcp_discover(double timeout_seconds, int discover_count, std::string& error) {
    std::vector<std::string> servers;
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        error = "socket failed";
        return servers;
    }

    BOOL yes = TRUE;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&yes), sizeof(yes));
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
    DWORD timeout_ms = static_cast<DWORD>(std::max(1.0, timeout_seconds) * 1000);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(68);
    if (bind(sock, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == SOCKET_ERROR) {
        error = "bind UDP/68 failed; run as Administrator or close DHCP client conflicts";
        closesocket(sock);
        return servers;
    }

    std::mt19937 rng(static_cast<unsigned>(std::chrono::steady_clock::now().time_since_epoch().count()));
    uint32_t xid = rng();
    std::array<uint8_t, 6> client_mac{
        static_cast<uint8_t>(0x02),
        static_cast<uint8_t>(rng() & 0xff),
        static_cast<uint8_t>(rng() & 0xff),
        static_cast<uint8_t>(rng() & 0xff),
        static_cast<uint8_t>(rng() & 0xff),
        static_cast<uint8_t>(rng() & 0xff),
    };

    std::vector<uint8_t> packet(244, 0);
    packet[0] = 1;
    packet[1] = 1;
    packet[2] = 6;
    write_u32_be(packet, 4, xid);
    packet[10] = 0x80;
    std::copy(client_mac.begin(), client_mac.end(), packet.begin() + 28);
    packet[236] = 99; packet[237] = 130; packet[238] = 83; packet[239] = 99;
    packet[240] = 53; packet[241] = 1; packet[242] = 1;
    packet[243] = 255;

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = INADDR_BROADCAST;
    dest.sin_port = htons(67);
    int sends = std::max(1, discover_count);
    for (int i = 0; i < sends; ++i) {
        if (sendto(sock, reinterpret_cast<const char*>(packet.data()), static_cast<int>(packet.size()), 0,
                   reinterpret_cast<sockaddr*>(&dest), sizeof(dest)) == SOCKET_ERROR) {
            error = "send DHCP Discover failed";
            closesocket(sock);
            return servers;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }

    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(static_cast<int>(std::max(1.0, timeout_seconds) * 1000));
    while (std::chrono::steady_clock::now() < deadline) {
        std::array<uint8_t, 1500> buffer{};
        sockaddr_in peer{};
        int peer_len = sizeof(peer);
        int received = recvfrom(sock, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0,
                                reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (received == SOCKET_ERROR) {
            break;
        }
        if (received < 240 || buffer[0] != 2) {
            continue;
        }
        uint32_t rx_xid = (static_cast<uint32_t>(buffer[4]) << 24) | (static_cast<uint32_t>(buffer[5]) << 16) |
                          (static_cast<uint32_t>(buffer[6]) << 8) | buffer[7];
        if (rx_xid != xid) {
            continue;
        }
        char peer_text[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &peer.sin_addr, peer_text, sizeof(peer_text));
        std::string server = peer_text;
        for (int offset = 240; offset + 1 < received;) {
            uint8_t code = buffer[offset++];
            if (code == 255) break;
            if (code == 0) continue;
            uint8_t len = buffer[offset++];
            if (offset + len > received) break;
            if (code == 54 && len == 4) {
                uint32_t server_ip = (static_cast<uint32_t>(buffer[offset]) << 24) |
                                     (static_cast<uint32_t>(buffer[offset + 1]) << 16) |
                                     (static_cast<uint32_t>(buffer[offset + 2]) << 8) |
                                     buffer[offset + 3];
                server = u32_ip_text(server_ip);
            }
            offset += len;
        }
        if (!server.empty() && std::find(servers.begin(), servers.end(), server) == servers.end()) {
            servers.push_back(server);
        }
    }
    closesocket(sock);
    return servers;
}

struct DeviceHandle {
    PcapApi* api = nullptr;
    pcap_t* handle = nullptr;

    DeviceHandle() = default;
    DeviceHandle(const DeviceHandle&) = delete;
    DeviceHandle& operator=(const DeviceHandle&) = delete;

    DeviceHandle(DeviceHandle&& other) noexcept {
        api = other.api;
        handle = other.handle;
        other.api = nullptr;
        other.handle = nullptr;
    }

    DeviceHandle& operator=(DeviceHandle&& other) noexcept {
        if (this != &other) {
            close();
            api = other.api;
            handle = other.handle;
            other.api = nullptr;
            other.handle = nullptr;
        }
        return *this;
    }

    ~DeviceHandle() {
        close();
    }

    void close() {
        if (handle && api && api->pcap_close) {
            api->pcap_close(handle);
        }
        handle = nullptr;
        api = nullptr;
    }
};

std::string pcap_error(PcapApi& api, pcap_t* handle) {
    if (!handle || !api.pcap_geterr) return {};
    return local_ansi_to_utf8(api.pcap_geterr(handle));
}

std::string choose_device(PcapApi& api, const std::string& interface_name, std::vector<std::string>& device_names) {
    char errbuf[kPcapErrbufSize]{};
    pcap_if_t* devices = nullptr;
    if (api.pcap_findalldevs(&devices, errbuf) != 0 || !devices) {
        if (errbuf[0]) device_names.push_back("pcap_findalldevs error: " + local_ansi_to_utf8(errbuf));
        return {};
    }
    std::string selected;
    for (pcap_if_t* dev = devices; dev; dev = dev->next) {
        std::string name = dev->name ? dev->name : "";
        std::string description = dev->description ? dev->description : "";
        device_names.push_back(description.empty() ? name : (description + " [" + name + "]"));
        if (selected.empty()) selected = name;
        if (!interface_name.empty() &&
            (description.find(interface_name) != std::string::npos || name.find(interface_name) != std::string::npos)) {
            selected = name;
        }
    }
    api.pcap_freealldevs(devices);
    return selected;
}

DeviceHandle open_capture(const std::string& interface_name, const char* filter, std::vector<std::string>& devices, std::string& error) {
    DeviceHandle device;
    PcapApi& api = pcap_api();
    if (!api.load()) {
        error = api.error;
        return device;
    }

    char errbuf[kPcapErrbufSize]{};
    std::string selected = choose_device(api, interface_name, devices);
    if (selected.empty()) {
        error = "Npcap did not return any capture device.";
        return device;
    }
    device.api = &api;
    device.handle = api.pcap_open_live(selected.c_str(), 65535, 1, 500, errbuf);
    if (!device.handle) {
        error = errbuf[0] ? local_ansi_to_utf8(errbuf) : "pcap_open_live failed";
        device.api = nullptr;
        return device;
    }
    bpf_program program{};
    if (api.pcap_compile(device.handle, &program, filter, 1, kPcapNetmaskUnknown) == 0) {
        if (api.pcap_setfilter(device.handle, &program) != 0) {
            error = pcap_error(api, device.handle);
        }
        api.pcap_freecode(&program);
    } else {
        error = pcap_error(api, device.handle);
    }
    return device;
}

std::string mac_text(const uint8_t* data) {
    char buf[32]{};
    sprintf_s(buf, "%02x:%02x:%02x:%02x:%02x:%02x", data[0], data[1], data[2], data[3], data[4], data[5]);
    return buf;
}

std::string ipv4_text(const uint8_t* data) {
    char buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, data, buf, sizeof(buf));
    return buf;
}

uint16_t be16(const uint8_t* data) {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
}

std::vector<uint8_t> mac_bytes_from_text(const std::string& mac) {
    std::vector<uint8_t> bytes;
    std::stringstream stream(mac);
    std::string part;
    while (std::getline(stream, part, ':')) {
        if (part.empty()) return {};
        char* end = nullptr;
        long value = std::strtol(part.c_str(), &end, 16);
        if (!end || *end != '\0' || value < 0 || value > 255) return {};
        bytes.push_back(static_cast<uint8_t>(value));
    }
    return bytes.size() == 6 ? bytes : std::vector<uint8_t>{};
}

std::vector<uint8_t> choose_source_mac(const std::vector<InterfaceInfo>& interfaces, const std::string& interface_name) {
    for (const auto& iface : interfaces) {
        if (!interface_name.empty() && iface.name != interface_name && iface.description.find(interface_name) == std::string::npos) {
            continue;
        }
        auto bytes = mac_bytes_from_text(iface.mac);
        if (!bytes.empty()) return bytes;
    }
    for (const auto& iface : interfaces) {
        if (!iface.up) continue;
        auto bytes = mac_bytes_from_text(iface.mac);
        if (!bytes.empty()) return bytes;
    }
    return {};
}

std::string extract_dhcp_server(const uint8_t* frame, unsigned int caplen) {
    if (caplen < 14) return {};
    uint16_t eth_type = be16(frame + 12);
    size_t ip_offset = 14;
    if (eth_type == 0x8100 && caplen >= 18) {
        eth_type = be16(frame + 16);
        ip_offset = 18;
    }
    if (eth_type != 0x0800 || caplen < ip_offset + 20) return {};
    const uint8_t* ip = frame + ip_offset;
    uint8_t ihl = static_cast<uint8_t>((ip[0] & 0x0f) * 4);
    if (ihl < 20 || caplen < ip_offset + ihl + 8) return {};
    const uint8_t* udp = ip + ihl;
    uint16_t sport = be16(udp);
    uint16_t dport = be16(udp + 2);
    if (sport != 67 && dport != 67 && sport != 68 && dport != 68) return {};
    const uint8_t* dhcp = udp + 8;
    size_t dhcp_len = caplen - static_cast<size_t>(dhcp - frame);
    if (dhcp_len < 240) return {};

    std::string server = (sport == 67) ? ipv4_text(ip + 12) : "";
    for (size_t offset = 240; offset + 1 < dhcp_len;) {
        uint8_t code = dhcp[offset++];
        if (code == 255) break;
        if (code == 0) continue;
        uint8_t len = dhcp[offset++];
        if (offset + len > dhcp_len) break;
        if (code == 54 && len == 4) {
            uint32_t server_ip = (static_cast<uint32_t>(dhcp[offset]) << 24) |
                                 (static_cast<uint32_t>(dhcp[offset + 1]) << 16) |
                                 (static_cast<uint32_t>(dhcp[offset + 2]) << 8) |
                                 dhcp[offset + 3];
            server = u32_ip_text(server_ip);
        }
        offset += len;
    }
    return server;
}

int send_loop_probes(DeviceHandle& capture, const std::vector<InterfaceInfo>& interfaces, const Options& options, std::string& note) {
    PcapApi& api = pcap_api();
    if (!capture.handle || !api.pcap_sendpacket) {
        note = "pcap_sendpacket is not available.";
        return 0;
    }
    auto source_mac = choose_source_mac(interfaces, options.interface_name);
    if (source_mac.empty()) {
        note = "No source MAC was available for active loop probes.";
        return 0;
    }
    std::array<uint8_t, 64> frame{};
    std::fill(frame.begin(), frame.begin() + 6, 0xff);
    std::copy(source_mac.begin(), source_mac.end(), frame.begin() + 6);
    frame[12] = 0x88;
    frame[13] = 0xb5;
    const char marker[] = "NFI-LOOP-PROBE";
    std::memcpy(frame.data() + 14, marker, sizeof(marker) - 1);
    uint32_t marker_id = static_cast<uint32_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    write_u32_be(frame, 30, marker_id);

    int sent = 0;
    for (int i = 0; i < std::max(0, options.loop_probes); ++i) {
        write_u32_be(frame, 34, static_cast<uint32_t>(i));
        if (api.pcap_sendpacket(capture.handle, frame.data(), static_cast<int>(frame.size())) == 0) {
            ++sent;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
    if (sent == 0 && options.loop_probes > 0) {
        note = "Active loop probes could not be injected; capture statistics are still usable.";
    }
    return sent;
}

std::vector<std::string> collect_configured_dhcp_servers(Check& check, const Options& options, int& dhcp_enabled_interfaces) {
    auto interfaces = collect_interfaces();
    std::vector<std::string> configured_servers;
    for (const auto& iface : interfaces) {
        if (!options.interface_name.empty() && iface.name != options.interface_name &&
            iface.description.find(options.interface_name) == std::string::npos) {
            continue;
        }
        if (iface.dhcp_enabled) {
            ++dhcp_enabled_interfaces;
            check.highlights.push_back("DHCP enabled: " + iface.name);
        }
        for (const auto& server : iface.dhcp_servers) {
            if (!server.empty() && std::find(configured_servers.begin(), configured_servers.end(), server) == configured_servers.end()) {
                configured_servers.push_back(server);
            }
        }
    }
    return configured_servers;
}

std::string availability_summary() {
    PcapApi& api = pcap_api();
    if (!api.load()) {
        return api.error;
    }
    return "Npcap loaded from " + api.loaded_from;
}

}  // namespace

void pcap_status_check(Report& report, const Options&) {
    Check check;
    check.name = "Npcap runtime";
    PcapApi& api = pcap_api();
    if (!api.load()) {
        check.status = Status::WARN;
        check.summary = "Npcap is not installed or cannot be loaded.";
        check.highlights.push_back(api.error);
        check.recommendations.push_back("Run Install-Npcap.bat, or install Npcap manually from https://npcap.com/.");
        check.recommendations.push_back("For bundled redistribution, place your licensed Npcap OEM installer beside the script or in third_party\\npcap.");
        check.details["loaded"] = "false";
        add_check(report, std::move(check));
        return;
    }

    char errbuf[kPcapErrbufSize]{};
    pcap_if_t* devices = nullptr;
    int count = 0;
    if (api.pcap_findalldevs(&devices, errbuf) == 0 && devices) {
        for (pcap_if_t* dev = devices; dev; dev = dev->next) {
            ++count;
            std::string name = dev->name ? dev->name : "";
            std::string description = dev->description ? dev->description : "";
            if (check.highlights.size() < 8) {
                check.highlights.push_back(description.empty() ? name : (description + " [" + name + "]"));
            }
        }
        api.pcap_freealldevs(devices);
    }

    check.status = count > 0 ? Status::OK : Status::WARN;
    check.summary = "Npcap loaded, capture devices=" + std::to_string(count) + ".";
    check.highlights.insert(check.highlights.begin(), "Loaded from: " + api.loaded_from);
    if (count == 0) {
        check.highlights.push_back(errbuf[0] ? local_ansi_to_utf8(errbuf) : "Npcap returned no capture devices.");
        check.recommendations.push_back("Run as Administrator and confirm the Npcap Packet Driver service is installed.");
    }
    check.details["loaded"] = "true";
    check.details["loaded_from"] = api.loaded_from;
    check.details["device_count"] = std::to_string(count);
    add_check(report, std::move(check));
}

void dhcp_check(Report& report, const Options& options) {
    Check check;
    check.name = "DHCP";

    int dhcp_enabled_interfaces = 0;
    std::vector<std::string> configured_servers = collect_configured_dhcp_servers(check, options, dhcp_enabled_interfaces);

    std::vector<std::string> active_servers;
    std::string active_error;
    if (options.dhcp_active) {
        active_servers = active_dhcp_discover(options.timeout_seconds, options.discover_count, active_error);
    }

    std::vector<std::string> devices;
    std::string capture_error;
    auto capture = open_capture(options.interface_name, "udp and (port 67 or 68)", devices, capture_error);
    int packets = 0;
    int broadcasts = 0;
    std::map<std::string, int> captured_server_counts;

    if (capture.handle) {
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(static_cast<int>(std::max(1.0, options.dhcp_seconds) * 1000));
        while (std::chrono::steady_clock::now() < deadline) {
            pcap_pkthdr* header = nullptr;
            const unsigned char* data = nullptr;
            int rc = capture.api->pcap_next_ex(capture.handle, &header, &data);
            if (rc <= 0 || !header || !data || header->caplen < 42) continue;
            ++packets;
            if (std::memcmp(data, "\xff\xff\xff\xff\xff\xff", 6) == 0) ++broadcasts;
            std::string server = extract_dhcp_server(data, header->caplen);
            if (!server.empty()) {
                captured_server_counts[server + " / " + mac_text(data + 6)]++;
            }
        }
    }

    std::vector<std::string> all_servers = configured_servers;
    for (const auto& server : active_servers) {
        if (std::find(all_servers.begin(), all_servers.end(), server) == all_servers.end()) {
            all_servers.push_back(server);
        }
    }
    for (const auto& pair : captured_server_counts) {
        const std::string& server = pair.first;
        int count = pair.second;
        std::string ip = server.substr(0, server.find(" / "));
        if (std::find(all_servers.begin(), all_servers.end(), ip) == all_servers.end()) {
            all_servers.push_back(ip);
        }
        check.highlights.push_back("Captured DHCP source " + server + " packets=" + std::to_string(count));
    }

    check.status = Status::OK;
    if (all_servers.empty()) {
        check.status = Status::WARN;
        check.recommendations.push_back("No DHCP server was found. Use DHCP-Active-Probe.bat as Administrator or capture longer with Npcap.");
    }
    if (all_servers.size() > 1) {
        check.status = Status::WARN;
        check.recommendations.push_back("Multiple DHCP sources were observed or configured. Verify whether all are authorized.");
    }
    if (!capture.handle) {
        check.highlights.push_back("Packet capture: unavailable");
        check.highlights.push_back("Npcap note: " + capture_error);
        check.recommendations.push_back("Install Npcap to count DHCP broadcasts and all LAN DHCP packets.");
    } else if (packets == 0) {
        check.status = Status::WARN;
        check.recommendations.push_back("No DHCP packets were captured. Increase --seconds or run --active during a safe maintenance window.");
    }

    check.summary = "DHCP enabled interfaces=" + std::to_string(dhcp_enabled_interfaces) +
                    ", DHCP source count=" + std::to_string(all_servers.size()) +
                    ", captured packets=" + std::to_string(packets) +
                    ", broadcasts=" + std::to_string(broadcasts) + ".";
    check.highlights.push_back("Windows DHCP servers: " + (configured_servers.empty() ? "-" : join(configured_servers, ", ")));
    check.highlights.push_back("Active DHCP Discover: " + std::string(options.dhcp_active ? "enabled" : "disabled"));
    if (options.dhcp_active) {
        check.highlights.push_back("Active Discover packets sent: " + std::to_string(std::max(1, options.discover_count)));
        check.highlights.push_back("Active DHCP servers: " + (active_servers.empty() ? "-" : join(active_servers, ", ")));
        if (!active_error.empty()) {
            check.highlights.push_back("Active probe note: " + active_error);
        }
    }
    check.highlights.push_back("DHCP source count: " + std::to_string(all_servers.size()));
    check.highlights.push_back("Captured DHCP packets: " + std::to_string(packets));
    check.highlights.push_back("DHCP broadcasts: " + std::to_string(broadcasts));
    check.details["configured_servers"] = join(configured_servers, ",");
    check.details["active_servers"] = join(active_servers, ",");
    check.details["source_count"] = std::to_string(all_servers.size());
    check.details["captured_packets"] = std::to_string(packets);
    check.details["broadcasts"] = std::to_string(broadcasts);
    check.details["pcap"] = capture.handle ? availability_summary() : capture_error;
    check.details["devices"] = join(devices, " | ");
    add_check(report, std::move(check));
}

void loop_check(Report& report, const Options& options, const std::vector<InterfaceInfo>& interfaces) {
    std::vector<std::string> devices;
    std::string error;
    auto capture = open_capture(options.interface_name, "ether broadcast or multicast or arp", devices, error);
    Check check;
    check.name = "LAN loop and broadcast storm";
    if (!capture.handle) {
        check.status = Status::SKIP;
        check.summary = "Packet-level loop detection is unavailable because Npcap cannot be loaded.";
        check.highlights.push_back("Npcap note: " + error);
        check.recommendations.push_back("Run Install-Npcap.bat, enable WinPcap-compatible mode, and run this command as Administrator.");
        check.details["pcap"] = error;
        add_check(report, std::move(check));
        return;
    }

    std::string probe_note;
    int probes_sent = send_loop_probes(capture, interfaces, options, probe_note);
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(static_cast<int>(std::max(1.0, options.loop_seconds) * 1000));
    int packets = 0;
    int broadcasts = 0;
    int probe_echoes = 0;
    std::map<std::string, int> source_counts;
    std::map<std::string, int> source_ip_counts;
    std::map<std::string, std::string> arp_claims;
    std::vector<std::string> duplicate_arp;
    while (std::chrono::steady_clock::now() < deadline) {
        pcap_pkthdr* header = nullptr;
        const unsigned char* data = nullptr;
        int rc = capture.api->pcap_next_ex(capture.handle, &header, &data);
        if (rc <= 0 || !header || !data || header->caplen < 14) continue;
        ++packets;
        bool is_broadcast = std::memcmp(data, "\xff\xff\xff\xff\xff\xff", 6) == 0;
        bool is_multicast = (data[0] & 0x01) != 0;
        if (is_broadcast || is_multicast) ++broadcasts;
        if (header->caplen >= 28 && std::memcmp(data + 14, "NFI-LOOP-PROBE", 14) == 0) {
            ++probe_echoes;
        }
        source_counts[mac_text(data + 6)]++;
        uint16_t eth_type = be16(data + 12);
        size_t payload_offset = 14;
        if (eth_type == 0x8100 && header->caplen >= 18) {
            eth_type = be16(data + 16);
            payload_offset = 18;
        }
        if (eth_type == 0x0800 && header->caplen >= payload_offset + 20) {
            const uint8_t* ip = data + payload_offset;
            source_ip_counts[ipv4_text(ip + 12)]++;
        }
        if (eth_type == 0x0806 && header->caplen >= payload_offset + 28) {
            const uint8_t* arp = data + payload_offset;
            std::string ip = ipv4_text(arp + 14);
            std::string mac = mac_text(arp + 8);
            auto it = arp_claims.find(ip);
            if (it != arp_claims.end() && it->second != mac) {
                std::string conflict = ip + " => " + it->second + ", " + mac;
                if (std::find(duplicate_arp.begin(), duplicate_arp.end(), conflict) == duplicate_arp.end()) {
                    duplicate_arp.push_back(conflict);
                }
            } else {
                arp_claims[ip] = mac;
            }
        }
    }

    double rate = broadcasts / std::max(1.0, options.loop_seconds);
    check.status = Status::OK;
    if (rate > options.broadcast_threshold || !duplicate_arp.empty() || probe_echoes > probes_sent + 1) {
        check.status = Status::WARN;
        if (rate > options.broadcast_threshold) {
            check.recommendations.push_back("Broadcast/multicast rate is high. Check switch loops, bad NICs, rogue bridges, or STP-disabled access switches.");
        }
        if (!duplicate_arp.empty()) {
            check.recommendations.push_back("The same IP was advertised by multiple MAC addresses; investigate duplicate IP or ARP spoofing.");
        }
        if (probe_echoes > probes_sent + 1) {
            check.recommendations.push_back("Active probe frames were observed more often than sent; inspect possible L2 loop or mirrored traffic.");
        }
    }
    if (packets == 0) {
        check.status = Status::WARN;
        check.recommendations.push_back("No packets were captured. Select --interface or run with packet capture privileges.");
    }
    check.summary = "Broadcast/multicast=" + std::to_string(broadcasts) +
                    " over " + std::to_string(options.loop_seconds) +
                    "s, active probes sent=" + std::to_string(probes_sent) + ".";
    check.highlights.push_back("Npcap: " + availability_summary());
    check.highlights.push_back("Packets captured: " + std::to_string(packets));
    check.highlights.push_back("Broadcast/multicast packets: " + std::to_string(broadcasts) + " (" + std::to_string(rate) + "/s)");
    check.highlights.push_back("Active loop probes sent: " + std::to_string(probes_sent));
    check.highlights.push_back("Loop probe frames observed: " + std::to_string(probe_echoes));
    if (!probe_note.empty()) {
        check.highlights.push_back("Probe note: " + probe_note);
    }
    int shown = 0;
    for (const auto& pair : source_counts) {
        if (shown++ >= 8) break;
        check.highlights.push_back("Top broadcast source mac=" + pair.first + " packets=" + std::to_string(pair.second));
    }
    shown = 0;
    for (const auto& pair : source_ip_counts) {
        if (shown++ >= 8) break;
        check.highlights.push_back("Top broadcast source ip=" + pair.first + " packets=" + std::to_string(pair.second));
    }
    for (const auto& conflict : duplicate_arp) {
        check.highlights.push_back("ARP conflict hint " + conflict);
    }
    check.details["pcap"] = availability_summary();
    check.details["devices"] = join(devices, " | ");
    check.details["packets"] = std::to_string(packets);
    check.details["broadcasts"] = std::to_string(broadcasts);
    check.details["active_probes_sent"] = std::to_string(probes_sent);
    check.details["probe_echoes"] = std::to_string(probe_echoes);
    add_check(report, std::move(check));
}

}  // namespace netfix
