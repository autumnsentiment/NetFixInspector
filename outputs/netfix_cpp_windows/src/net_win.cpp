#include "net_win.h"

#include <array>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include "util.h"

namespace netfix {
namespace {

std::string sockaddr_to_string(const SOCKADDR* addr) {
    char buffer[INET6_ADDRSTRLEN]{};
    if (!addr) return {};
    if (addr->sa_family == AF_INET) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(addr);
        inet_ntop(AF_INET, const_cast<IN_ADDR*>(&v4->sin_addr), buffer, sizeof(buffer));
    } else if (addr->sa_family == AF_INET6) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(addr);
        inet_ntop(AF_INET6, const_cast<IN6_ADDR*>(&v6->sin6_addr), buffer, sizeof(buffer));
    }
    return buffer;
}

std::string mac_to_string(const BYTE* address, ULONG length) {
    std::ostringstream out;
    for (ULONG i = 0; i < length; ++i) {
        if (i) out << ":";
        out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(address[i]);
    }
    return out.str();
}

bool is_link_local_v4(const std::string& ip) {
    return starts_with(ip, "169.254.");
}

bool is_global_v6_text(const std::string& ip) {
    std::string lower = to_lower(ip);
    return lower != "::1" && !starts_with(lower, "fe80:") && !starts_with(lower, "fc") && !starts_with(lower, "fd");
}

std::vector<std::string> build_dns_commands(const Options& options) {
    std::vector<std::string> servers = dns_provider_servers(options.set_dns);
    for (const auto& server : options.custom_dns) {
        if (std::find(servers.begin(), servers.end(), server) == servers.end()) {
            servers.push_back(server);
        }
    }
    std::vector<std::string> v4;
    std::vector<std::string> v6;
    for (const auto& server : servers) {
        if (server.find(':') == std::string::npos) v4.push_back(server);
        else v6.push_back(server);
    }
    std::vector<std::string> commands;
    if (servers.empty()) return commands;
    if (options.interface_name.empty()) {
        commands.push_back("NOTE: Windows DNS replacement needs --interface with the adapter alias.");
        return commands;
    }
    if (!v4.empty()) {
        commands.push_back("netsh interface ip set dns name=\"" + options.interface_name + "\" static " + v4[0] + " primary");
        for (size_t i = 1; i < v4.size(); ++i) {
            commands.push_back("netsh interface ip add dns name=\"" + options.interface_name + "\" " + v4[i] + " index=" + std::to_string(i + 1));
        }
    }
    if (!v6.empty()) {
        commands.push_back("netsh interface ipv6 set dnsservers \"" + options.interface_name + "\" static " + v6[0] + " primary");
        for (size_t i = 1; i < v6.size(); ++i) {
            commands.push_back("netsh interface ipv6 add dnsservers \"" + options.interface_name + "\" " + v6[i] + " index=" + std::to_string(i + 1));
        }
    }
    return commands;
}

int execute_shell_command(const std::string& command) {
    std::wstring wide = L"cmd.exe /C " + utf8_to_wide(command);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(nullptr, wide.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!ok) return -1;
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(code);
}

}  // namespace

std::vector<InterfaceInfo> collect_interfaces() {
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
    ULONG family = AF_UNSPEC;
    ULONG size = 16 * 1024;
    std::vector<BYTE> buffer(size);
    ULONG ret = GetAdaptersAddresses(family, flags, nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        ret = GetAdaptersAddresses(family, flags, nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    }
    std::vector<InterfaceInfo> interfaces;
    if (ret != NO_ERROR) {
        return interfaces;
    }
    for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); adapter; adapter = adapter->Next) {
        InterfaceInfo iface;
        iface.name = wide_to_utf8(adapter->FriendlyName ? adapter->FriendlyName : L"");
        iface.description = wide_to_utf8(adapter->Description ? adapter->Description : L"");
        iface.up = adapter->OperStatus == IfOperStatusUp;
        iface.speed_mbps = adapter->TransmitLinkSpeed / 1000000ULL;
        iface.mtu = adapter->Mtu;
        iface.mac = mac_to_string(adapter->PhysicalAddress, adapter->PhysicalAddressLength);
        iface.dhcp_enabled = (adapter->Flags & IP_ADAPTER_DHCP_ENABLED) != 0;
        std::string dhcp_v4 = sockaddr_to_string(adapter->Dhcpv4Server.lpSockaddr);
        if (!dhcp_v4.empty()) {
            iface.dhcp_servers.push_back(dhcp_v4);
        }
        for (auto* ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
            std::string addr = sockaddr_to_string(ua->Address.lpSockaddr);
            if (addr.empty()) continue;
            AddressInfo info{addr, std::to_string(ua->OnLinkPrefixLength)};
            if (ua->Address.lpSockaddr->sa_family == AF_INET) iface.ipv4.push_back(info);
            else if (ua->Address.lpSockaddr->sa_family == AF_INET6) iface.ipv6.push_back(info);
        }
        for (auto* dns = adapter->FirstDnsServerAddress; dns; dns = dns->Next) {
            std::string addr = sockaddr_to_string(dns->Address.lpSockaddr);
            if (!addr.empty() && std::find(iface.dns_servers.begin(), iface.dns_servers.end(), addr) == iface.dns_servers.end()) {
                iface.dns_servers.push_back(addr);
            }
        }
        interfaces.push_back(std::move(iface));
    }
    return interfaces;
}

std::vector<std::string> global_ipv6_addresses(const std::vector<InterfaceInfo>& interfaces) {
    std::vector<std::string> values;
    for (const auto& iface : interfaces) {
        if (!iface.up) continue;
        for (const auto& addr : iface.ipv6) {
            if (is_global_v6_text(addr.address)) {
                values.push_back(addr.address);
            }
        }
    }
    return values;
}

std::string primary_ipv4_address(const std::vector<InterfaceInfo>& interfaces, const std::string& preferred_interface) {
    for (const auto& iface : interfaces) {
        if (!preferred_interface.empty() && iface.name != preferred_interface) continue;
        if (!iface.up) continue;
        for (const auto& addr : iface.ipv4) {
            if (addr.address != "127.0.0.1" && !is_link_local_v4(addr.address)) {
                return addr.address;
            }
        }
    }
    return {};
}

void interface_check(Report& report, std::vector<InterfaceInfo>& interfaces) {
    interfaces = collect_interfaces();
    Check check;
    check.name = "Interface inventory";
    size_t active = 0;
    size_t ipv4_count = 0;
    auto global_v6 = global_ipv6_addresses(interfaces);
    std::vector<std::string> apipa;
    std::vector<std::string> low_mtu;
    for (const auto& iface : interfaces) {
        if (iface.up) ++active;
        if (iface.up) ipv4_count += iface.ipv4.size();
        for (const auto& addr : iface.ipv4) {
            if (iface.up && is_link_local_v4(addr.address)) {
                apipa.push_back(iface.name + " " + addr.address);
            }
        }
        if (iface.up && iface.mtu > 0 && iface.mtu < 1280) {
            low_mtu.push_back(iface.name + " mtu=" + std::to_string(iface.mtu));
        }
        std::vector<std::string> v4;
        std::vector<std::string> v6;
        for (const auto& addr : iface.ipv4) v4.push_back(addr.address);
        for (const auto& addr : iface.ipv6) v6.push_back(addr.address);
        check.highlights.push_back(iface.name + " [" + (iface.up ? "up" : "down") + "] IPv4=" +
                                   (v4.empty() ? "-" : join(v4, ",")) + " IPv6=" +
                                   (v6.empty() ? "-" : join(v6, ",")));
    }
    check.status = Status::OK;
    if (interfaces.empty() || active == 0) {
        check.status = Status::FAIL;
        check.recommendations.push_back("No active network interface was found.");
    } else if (ipv4_count == 0 && global_v6.empty()) {
        check.status = Status::FAIL;
        check.recommendations.push_back("No usable IPv4 address and no global IPv6 address were found.");
    } else if (!apipa.empty() || !low_mtu.empty()) {
        check.status = Status::WARN;
        if (!apipa.empty()) check.recommendations.push_back("169.254.x.x address found; DHCP may have failed.");
        if (!low_mtu.empty()) check.recommendations.push_back("MTU below 1280 can break IPv6 and tunnels.");
    }
    check.summary = std::to_string(active) + " active interface(s), IPv4 addresses=" +
                    std::to_string(ipv4_count) + ", global IPv6=" + std::to_string(global_v6.size()) + ".";
    check.details["active_interfaces"] = std::to_string(active);
    check.details["global_ipv6"] = join(global_v6, ",");
    add_check(report, std::move(check));
}

void route_check(Report& report) {
    Check check;
    check.name = "Default route";
    MIB_IPFORWARD_TABLE2* table = nullptr;
    ULONG ret = GetIpForwardTable2(AF_UNSPEC, &table);
    int v4_default = 0;
    int v6_default = 0;
    if (ret == NO_ERROR && table) {
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            const auto& row = table->Table[i];
            if (row.DestinationPrefix.PrefixLength == 0) {
                if (row.DestinationPrefix.Prefix.si_family == AF_INET) ++v4_default;
                if (row.DestinationPrefix.Prefix.si_family == AF_INET6) ++v6_default;
            }
        }
        FreeMibTable(table);
    }
    check.highlights.push_back("IPv4 default routes: " + std::to_string(v4_default));
    check.highlights.push_back("IPv6 default routes: " + std::to_string(v6_default));
    check.summary = "IPv4 default=" + std::to_string(v4_default) + ", IPv6 default=" + std::to_string(v6_default) + ".";
    check.status = Status::OK;
    if (v4_default == 0 && v6_default == 0) {
        check.status = Status::FAIL;
        check.recommendations.push_back("No default route was found. Check gateway, DHCP, VPN, or static routes.");
    } else if (v4_default == 0 || v4_default > 1 || v6_default > 1) {
        check.status = Status::WARN;
        if (v4_default == 0) check.recommendations.push_back("No IPv4 default route was found.");
        if (v4_default > 1) check.recommendations.push_back("Multiple IPv4 default routes exist; verify route metrics.");
        if (v6_default > 1) check.recommendations.push_back("Multiple IPv6 default routes exist; verify RA/VPN metrics.");
    }
    add_check(report, std::move(check));
}

std::vector<std::string> dns_provider_servers(const std::string& provider) {
    const std::string p = to_lower(provider);
    if (p == "cloudflare") return {"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"};
    if (p == "google") return {"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"};
    if (p == "alidns") return {"223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"};
    if (p == "tencent") return {"119.29.29.29", "182.254.116.116"};
    if (p == "quad9") return {"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"};
    return {};
}

void dns_system_check(Report& report, const Options&) {
    auto interfaces = collect_interfaces();
    std::vector<std::string> servers;
    for (const auto& iface : interfaces) {
        for (const auto& server : iface.dns_servers) {
            if (std::find(servers.begin(), servers.end(), server) == servers.end()) {
                servers.push_back(server);
            }
        }
    }
    Check check;
    check.name = "System DNS";
    check.status = servers.empty() ? Status::WARN : Status::OK;
    check.summary = "System DNS servers=" + std::to_string(servers.size()) + ".";
    check.highlights.push_back("System DNS: " + (servers.empty() ? "-" : join(servers, ", ")));
    check.details["servers"] = join(servers, ",");
    if (servers.empty()) check.recommendations.push_back("No system DNS server was detected.");
    add_check(report, std::move(check));
}

void repair_check(Report& report, const Options& options) {
    Check check;
    check.name = "Repair";
    std::vector<std::string> commands;
    if (options.flush_dns) commands.push_back("ipconfig /flushdns");
    if (options.reset_stack) {
        commands.push_back("netsh winsock reset");
        commands.push_back("netsh int ip reset");
        commands.push_back("netsh int ipv6 reset");
        check.highlights.push_back("Note: Windows stack reset usually requires reboot.");
    }
    if (!options.set_dns.empty() || !options.custom_dns.empty()) {
        auto dns_commands = build_dns_commands(options);
        commands.insert(commands.end(), dns_commands.begin(), dns_commands.end());
    }
    if (commands.empty()) {
        check.status = Status::INFO;
        check.summary = "No repair action was requested.";
    } else if (!options.apply) {
        check.status = Status::INFO;
        check.summary = "Prepared repair commands without changing the system.";
        check.recommendations.push_back("Dry run only. Re-run with --apply to execute these commands.");
    } else {
        check.status = Status::OK;
        check.summary = "Executed requested repair commands.";
        for (const auto& cmd : commands) {
            if (starts_with(cmd, "NOTE:")) continue;
            int rc = execute_shell_command(cmd);
            check.highlights.push_back("Ran rc=" + std::to_string(rc) + ": " + cmd);
            if (rc != 0) check.status = Status::WARN;
        }
        if (check.status == Status::WARN) {
            check.recommendations.push_back("At least one repair command failed; inspect command output and privileges.");
        }
    }
    for (const auto& cmd : commands) {
        check.highlights.push_back((starts_with(cmd, "NOTE:") ? "" : "Command: ") + cmd);
    }
    check.details["apply"] = options.apply ? "true" : "false";
    add_check(report, std::move(check));
}

}  // namespace netfix
