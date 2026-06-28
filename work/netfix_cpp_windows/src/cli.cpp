#include "cli.h"

#include <iostream>
#include <set>
#include <stdexcept>

#include "util.h"

namespace netfix {
namespace {

bool is_command(const std::string& value) {
    static const std::set<std::string> commands = {
        "scan", "connectivity", "dns", "nat", "ipv6", "dhcp", "loop", "repair", "npcap", "port", "portping",
    };
    return commands.count(value) > 0;
}

bool needs_value(const std::string& arg) {
    static const std::set<std::string> value_args = {
        "--output", "--timeout", "--interface", "--target-v4", "--target-v6",
        "--provider", "--dns-server", "--dns-name", "--stun-server",
        "--inbound-address", "--inbound-port", "--inbound-seconds",
        "--check-host-nodes", "--dhcp-seconds", "--seconds", "--discover-count",
        "--loop-seconds", "--loop-probes", "--probes", "--broadcast-threshold",
        "--family", "--count", "--protocol",
        "--set-dns", "--custom-dns", "--host", "--port", "--target",
    };
    return value_args.count(arg) > 0;
}

double parse_double(const std::string& value, const std::string& name) {
    try {
        return std::stod(value);
    } catch (const std::exception&) {
        throw std::runtime_error("Invalid numeric value for " + name + ": " + value);
    }
}

int parse_int(const std::string& value, const std::string& name) {
    try {
        return std::stoi(value);
    } catch (const std::exception&) {
        throw std::runtime_error("Invalid integer value for " + name + ": " + value);
    }
}

}  // namespace

ParseResult parse_args(int argc, wchar_t** argv) {
    ParseResult result;
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        args.push_back(wide_to_utf8(argv[i]));
    }

    if (!args.empty() && is_command(args.front())) {
        result.options.command = args.front();
        args.erase(args.begin());
    }

    try {
        for (size_t i = 0; i < args.size(); ++i) {
            const std::string& arg = args[i];
            if (arg == "-h" || arg == "--help") {
                result.show_help = true;
                continue;
            }
            std::string value;
            if (needs_value(arg)) {
                if (i + 1 >= args.size()) {
                    throw std::runtime_error("Missing value for " + arg);
                }
                value = args[++i];
            }

            if (arg == "--json") result.options.json = true;
            else if (arg == "--strict-exit") result.options.strict_exit = true;
            else if (arg == "--apply") result.options.apply = true;
            else if (arg == "--skip-packet") result.options.skip_packet = true;
            else if (arg == "--no-external-inbound") result.options.no_external_inbound = true;
            else if (arg == "--dhcp-active" || arg == "--active") result.options.dhcp_active = true;
            else if (arg == "--flush-dns") result.options.flush_dns = true;
            else if (arg == "--reset-stack") result.options.reset_stack = true;
            else if (arg == "--output") result.options.output_path = value;
            else if (arg == "--timeout") result.options.timeout_seconds = parse_double(value, arg);
            else if (arg == "--interface") result.options.interface_name = value;
            else if (arg == "--target-v4") result.options.target_v4.push_back(value);
            else if (arg == "--target-v6") result.options.target_v6.push_back(value);
            else if (arg == "--provider") result.options.provider = to_lower(value);
            else if (arg == "--dns-server") result.options.dns_servers.push_back(value);
            else if (arg == "--dns-name") result.options.dns_names.push_back(value);
            else if (arg == "--stun-server") result.options.stun_servers.push_back(value);
            else if (arg == "--inbound-address") result.options.inbound_address = value;
            else if (arg == "--inbound-port") result.options.inbound_port = parse_int(value, arg);
            else if (arg == "--inbound-seconds") result.options.inbound_seconds = parse_double(value, arg);
            else if (arg == "--check-host-nodes") result.options.check_host_nodes = parse_int(value, arg);
            else if (arg == "--dhcp-seconds") result.options.dhcp_seconds = parse_double(value, arg);
            else if (arg == "--seconds") {
                result.options.dhcp_seconds = parse_double(value, arg);
                result.options.loop_seconds = result.options.dhcp_seconds;
            }
            else if (arg == "--discover-count") result.options.discover_count = parse_int(value, arg);
            else if (arg == "--loop-seconds") result.options.loop_seconds = parse_double(value, arg);
            else if (arg == "--loop-probes" || arg == "--probes") result.options.loop_probes = parse_int(value, arg);
            else if (arg == "--broadcast-threshold") result.options.broadcast_threshold = parse_double(value, arg);
            else if (arg == "--set-dns") result.options.set_dns = to_lower(value);
            else if (arg == "--custom-dns") result.options.custom_dns.push_back(value);
            else if (arg == "--host") result.options.port_host = value;
            else if (arg == "--port") result.options.port_number = parse_int(value, arg);
            else if (arg == "--target") result.options.port_targets.push_back(value);
            else if (arg == "--family") result.options.port_family = to_lower(value);
            else if (arg == "--count") result.options.port_count = parse_int(value, arg);
            else if (arg == "--protocol") result.options.port_protocol = to_lower(value);
            else {
                throw std::runtime_error("Unknown argument: " + arg);
            }
        }
        if (result.options.command == "portping") {
            result.options.command = "port";
        }
        if (result.options.port_number < 1 || result.options.port_number > 65535) {
            throw std::runtime_error("Invalid port: " + std::to_string(result.options.port_number));
        }
        if (result.options.port_count < 1 || result.options.port_count > 20) {
            throw std::runtime_error("Invalid count: " + std::to_string(result.options.port_count) + " (expected 1..20)");
        }
        if (result.options.port_family != "both" && result.options.port_family != "ipv4" &&
            result.options.port_family != "ipv6" && result.options.port_family != "4" &&
            result.options.port_family != "6") {
            throw std::runtime_error("Invalid family: " + result.options.port_family + " (expected both, ipv4, or ipv6)");
        }
        if (result.options.port_protocol != "tcp" && result.options.port_protocol != "udp") {
            throw std::runtime_error("Invalid protocol: " + result.options.port_protocol + " (expected tcp or udp)");
        }
    } catch (const std::exception& ex) {
        result.error = true;
        result.message = ex.what();
    }

    return result;
}

void print_help() {
    std::cout
        << "usage: NetFixInspector [scan|connectivity|dns|nat|ipv6|dhcp|loop|repair|npcap|port] [options]\n\n"
        << "Cross-platform-compatible Windows native network detection and conservative repair helper.\n\n"
        << "Commands:\n"
        << "  scan            Run the full diagnostic suite.\n"
        << "  connectivity    Check IPv4/IPv6 TCP reachability and system DNS resolution.\n"
        << "  dns             Check system DNS and direct resolver behavior.\n"
        << "  nat             Detect IPv4 NAT mapping behavior using STUN.\n"
        << "  ipv6            Check IPv6 outbound and optional inbound reachability.\n"
        << "  dhcp            Capture DHCP broadcasts and identify DHCP sources.\n"
        << "  loop            Probe and capture LAN loop or broadcast-storm hints.\n"
        << "  repair          Prepare or apply conservative repair commands.\n\n"
        << "  npcap           Check whether the Npcap runtime can be loaded.\n\n"
        << "  port            TCP/UDP port ping over IPv4 and/or IPv6.\n\n"
        << "Common options:\n"
        << "  --json                  Print JSON instead of text summary.\n"
        << "  --output PATH           Write full JSON report to PATH.\n"
        << "  --timeout SEC           Network timeout in seconds.\n"
        << "  --interface NAME        Adapter alias for packet checks and DNS repair.\n"
        << "  --strict-exit           Return non-zero when WARN or FAIL is present.\n\n"
        << "Scan options:\n"
        << "  --skip-packet           Skip DHCP and LAN loop packet checks.\n"
        << "  --no-external-inbound   Skip online IPv6 inbound checker.\n"
        << "  --dhcp-active           Send DHCP Discover probes during DHCP capture.\n\n"
        << "Packet options:\n"
        << "  --seconds SEC           Capture duration for dhcp/loop.\n"
        << "  --probes N              Active L2 probe count for loop detection.\n"
        << "  --broadcast-threshold N Warn when broadcast/multicast rate exceeds N/s.\n\n"
        << "Port ping options:\n"
        << "  --protocol tcp|udp      Transport protocol, default tcp.\\n"
        << "  --host HOST             Hostname or IP to test, default example.com.\\n"
        << "  --port N                Port to test, default 443.\\n"
        << "  --family both|ipv4|ipv6 Address family to test, default both.\n"
        << "  --count N               Probe attempts per family/target, default 3.\n\n"
        << "Repair options:\n"
        << "  --set-dns PROVIDER      cloudflare, google, alidns, tencent, quad9.\n"
        << "  --custom-dns SERVER     Add custom DNS server for replacement.\n"
        << "  --flush-dns             Flush DNS cache.\n"
        << "  --reset-stack           Prepare Windows network stack reset commands.\n"
        << "  --apply                 Actually execute repair commands.\n";
}

}  // namespace netfix
