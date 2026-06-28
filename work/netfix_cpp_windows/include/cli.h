#pragma once

#include <string>
#include <vector>

namespace netfix {

struct Options {
    std::string command = "scan";
    bool json = false;
    bool strict_exit = false;
    bool apply = false;
    bool skip_packet = false;
    bool no_external_inbound = false;
    bool dhcp_active = false;
    bool flush_dns = false;
    bool reset_stack = false;
    double timeout_seconds = 3.0;
    double dhcp_seconds = 12.0;
    double loop_seconds = 8.0;
    double inbound_seconds = 22.0;
    int discover_count = 2;
    int loop_probes = 3;
    int check_host_nodes = 3;
    int inbound_port = 0;
    int port_number = 443;
    int port_count = 3;
    std::string port_protocol = "tcp";
    double broadcast_threshold = 60.0;
    std::string output_path;
    std::string interface_name;
    std::string provider = "cloudflare";
    std::string set_dns;
    std::string inbound_address;
    std::string port_host = "example.com";
    std::string port_family = "both";
    std::vector<std::string> target_v4;
    std::vector<std::string> target_v6;
    std::vector<std::string> port_targets;
    std::vector<std::string> dns_servers;
    std::vector<std::string> dns_names;
    std::vector<std::string> stun_servers;
    std::vector<std::string> custom_dns;
};

struct ParseResult {
    Options options;
    bool show_help = false;
    bool error = false;
    std::string message;
};

ParseResult parse_args(int argc, wchar_t** argv);
void print_help();

}  // namespace netfix
