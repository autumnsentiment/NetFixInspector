#pragma once

#include <string>
#include <vector>

#include "cli.h"
#include "report.h"

namespace netfix {

struct AddressInfo {
    std::string address;
    std::string prefix;
};

struct InterfaceInfo {
    std::string name;
    std::string description;
    bool up = false;
    uint64_t speed_mbps = 0;
    uint32_t mtu = 0;
    std::vector<AddressInfo> ipv4;
    std::vector<AddressInfo> ipv6;
    std::vector<std::string> dns_servers;
    std::vector<std::string> dhcp_servers;
    bool dhcp_enabled = false;
    std::string mac;
};

std::vector<InterfaceInfo> collect_interfaces();
std::vector<std::string> global_ipv6_addresses(const std::vector<InterfaceInfo>& interfaces);
void interface_check(Report& report, std::vector<InterfaceInfo>& interfaces);
void route_check(Report& report);
void dns_system_check(Report& report, const Options& options);
void repair_check(Report& report, const Options& options);

std::vector<std::string> dns_provider_servers(const std::string& provider);
std::string primary_ipv4_address(const std::vector<InterfaceInfo>& interfaces, const std::string& preferred_interface);

}  // namespace netfix
