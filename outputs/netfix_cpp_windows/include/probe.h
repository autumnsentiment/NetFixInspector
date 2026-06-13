#pragma once

#include <string>
#include <vector>

#include "cli.h"
#include "net_win.h"
#include "report.h"

namespace netfix {

void winsock_startup();
void winsock_cleanup();

void connectivity_check(Report& report, const Options& options);
void port_ping_check(Report& report, const Options& options);
void dns_direct_check(Report& report, const Options& options);
void nat_check(Report& report, const Options& options);
void ipv6_check(Report& report, const Options& options, const std::vector<InterfaceInfo>& interfaces);

}  // namespace netfix
