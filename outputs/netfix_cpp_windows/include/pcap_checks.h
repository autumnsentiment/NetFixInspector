#pragma once

#include <vector>

#include "cli.h"
#include "net_win.h"
#include "report.h"

namespace netfix {

void pcap_status_check(Report& report, const Options& options);
void dhcp_check(Report& report, const Options& options);
void loop_check(Report& report, const Options& options, const std::vector<InterfaceInfo>& interfaces);

}  // namespace netfix
