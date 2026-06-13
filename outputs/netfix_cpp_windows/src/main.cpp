#include <iostream>
#include <set>
#include <windows.h>

#include "cli.h"
#include "net_win.h"
#include "pcap_checks.h"
#include "probe.h"
#include "report.h"

namespace netfix {
namespace {

void lan_health_summary(Report& report) {
    Check check;
    check.name = "LAN health summary";
    check.status = Status::OK;
    check.summary = "No obvious LAN-side issue was detected.";
    for (const auto& existing : report.checks) {
        if ((existing.name == "DHCP" || existing.name == "LAN loop and broadcast storm" ||
             existing.name == "Default route" || existing.name == "Interface inventory") &&
            (existing.status == Status::WARN || existing.status == Status::FAIL)) {
            check.status = Status::WARN;
            check.highlights.push_back(existing.name + ": " + existing.summary);
        }
    }
    if (check.status == Status::WARN) {
        check.summary = std::to_string(check.highlights.size()) + " LAN-side issue hint(s) detected.";
        check.recommendations.push_back("Review detailed checks above; focus first on DHCP, routes, DNS, and broadcast sources.");
    }
    add_check(report, std::move(check));
}

int run_scan(const Options& options) {
    Report report = make_report("scan");
    std::vector<InterfaceInfo> interfaces;
    interface_check(report, interfaces);
    route_check(report);
    connectivity_check(report, options);
    dns_system_check(report, options);
    dns_direct_check(report, options);
    nat_check(report, options);
    ipv6_check(report, options, interfaces);
    if (options.skip_packet) {
        Check check;
        check.name = "Packet-level LAN checks";
        check.status = Status::SKIP;
        check.summary = "DHCP and LAN loop packet checks were skipped by --skip-packet.";
        add_check(report, std::move(check));
    } else {
        dhcp_check(report, options);
        loop_check(report, options, interfaces);
    }
    lan_health_summary(report);
    return emit_report(report, options);
}

int run_command(const Options& options) {
    std::vector<InterfaceInfo> interfaces;
    Report report = make_report(options.command);
    if (options.command == "scan") {
        return run_scan(options);
    }
    if (options.command == "connectivity") {
        connectivity_check(report, options);
    } else if (options.command == "dns") {
        dns_system_check(report, options);
        dns_direct_check(report, options);
    } else if (options.command == "nat") {
        nat_check(report, options);
    } else if (options.command == "ipv6") {
        interface_check(report, interfaces);
        ipv6_check(report, options, interfaces);
    } else if (options.command == "dhcp") {
        dhcp_check(report, options);
    } else if (options.command == "loop") {
        interface_check(report, interfaces);
        loop_check(report, options, interfaces);
    } else if (options.command == "repair") {
        repair_check(report, options);
    } else if (options.command == "npcap") {
        pcap_status_check(report, options);
    } else if (options.command == "port") {
        port_ping_check(report, options);
    } else {
        std::cerr << "Unknown command: " << options.command << "\n";
        return 2;
    }
    return emit_report(report, options);
}

void print_interactive_menu() {
    std::cout << "\n";
    std::cout << "================ NetFixInspector ================\n";
    std::cout << "Choose an action and press Enter.\n\n";
    std::cout << "  1. Quick scan (recommended, no packet capture)\n";
    std::cout << "  2. Full scan (uses Npcap packet capture when installed)\n";
    std::cout << "  3. DNS check\n";
    std::cout << "  4. IPv4 NAT check\n";
    std::cout << "  5. IPv6 check\n";
    std::cout << "  6. DHCP check (system state + Npcap capture when installed)\n";
    std::cout << "  7. DHCP active probe (run as Administrator for best results)\n";
    std::cout << "  8. LAN loop/broadcast detection (requires Npcap + Administrator)\n";
    std::cout << "  9. Npcap status\n";
    std::cout << "  P. TCP port ping (IPv4/IPv6)\n";
    std::cout << "  H. Help\n";
    std::cout << "  0. Exit\n\n";
    std::cout << "Choice: ";
}

Options interactive_options_for_choice(const std::string& choice) {
    Options options;
    options.timeout_seconds = 2.0;
    options.no_external_inbound = true;
    options.skip_packet = true;

    if (choice == "1") {
        options.command = "scan";
        options.output_path = "NetFixInspector-quick-report.json";
    } else if (choice == "2") {
        options.command = "scan";
        options.timeout_seconds = 3.0;
        options.skip_packet = false;
        options.output_path = "NetFixInspector-full-report.json";
    } else if (choice == "3") {
        options.command = "dns";
        options.output_path = "NetFixInspector-dns-report.json";
    } else if (choice == "4") {
        options.command = "nat";
        options.timeout_seconds = 3.0;
        options.output_path = "NetFixInspector-nat-report.json";
    } else if (choice == "5") {
        options.command = "ipv6";
        options.output_path = "NetFixInspector-ipv6-report.json";
    } else if (choice == "6") {
        options.command = "dhcp";
        options.output_path = "NetFixInspector-dhcp-report.json";
    } else if (choice == "7") {
        options.command = "dhcp";
        options.dhcp_active = true;
        options.timeout_seconds = 5.0;
        options.output_path = "NetFixInspector-dhcp-active-report.json";
    } else if (choice == "8") {
        options.command = "loop";
        options.skip_packet = false;
        options.loop_seconds = 15.0;
        options.loop_probes = 5;
        options.output_path = "NetFixInspector-loop-report.json";
    } else if (choice == "9") {
        options.command = "npcap";
        options.output_path = "NetFixInspector-npcap-report.json";
    } else if (choice == "p" || choice == "P") {
        options.command = "port";
        options.port_host = "example.com";
        options.port_number = 443;
        options.port_family = "both";
        options.port_count = 3;
        options.output_path = "NetFixInspector-port-report.json";
    }
    return options;
}

int run_interactive_menu() {
    while (true) {
        print_interactive_menu();
        std::string choice;
        std::getline(std::cin, choice);
        if (choice == "0" || choice == "q" || choice == "Q") {
            std::cout << "Exited.\n";
            return 0;
        }
        if (choice == "h" || choice == "H" || choice == "help" || choice == "HELP") {
            std::cout << "\n";
            print_help();
            std::cout << "\nPress Enter to return to the menu...";
            std::string ignored;
            std::getline(std::cin, ignored);
            continue;
        }
        static const std::set<std::string> valid_choices = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "p", "P"};
        if (valid_choices.count(choice) == 0) {
            std::cout << "Invalid choice. Try again.\n";
            continue;
        }
        Options options = interactive_options_for_choice(choice);
        std::cout << "\nRunning, please wait...\n\n";
        winsock_startup();
        int rc = run_command(options);
        winsock_cleanup();
        std::cout << "\nDone. Report file: " << options.output_path << "\n";
        std::cout << "Return code: " << rc << "\n";
        std::cout << "\nPress Enter to return to the menu, or type 0 then Enter to exit: ";
        std::string next;
        std::getline(std::cin, next);
        if (next == "0" || next == "q" || next == "Q") {
            return rc;
        }
    }
}

}  // namespace
}  // namespace netfix

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    const bool double_click_mode = argc <= 1;
    if (double_click_mode) {
        return netfix::run_interactive_menu();
    }
    netfix::ParseResult parsed = netfix::parse_args(argc, argv);
    if (parsed.show_help) {
        netfix::print_help();
        return 0;
    }
    if (parsed.error) {
        std::cerr << parsed.message << "\n\n";
        netfix::print_help();
        return 2;
    }
    netfix::winsock_startup();
    int rc = netfix::run_command(parsed.options);
    netfix::winsock_cleanup();
    return rc;
}
