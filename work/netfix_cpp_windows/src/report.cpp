#include "report.h"

#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <windows.h>

#include "util.h"

namespace netfix {
namespace {

bool is_admin() {
    BOOL is_member = FALSE;
    PSID admin_group = nullptr;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(
            &nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &admin_group)) {
        CheckTokenMembership(nullptr, admin_group, &is_member);
        FreeSid(admin_group);
    }
    return is_member == TRUE;
}

std::string windows_version_text() {
    OSVERSIONINFOEXW os{};
    os.dwOSVersionInfoSize = sizeof(os);
#pragma warning(push)
#pragma warning(disable : 4996)
    GetVersionExW(reinterpret_cast<OSVERSIONINFOW*>(&os));
#pragma warning(pop)
    std::ostringstream out;
    out << "Windows " << os.dwMajorVersion << "." << os.dwMinorVersion << "." << os.dwBuildNumber;
    return out.str();
}

int status_weight(Status status) {
    switch (status) {
        case Status::FAIL: return 4;
        case Status::WARN: return 3;
        case Status::SKIP: return 2;
        case Status::INFO: return 1;
        case Status::OK: return 0;
    }
    return 0;
}

std::string json_array(const std::vector<std::string>& values) {
    std::ostringstream out;
    out << "[";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i) out << ",";
        out << quote_json(values[i]);
    }
    out << "]";
    return out.str();
}

}  // namespace

std::string status_to_string(Status status) {
    switch (status) {
        case Status::OK: return "OK";
        case Status::WARN: return "WARN";
        case Status::FAIL: return "FAIL";
        case Status::SKIP: return "SKIP";
        case Status::INFO: return "INFO";
    }
    return "INFO";
}

Report make_report(const std::string& command) {
    Report report;
#ifdef NETFIX_VERSION_TEXT
    report.version = NETFIX_VERSION_TEXT;
#else
    report.version = "1.0.0";
#endif
    report.command = command;
    report.started_at = now_iso_local();
    report.started_at_utc = now_iso_utc();
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(buffer, &size)) {
        report.hostname = wide_to_utf8(buffer);
    } else {
        report.hostname = "unknown";
    }
    report.platform = windows_version_text();
    report.admin = is_admin();
    return report;
}

void add_check(Report& report, Check check) {
    report.checks.push_back(std::move(check));
}

Status overall_status(const Report& report) {
    Status worst = Status::OK;
    for (const auto& check : report.checks) {
        if (status_weight(check.status) > status_weight(worst)) {
            worst = check.status;
        }
    }
    return report.checks.empty() ? Status::INFO : worst;
}

std::string report_to_json(const Report& report) {
    std::map<std::string, int> counts;
    for (const auto& check : report.checks) {
        counts[status_to_string(check.status)]++;
    }

    std::ostringstream out;
    out << "{\n";
    out << "  \"tool\": " << quote_json(report.tool) << ",\n";
    out << "  \"version\": " << quote_json(report.version) << ",\n";
    out << "  \"command\": " << quote_json(report.command) << ",\n";
    out << "  \"started_at\": " << quote_json(report.started_at) << ",\n";
    out << "  \"started_at_utc\": " << quote_json(report.started_at_utc) << ",\n";
    out << "  \"host\": {\n";
    out << "    \"hostname\": " << quote_json(report.hostname) << ",\n";
    out << "    \"platform\": " << quote_json(report.platform) << ",\n";
    out << "    \"system\": \"Windows\",\n";
    out << "    \"admin\": " << (report.admin ? "true" : "false") << "\n";
    out << "  },\n";
    out << "  \"checks\": [\n";
    for (size_t i = 0; i < report.checks.size(); ++i) {
        const auto& check = report.checks[i];
        out << "    {\n";
        out << "      \"name\": " << quote_json(check.name) << ",\n";
        out << "      \"status\": " << quote_json(status_to_string(check.status)) << ",\n";
        out << "      \"summary\": " << quote_json(check.summary) << ",\n";
        out << "      \"details\": {\n";
        size_t j = 0;
        for (const auto& pair : check.details) {
            out << "        " << quote_json(pair.first) << ": " << quote_json(pair.second);
            out << (++j < check.details.size() ? ",\n" : "\n");
        }
        out << "      },\n";
        out << "      \"highlights\": " << json_array(check.highlights) << ",\n";
        out << "      \"recommendations\": " << json_array(check.recommendations) << "\n";
        out << "    }" << (i + 1 < report.checks.size() ? "," : "") << "\n";
    }
    out << "  ],\n";
    out << "  \"finished_at\": " << quote_json(report.finished_at) << ",\n";
    out << "  \"finished_at_utc\": " << quote_json(report.finished_at_utc) << ",\n";
    out << "  \"summary\": {\n";
    out << "    \"status\": " << quote_json(status_to_string(overall_status(report))) << ",\n";
    out << "    \"counts\": {";
    size_t k = 0;
    for (const auto& pair : counts) {
        if (k++) out << ",";
        out << "\n      " << quote_json(pair.first) << ": " << pair.second;
    }
    if (!counts.empty()) out << "\n    ";
    out << "}\n";
    out << "  }\n";
    out << "}\n";
    return out.str();
}

std::string report_to_text(const Report& report) {
    std::map<std::string, int> counts;
    for (const auto& check : report.checks) {
        counts[status_to_string(check.status)]++;
    }

    std::ostringstream out;
    out << report.tool << " " << report.version << "\n";
    out << "Host: " << report.hostname << "  System: " << report.platform << "\n";
    out << "Started: " << report.started_at << "  Admin/root: " << (report.admin ? "true" : "false") << "\n\n";
    for (const auto& check : report.checks) {
        out << "[" << status_to_string(check.status) << "] " << check.name << ": " << check.summary << "\n";
        for (size_t i = 0; i < check.highlights.size() && i < 8; ++i) {
            out << "  - " << check.highlights[i] << "\n";
        }
        for (size_t i = 0; i < check.recommendations.size() && i < 6; ++i) {
            out << "  * Recommendation: " << check.recommendations[i] << "\n";
        }
        if (!check.highlights.empty() || !check.recommendations.empty()) {
            out << "\n";
        }
    }
    out << "Overall: " << status_to_string(overall_status(report)) << " (";
    size_t i = 0;
    for (const auto& pair : counts) {
        if (i++) out << ", ";
        out << pair.first << "=" << pair.second;
    }
    out << ")\n";
    return out.str();
}

int emit_report(Report& report, const Options& options) {
    report.finished_at = now_iso_local();
    report.finished_at_utc = now_iso_utc();
    const std::string json = report_to_json(report);
    if (!options.output_path.empty()) {
        std::ofstream file(options.output_path, std::ios::binary);
        file << json;
    }
    if (options.json) {
        std::cout << json;
    } else {
        std::cout << report_to_text(report);
        if (!options.output_path.empty()) {
            std::cout << "\nJSON report saved: " << options.output_path << "\n";
        }
    }
    if (options.strict_exit) {
        Status status = overall_status(report);
        return (status == Status::WARN || status == Status::FAIL) ? 1 : 0;
    }
    return 0;
}

}  // namespace netfix
