#pragma once

#include <map>
#include <string>
#include <vector>

#include "cli.h"

namespace netfix {

enum class Status {
    OK,
    WARN,
    FAIL,
    SKIP,
    INFO,
};

std::string status_to_string(Status status);

struct Check {
    std::string name;
    Status status = Status::INFO;
    std::string summary;
    std::vector<std::string> highlights;
    std::vector<std::string> recommendations;
    std::map<std::string, std::string> details;
};

struct Report {
    std::string tool = "NetFix Inspector";
    std::string version;
    std::string command;
    std::string started_at;
    std::string started_at_utc;
    std::string finished_at;
    std::string finished_at_utc;
    std::string hostname;
    std::string platform;
    bool admin = false;
    std::vector<Check> checks;
};

Report make_report(const std::string& command);
void add_check(Report& report, Check check);
Status overall_status(const Report& report);
std::string report_to_json(const Report& report);
std::string report_to_text(const Report& report);
int emit_report(Report& report, const Options& options);

}  // namespace netfix
