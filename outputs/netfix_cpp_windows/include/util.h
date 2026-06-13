#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <windows.h>

namespace netfix {

inline std::wstring utf8_to_wide(const std::string& input) {
    if (input.empty()) {
        return {};
    }
    int length = MultiByteToWideChar(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0);
    std::wstring output(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), output.data(), length);
    return output;
}

inline std::string wide_to_utf8(const std::wstring& input) {
    if (input.empty()) {
        return {};
    }
    int length = WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    std::string output(static_cast<size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), output.data(), length, nullptr, nullptr);
    return output;
}

inline std::string json_escape(const std::string& input) {
    std::ostringstream out;
    for (unsigned char ch : input) {
        switch (ch) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (ch < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(ch);
                } else {
                    out << ch;
                }
        }
    }
    return out.str();
}

inline std::string quote_json(const std::string& input) {
    return "\"" + json_escape(input) + "\"";
}

inline std::string join(const std::vector<std::string>& values, const std::string& sep) {
    std::ostringstream out;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i) {
            out << sep;
        }
        out << values[i];
    }
    return out.str();
}

inline std::string now_iso_local() {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &tt);
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    return out.str();
}

inline std::string now_iso_utc() {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_s(&tm, &tt);
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

inline uint64_t elapsed_ms(std::chrono::steady_clock::time_point start) {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count());
}

inline bool starts_with(const std::string& value, const std::string& prefix) {
    return value.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), value.begin());
}

inline std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

}  // namespace netfix
