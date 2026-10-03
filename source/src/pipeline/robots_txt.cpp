#include "pipeline/robots_txt.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace atomwall {

namespace {

std::string trim(const std::string& s) {
    auto begin = std::find_if_not(s.begin(), s.end(), [](unsigned char c) { return std::isspace(c); });
    auto end = std::find_if_not(s.rbegin(), s.rend(), [](unsigned char c) { return std::isspace(c); }).base();
    return begin < end ? std::string(begin, end) : std::string();
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

// True for a directive line whose field is "user-agent" (case-insensitive,
// arbitrary spacing around the colon) and whose value is exactly "*".
bool is_wildcard_user_agent_line(const std::string& line) {
    const auto trimmed = trim(line);
    const auto colon = trimmed.find(':');
    if (colon == std::string::npos) {
        return false;
    }
    return to_lower(trim(trimmed.substr(0, colon))) == "user-agent" &&
           trim(trimmed.substr(colon + 1)) == "*";
}

std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> lines;
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        lines.push_back(line);
    }
    return lines;
}

} // namespace

std::string build_robots_txt_body(const std::string& base, const std::vector<BlacklistEntry>& fake_routes) {
    if (fake_routes.empty()) {
        return base;
    }

    std::vector<std::string> disallow_lines;
    for (const auto& route : fake_routes) {
        disallow_lines.push_back("Disallow: " + route.value);
    }

    if (base.empty()) {
        std::string out = "User-agent: *\n";
        for (const auto& line : disallow_lines) {
            out += line + "\n";
        }
        return out;
    }

    auto lines = split_lines(base);
    const bool ends_with_newline = base.back() == '\n';
    auto it = std::find_if(lines.begin(), lines.end(), is_wildcard_user_agent_line);
    const bool merged_into_existing = it != lines.end();

    if (merged_into_existing) {
        // Merge into the existing wildcard group so a crawler that only
        // honors the first "User-agent: *" block it sees (the common
        // real-world behavior, even though the spec technically allows
        // multiple) still picks up the honeypot Disallow entries. `it` does
        // not survive this insert (vector reallocation may invalidate it),
        // so nothing below may use it again.
        lines.insert(it + 1, disallow_lines.begin(), disallow_lines.end());
    } else {
        lines.push_back("");
        lines.push_back("User-agent: *");
        for (const auto& line : disallow_lines) {
            lines.push_back(line);
        }
    }

    std::string out;
    for (const auto& line : lines) {
        out += line + "\n";
    }
    if (!ends_with_newline && merged_into_existing) {
        // Only the "merged into existing content" path needs to respect the
        // original file's lack of a trailing newline; the "appended a new
        // group" path always ends with one by construction above.
        out.pop_back();
    }
    return out;
}

} // namespace atomwall
