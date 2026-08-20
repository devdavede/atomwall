#include "admin/static_files.hpp"

#include <cctype>
#include <sstream>
#include <vector>

namespace atomwall {

namespace fs = std::filesystem;

namespace {

std::string percent_decode(std::string_view input) {
    std::string out;
    out.reserve(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '%' && i + 2 < input.size() &&
            std::isxdigit(static_cast<unsigned char>(input[i + 1])) &&
            std::isxdigit(static_cast<unsigned char>(input[i + 2]))) {
            const std::string hex(input.substr(i + 1, 2));
            out.push_back(static_cast<char>(std::stoi(hex, nullptr, 16)));
            i += 2;
        } else {
            out.push_back(input[i]);
        }
    }
    return out;
}

} // namespace

std::optional<fs::path> resolve_static_path(const fs::path& root, std::string_view request_target) {
    auto path_part = request_target.substr(0, request_target.find('?'));
    const std::string decoded = percent_decode(path_part);

    fs::path relative;
    std::stringstream ss(decoded);
    std::string segment;
    while (std::getline(ss, segment, '/')) {
        if (segment.empty() || segment == ".") {
            continue;
        }
        if (segment == "..") {
            return std::nullopt;
        }
        relative /= segment;
    }
    if (relative.empty()) {
        relative = "index.html";
    }

    std::error_code ec;
    const auto canonical_root = fs::weakly_canonical(root, ec);
    if (ec) {
        return std::nullopt;
    }
    const auto candidate = fs::weakly_canonical(canonical_root / relative, ec);
    if (ec) {
        return std::nullopt;
    }

    const auto candidate_str = candidate.string();
    const auto root_str = canonical_root.string();
    if (candidate_str.compare(0, root_str.size(), root_str) != 0) {
        return std::nullopt;
    }

    if (!fs::is_regular_file(candidate, ec) || ec) {
        return std::nullopt;
    }
    return candidate;
}

std::string_view mime_type_for(const fs::path& path) {
    const auto ext = path.extension().string();
    if (ext == ".html") return "text/html; charset=utf-8";
    if (ext == ".css") return "text/css; charset=utf-8";
    if (ext == ".js") return "application/javascript; charset=utf-8";
    if (ext == ".json") return "application/json; charset=utf-8";
    if (ext == ".svg") return "image/svg+xml";
    if (ext == ".png") return "image/png";
    if (ext == ".webp") return "image/webp";
    if (ext == ".ico") return "image/x-icon";
    return "application/octet-stream";
}

} // namespace atomwall
