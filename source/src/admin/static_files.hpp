#pragma once

#include <filesystem>
#include <optional>
#include <string_view>

namespace atomwall {

// Resolves an HTTP request target to a file under `root`, decoding
// percent-encoding and rejecting any path that would escape `root`
// (dot-segments, absolute overrides, etc). Returns nullopt if the target
// doesn't map to an existing regular file. "/" maps to "index.html".
std::optional<std::filesystem::path> resolve_static_path(const std::filesystem::path& root,
                                                           std::string_view request_target);

std::string_view mime_type_for(const std::filesystem::path& path);

} // namespace atomwall
