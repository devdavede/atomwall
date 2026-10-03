#pragma once

#include <string>

#include "config/runtime_config.hpp"

namespace atomwall {

RuntimeConfig parse_yaml_config(const std::string& yaml_text);
std::string to_yaml_config(const RuntimeConfig& config);

} // namespace atomwall
