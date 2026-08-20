#include "admin/http_util.hpp"

#include <charconv>

namespace atomwall {

namespace http = boost::beast::http;
namespace json = boost::json;

std::size_t query_param_size_t(std::string_view target, std::string_view key, std::size_t fallback) {
    const auto qpos = target.find('?');
    if (qpos == std::string_view::npos) {
        return fallback;
    }
    auto query = target.substr(qpos + 1);
    while (!query.empty()) {
        const auto amp = query.find('&');
        const auto pair = query.substr(0, amp);
        const auto eq = pair.find('=');
        if (eq != std::string_view::npos && pair.substr(0, eq) == key) {
            std::size_t value = fallback;
            const auto value_str = pair.substr(eq + 1);
            auto result = std::from_chars(value_str.data(), value_str.data() + value_str.size(), value);
            return result.ec == std::errc{} ? value : fallback;
        }
        if (amp == std::string_view::npos) {
            break;
        }
        query.remove_prefix(amp + 1);
    }
    return fallback;
}

http::response<http::string_body> json_response(http::status status, const json::value& body,
                                                  unsigned version) {
    http::response<http::string_body> res{status, version};
    res.set(http::field::server, "atomwall-admin");
    res.set(http::field::content_type, "application/json");
    res.body() = json::serialize(body);
    res.prepare_payload();
    return res;
}

http::response<http::string_body> error_response(http::status status, std::string_view message,
                                                   unsigned version) {
    json::object obj;
    obj["error"] = std::string(message);
    return json_response(status, obj, version);
}

} // namespace atomwall
