#pragma once

#include <boost/asio/ssl.hpp>
#include <string>

namespace atomwall {

// Shared by the TLS proxy listener (:443) and the optional TLS-enabled
// public globe listener — same conservative TLS server posture for both:
// no SSLv2/v3/TLS1.0/1.1, single_dh_use.
inline boost::asio::ssl::context make_tls_server_context(const std::string& cert_file,
                                                           const std::string& key_file) {
    namespace ssl = boost::asio::ssl;
    ssl::context ctx(ssl::context::tls_server);
    ctx.set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 |
                     ssl::context::no_sslv3 | ssl::context::no_tlsv1 |
                     ssl::context::no_tlsv1_1 | ssl::context::single_dh_use);
    ctx.use_certificate_chain_file(cert_file);
    ctx.use_private_key_file(key_file, ssl::context::pem);
    return ctx;
}

} // namespace atomwall
