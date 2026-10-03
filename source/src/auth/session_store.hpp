#pragma once

#include <chrono>
#include <cstddef>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace atomwall {

struct SessionInfo {
    std::string username;
    // True when security.require_2fa is on and this user had no second
    // factor enrolled at login time — the admin_server connection loop
    // restricts such a session to auth/enrollment endpoints only, so the
    // user can reach the Security panel without being fully locked out by a
    // requirement nobody told them to meet yet. Cleared by re-issuing the
    // session once enrollment completes (see handle_auth_2fa_totp_confirm /
    // handle_auth_2fa_webauthn_register_verify in admin_server.cpp).
    bool needs_mfa_setup = false;
};

// In-memory session tokens (lost on restart — matches RequestLog/trackers).
// Session cookies are HttpOnly + SameSite=Strict; plain HTTP is acceptable here because the admin
// listener is loopback-only by default (TLS is required to bind elsewhere).
class SessionStore {
public:
    std::string create(const std::string& username, bool needs_mfa_setup = false,
                        std::chrono::hours ttl = std::chrono::hours(12));

    std::optional<SessionInfo> validate(const std::string& token) const;

    void invalidate(const std::string& token);

    // Flips needs_mfa_setup to false in place once enrollment completes, so
    // an already-issued session cookie doesn't need to be replaced — see
    // handle_auth_2fa_totp_confirm in admin_server.cpp. No-op if the token
    // doesn't exist (e.g. already expired).
    void mark_mfa_satisfied(const std::string& token);

    std::size_t size() const;

private:
    struct Session {
        std::string username;
        bool needs_mfa_setup = false;
        std::chrono::system_clock::time_point expires_at;
    };

    mutable std::mutex mutex_;
    std::unordered_map<std::string, Session> sessions_;
};

} // namespace atomwall
