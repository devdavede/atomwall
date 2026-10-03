#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace atomwall {

// RFC 4648 §5 (base64url), unpadded — the wire format the WebAuthn spec uses
// for every binary field (challenges, credential IDs, clientDataJSON,
// attestationObject, ...) when carried inside JSON between browser and server.
std::string base64url_encode(const std::vector<std::uint8_t>& data);

// Throws std::invalid_argument on malformed input (wrong alphabet, or a
// length that can't form whole bytes) — this decodes attacker-controlled
// strings from the client, so a malformed value must be rejected outright,
// never truncated or silently reinterpreted.
std::vector<std::uint8_t> base64url_decode(const std::string& text);

} // namespace atomwall
