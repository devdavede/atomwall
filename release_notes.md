# Release notes

Changes since the initial public snapshot (`0.1.0`, commit `b6adc551`).
The version number is bumped by `run/release.sh` when a release is cut.

## Highlights

- **Two-factor authentication for the admin UI** — authenticator apps (TOTP),
  one-time backup codes, and passkeys (WebAuthn), with an optional
  "require 2FA for every admin" policy.
- **Emergency Off** — a site-wide kill switch that blanks every public response
  instantly, without touching the admin UI.
- **Whitelist by route** and **robots.txt management** with honeypot ("fake")
  routes that extend your real `robots.txt` instead of replacing it.
- **Hardening pass** across the request pipeline, trackers, TLS handling and
  admin API (see below).
- **Repository prepared for public release**: vcpkg is now a real submodule,
  private deployment tooling and references to internal docs removed.

## New features

### Admin authentication & security
- TOTP enrollment with QR code provisioning, confirmation with a live code
  before activation, and disable/re-enroll.
- TOTP anti-replay: a code's time-step can only be used once per user.
- 10 single-use backup codes (stored hashed, shown once, regenerable).
- Passkeys (WebAuthn): register, list and remove credentials; usable as a
  second factor and for passwordless login (discoverable credentials).
  Registration uses `attestation: "none"` by design.
- New **Security** panel in the admin UI for managing the above.
- New `security.require_2fa` option (off by default). Users without a second
  factor are restricted to the Security panel and logout until they enroll;
  a passkey login satisfies the requirement on its own.
- First-run admin setup is now race-free: two concurrent setup requests can no
  longer both become admins.
- Short-lived pending-MFA / pending-TOTP / WebAuthn challenge state is kept in
  memory only and never written to disk.

### Request pipeline & protection
- **Emergency Off** (`emergency_off.enabled`, toggle in the admin UI, takes
  effect immediately): every request on the public HTTP/HTTPS listeners gets a
  blank page; checked before every other gate; never affects the admin port.
- **Route whitelist** (`whitelist.routes`): path-substring entries that bypass
  every check for every visitor (e.g. a health-check endpoint). Complements
  the existing IP whitelist; supports bulk import and import from URL.
- **robots.txt** (`robots_txt.custom_content`): paste your site's own
  `robots.txt`; atomwall appends a `Disallow` per fake route, merged into your
  existing `User-agent: *` group. Empty = pass-through to the origin.
- **Fake routes** are scored and blocked as robots.txt violators via
  `ban.scores.fake_route`.
- **Request-rate check** now only counts real page navigations
  (`Sec-Fetch-Dest`), so a page's subresources no longer trip the limit.
  Note: the header is client-supplied, so this catches fast browsing, not a
  determined non-browser client.
- `X-Forwarded-Proto` is now sent to the origin with the scheme the visitor
  actually used.

### Admin UI
- New panels: Emergency Off, Whitelisted routes, Robots.txt, Security, and a
  Session stats section.
- Reworked blacklist/whitelist management and login flow (login.js supports
  the 2FA and passkey steps).
- Large extension of the admin API (`/api/auth/2fa/*`, `/api/auth/webauthn/*`,
  `/api/emergency-off`, `/api/robots-txt`, `/api/security-config`,
  `/api/whitelist/routes[/import|/import-url|/clear]`, and more).

## Security & robustness fixes
- IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`, common on dual-stack
  listeners) are normalized to IPv4 when the client address is read, so a
  blocked IPv4 client can no longer slip past blacklists, bans, and whitelists.
- Temporary-ban durations are capped; an absurdly long duration previously
  overflowed the clock and silently became "no ban".
- Memory is now bounded for attacker-controlled keys: the score tracker caps
  tracked IPs (oldest dropped first) and the rate tracker sweeps idle IPs.
- The IP block list uses a hash lookup for exact IPs (the first gate every
  request passes) and drops expired entries on insert, so ban waves can't pile
  up unbounded.
- TLS per-site certificates are cached and only rebuilt when a domain, cert or
  key path, or file modification time changes; reloads are single-flight and
  never block handshakes on disk I/O. Renewed certs dropped in place are
  picked up automatically.
- Config and user files are written atomically; files holding secrets have
  their permissions tightened, while operator-set modes on other files survive
  admin-API rewrites.
- JSON numbers from the admin API are converted with saturation instead of an
  undefined-behavior cast (e.g. `1e300`).
- Transient `accept()` failures (file-descriptor exhaustion, connection resets)
  are retried after a pause instead of crashing the whole process.
- CBOR parsing (passkeys) has hard size and depth limits.

## Build, dependencies & tests
- New dependency: **libcbor** (`>= 0.11.0`), for WebAuthn.
- New CMake/test **`release`** preset.
- About 16 new test files and extended existing tests (TOTP, backup codes,
  CBOR/COSE/WebAuthn, challenge store, user store, session stores, scoring,
  robots.txt, static files, TLS site contexts, upstream, atomic file, and
  more).
- New `run/release.sh` to bump the version, tag and create a GitHub release.
- New public project page in `public_page/` (landing page, privacy and imprint
  pages, vendored fonts and assets).
- New vendored front-end library `qrcode.js` (see `THIRD_PARTY_LICENSES.md`).

## Repository changes
- `source/third_party/vcpkg` is now a proper git submodule pinned to the
  `builtin-baseline` in `source/vcpkg.json`, instead of ~14,000 vendored files.
  Clone with `git clone --recurse-submodules`.
- Removed private deployment tooling (`run/server/`) and the deploy-workflow
  mention in `run/release.sh`.
- Removed all references to an internal design document from docs, the example
  config, the web UI and source comments.
- `.gitignore`: GeoIP databases are now ignored via `*.mmdb`.

## Upgrade notes
- New config sections (`robots_txt`, `whitelist`, `security`, `emergency_off`)
  are all optional and default to off / empty; see
  `source/config/atomwall.example.yaml`.
- Run `git submodule update --init` after pulling, and re-run
  `cmake --preset default` so vcpkg installs libcbor.
- Admin users will not be forced into 2FA unless `security.require_2fa` is set.
