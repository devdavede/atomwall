<p align="center">
  <img src="source/images/hero-header.png" alt="atomwall" width="100%">
</p>

<h1 align="center">atomwall</h1>

<p align="center">
  <b>A self-hosted, C++20 reverse proxy that sits in front of your origin the way Cloudflare does —</b><br>
  terminate TLS, inspect every request, ban the bad ones, and forward the rest. On your own box.
</p>

<p align="center">
  <img alt="language" src="https://img.shields.io/badge/language-C%2B%2B20-00599C?style=for-the-badge&logo=cplusplus&logoColor=white">
  <img alt="async" src="https://img.shields.io/badge/async%20io-Boost.Asio-orange?style=for-the-badge">
  <img alt="tls" src="https://img.shields.io/badge/TLS-OpenSSL-721412?style=for-the-badge&logo=openssl&logoColor=white">
  <img alt="build" src="https://img.shields.io/badge/build-CMake%20%2B%20vcpkg-064F8C?style=for-the-badge&logo=cmake&logoColor=white">
  <img alt="status" src="https://img.shields.io/badge/status-active%20development-yellow?style=for-the-badge">
</p>

---

## What is this?

**atomwall** is a single binary that runs on the edge of your infrastructure, listening on `:80`/`:443`, terminating TLS, and inspecting every inbound request *before* it ever reaches your origin server. Clean traffic gets proxied straight through; bad traffic gets a `403` and never touches your app.

This is heavily vibecoded as it was just a fun project I didn't want to spend too much time on.
Therefore - no warranty or liability!

Think of it as a WAF + reverse proxy + admin console, built from scratch in modern C++, with no external dependencies beyond what `vcpkg` fetches for you.

```
                     ┌──────────────────────────────────────────────┐
  client ── TLS ──►  │  listener (SNI / cert)                       │
                     │        │                                     │
                     │        ▼                                     │
                     │  pipeline (ordered, short-circuiting checks) │
                     │   temp-ban ▸ header ▸ blacklist ▸ body        │
                     │        │                                     │
                     │  ┌─────┴─────┐                                │
                     │  ▼           ▼                                │
                     │ 403        upstream ──► your origin server    │
                     └──────────────────────────────────────────────┘
```

## ✦ Features

|  |  |
|---|---|
| 🛡️ **Threat pipeline** | Ordered, short-circuiting checks — IP blacklist (exact + CIDR), route/path blacklist, honeypot fake-routes, User-Agent & Referrer blacklist, ISP blacklist, method allowlist, request-rate limiting, body-size limits, body-content blacklist. Cheap checks run first so bad traffic never pays for body buffering. |
| 🚫 **Ban & scoring** | Every check can carry a point value. Cross a configurable threshold and the IP is auto-banned for a configurable duration — same mechanism as manual admin bans, unified in one tracker. |
| 🌍 **GeoIP + ASN** | MaxMind/DB-IP `.mmdb` lookups, offline & in-memory — feeds the request log's Country/ISP columns and the live globe. |
| 🌐 **Live Visitor Globe** | A WebGL globe (green = allowed, red = blocked) rendered from an anonymized, IP-free event stream — safe to embed **unauthenticated** on your public site via its own dedicated listener. |
| 🏢 **Multi-site routing** | One binary, many domains — per-site cert/key + upstream target, matched by exact Host/SNI (never substring). |
| 🔐 **Real authentication** | PBKDF2-HMAC-SHA256 (210k iterations), constant-time verification, HttpOnly + SameSite=Strict session cookies, optional TLS-secured non-loopback admin access. |
| 📊 **Live admin dashboard** | SSE-powered request stream, traffic graph, blacklist management, IP block viewer, login history — all served from an in-process API, zero build step. |
| 📝 **Custom response pages** | Admin-editable block/ban pages, plus per-status-code overrides that swap the *origin's* error page body while preserving its real status code. |

## Architecture

```
atomwall/
├── listener/    → TCP accept loops + TLS handshake, SNI-based cert routing
├── pipeline/    → independent, testable request checks (allow / block)
├── upstream/    → forwards clean requests to your origin
├── admin/       → loopback-bound JSON API + static web UI (separate port)
├── globe/       → optional public, unauthenticated, anonymized globe feed
├── geoip/       → MaxMind/DB-IP .mmdb lookups (City + ASN)
├── auth/        → password hashing, sessions, user store
├── history/     → request log, ban tracker, score tracker, login history
└── config/      → single YAML source of truth, hot-reloadable
```

A **single YAML config** drives everything. It's read at startup, reloadable by editing the file on disk (polled every 2s) *or* by mutating it through the admin API — either way, every in-flight worker sees one consistent, atomically-swapped config snapshot, never a half-written one.

## 🚀 Quick start

**Prerequisites** (macOS via Homebrew, or your distro's equivalent): `cmake`, `ninja`, `pkg-config`. Everything else — Boost.Asio, Boost.Beast, Boost.JSON, OpenSSL, yaml-cpp, spdlog, Catch2, libmaxminddb — is fetched and built by the vendored `vcpkg` submodule on first configure.

```sh
# clone with submodules (vcpkg is vendored)
git clone --recurse-submodules <this-repo>
cd atomwall

# configure, build, test, run — all in one
./run/all.sh
```

Or manually, from `source/`:

```sh
cmake --preset default              # first run bootstraps vcpkg deps (~2-3 min)
cmake --build --preset default
./build/default/atomwall            # run
ctest --preset default              # test
```

Generate a self-signed dev certificate for local `:443` testing:

```sh
./run/gen-dev-cert.sh
```

On first launch, open the admin UI at **`http://127.0.0.1:9000`** — the very first account you create becomes the admin.

> **Ports `:80`/`:443` are privileged on Linux.** Either run as root or:
> `sudo setcap 'cap_net_bind_service=+ep' ./atomwall`

## ⚙️ Configuration at a glance

```yaml
http:
  enabled: true
  port: 80
https:
  enabled: true
  port: 443
  cert_file: certs/dev.crt
  key_file: certs/dev.key

upstream:
  host: 127.0.0.1
  port: 8000

admin:
  bind: 127.0.0.1     # loopback by default — widen only with TLS configured
  port: 9000

ban:
  enabled: true
  threshold: 100
  ban_duration_hours: 24

globe:
  public_enabled: false   # opt-in, dedicated unauthenticated listener
  public_port: 9443
```

Every field above (and every blacklist, the ban score table, response pages, GeoIP paths, and more) is also readable/writable live through the admin API and UI — no restart, no redeploy.

## 🔒 Security posture

atomwall *is* the security boundary for whatever sits behind it:

- All inbound bytes — headers, body, TLS fields, SNI — are treated as hostile input.
- A crash in one connection never takes down another (per-connection exception isolation).
- Passwords: PBKDF2-HMAC-SHA256 / 210,000 iterations / random salt / constant-time verify.
- Sessions: `HttpOnly` + `SameSite=Strict`, `Secure` automatically whenever the admin server runs behind TLS.
- The public Live Globe listener is unauthenticated *by design* — its event type structurally cannot carry an IP or any other identifying field, so there's nothing to leak.

## 🧱 Tech stack

- **C++20**, built with **CMake + vcpkg** for fully reproducible builds
- **Boost.Asio** coroutines (`awaitable`/`co_spawn`) for the async request pipeline
- **Boost.Beast** for HTTP parsing, **Boost.JSON** for the admin API
- **OpenSSL** for TLS termination and password hashing primitives
- **yaml-cpp** for config, **spdlog** for logging, **Catch2** for tests
- **libmaxminddb** for GeoIP/ASN lookups

## 🗺️ Status

This is an actively evolving project — the pipeline, admin API, and threat-detection sources are all growing, with several design decisions still up for discussion before this goes into production in front of real traffic.

---

<p align="center"><i>Built for people who want Cloudflare-grade request inspection without handing their traffic to Cloudflare.</i></p>
