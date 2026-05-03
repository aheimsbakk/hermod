---
when: 2026-05-03T00:19:28Z
why: enforce mandatory TLS on all connections — no unencrypted transport path can exist
what: mandatory TLS with cert pinning, trust-store cert PEM storage, and backward-compat removal
model: github-copilot/claude-sonnet-4.6
tags: [tls, security, trust-store, config, cleanup]
---

Removed `--no-tls` and `--cert`/`--key` CLI flags; `hermod serve` now always generates a self-signed RSA-4096 cert (paths from config only) and persists `cert_path`/`key_path` to `config.yaml` on first run. `hermod trust` stores the full cert PEM alongside the fingerprint so `tx`/`rx` can build a pinned SSL context via the new `_require_ssl_context()` helper — both commands abort with a clear message if the server is not yet trusted. `TrustStore._load()` drops legacy `{url: str}` format; both ICE single-endpoint fallback branches in `session.py` are removed. Session integration tests upgraded from `ws://` to `wss://` using a session-scoped RSA-2048 fixture. Bumped to v0.3.0.
