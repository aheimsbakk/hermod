---
when: 2026-05-30T12:52:03Z
why: Resolve all medium-severity findings from the audit-sonet46.md security audit
what: Fix M-01 through M-07 (excluding M-04): cert hardening, AES-GCM AAD, rate-limiter cleanup, channel validation, /cert endpoint, and streaming hash
model: github-copilot/claude-sonnet-4.6
tags: [security, crypto, transfer, server, config]
---

Fixed all six actionable medium findings from the security audit: server certificate is now non-CA with a 1-year validity and startup expiry warnings (M-01); endpoint bundles bind the channel ID as AES-GCM AAD (M-02); the rate-limiter bucket map is now pruned every 10 minutes via a background ticker (M-03); `handleJoin` rejects receivers for non-existent channels (M-05); the `/cert` endpoint now correctly serves the DER-encoded server certificate (M-06); and all transfer kinds now compute SHA-256 in parallel during streaming, sending the hash as a trailing metadata stream after the payload so large stdin inputs are never buffered (M-07). Bumped to v0.8.0.
