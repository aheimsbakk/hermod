---
when: 2026-05-30T13:19:28Z
why: Fix all LOW severity findings from the claude-sonnet-4-6 security audit
what: Resolved L-01 through L-08 — SAS context binding, ECDSA P-256 certs, randScalar rejection sampling, single-receiver enforcement, trust TOFU hardening, WebSocket origin check, session-unique hole punch nonce, and WithContext goroutine leak
model: github-copilot/claude-sonnet-4.6
tags: [security, fix, crypto, server, network, cli]
---

Fixed all 8 LOW findings from `audit-sonet46.md`. Key changes: `ExportKeyingMaterial` now binds the channel ID as context (L-01); both ephemeral and server certs switched from RSA-2048 to ECDSA P-256 (L-02); `randScalar` replaced biased modular reduction with true rejection sampling (L-03); `handleJoin` rejects a second receiver on the same channel (L-04); `hermod trust` gained `--fingerprint` for pre-known fingerprint verification (L-05); WebSocket upgrader now blocks browser cross-origin connections (L-06); `HolePunch` accepts a CPace-derived 4-byte nonce making probe packets session-unique (L-07); `SignalingClient.WithContext` goroutine now exits on `Close()` via a `done` channel (L-08). Bumped to v0.8.1.
