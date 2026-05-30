---
when: 2026-05-30T11:22:21Z
why: Fix H-02 timing side channel — try-and-increment hash-to-curve leaks loop count via timing
what: Replace try-and-increment with RFC 9380 P256_XMD:SHA-256_SSWU_RO_ constant-branch hash-to-curve
model: github-copilot/claude-sonnet-4.6
tags: [security, crypto, cpace, rfc9380, sswu, timing-side-channel]
---

Replaced the `cpaceGenerator` try-and-increment loop (which leaked iteration count through timing) with a full RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` implementation in `internal/crypto/hash_to_curve.go`, covering `expand_message_xmd`, `hash_to_field`, simplified SWU map, and `sqrt_ratio` for p≡3 mod 4. The new code has no data-dependent loop iterations. Added `filippo.io/nistec v0.0.4` as a dependency. All five RFC 9380 Appendix J.1.1 test vectors pass (plus K.1 `expand_message_xmd` vector and `sqrt_ratio` contract test). Updated `docs/protocol.md`, `docs/api.md`, and the package-level comment to reference RFC 9380. Bumped to v0.7.5.
