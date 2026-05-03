---
when: 2026-05-03T10:32:11Z
why: Three cryptographic vulnerabilities identified in docs/apendix/b.md required remediation before production use
what: Appendix B security hardening — MAC binding, XChaCha20-Poly1305 AEAD, SecretStream payload encryption, resume sub-key derivation
model: github-copilot/claude-sonnet-4.6
tags: [security, crypto, pynacl, xchacha20, secretstream, hmac, kdf]
---

Implemented all three Appendix B fixes and bumped version to 0.5.0. Added `crypto/mac.py` (HMAC-SHA256 compute/verify) and `crypto/stream.py` (SecretStreamPush/Pull wrapping libsodium `crypto_secretstream`); migrated `crypto/aead.py` from AES-256-GCM to XChaCha20-Poly1305 (192-bit nonce) via `pynacl` bindings; extended `crypto/kdf.py` with `derive_resume_key`; rewrote `core/session.py` to attach MAC tags to PQ_INIT/PQ_RESPONSE frames and use SecretStream for all payload chunks with TAG_FINAL truncation detection; the `META` wire frame now carries a `stream_header` field (24 bytes). All 179 tests pass at 71% coverage.
