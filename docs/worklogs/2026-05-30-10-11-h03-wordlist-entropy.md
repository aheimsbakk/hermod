---
when: 2026-05-30T10:11:14Z
why: Fix H-03 — transfer code wordlist had insufficient entropy and two selection defects
what: Replace 255-entry custom wordlist with full 1296-entry EFF Short Wordlist 1 and use rejection sampling
model: github-copilot/claude-sonnet-4.6
tags: [security, crypto, entropy, wordlist]
---

Replaced `effShortWordlist` in `internal/crypto/crypto.go` with the complete EFF Short Wordlist 1 (1,296 unique entries), eliminating the duplicate `"emit"` entry and the truncated 255-word list that gave only ≈24 bits of passphrase entropy. Replaced the biased `int(b) % len(list)` byte-modulo selection with `randomWordIndex()`, which uses `crypto/rand` and rejection sampling on `uint16` values (accepting only `v < 64800`) to produce uniform indices with no modulo bias — giving ≈31.9 bits for 3-word codes. Added `TestWordlistIntegrity` to `crypto_test.go` to guard against future regressions (length == 1296, zero duplicates). Updated `docs/protocol.md` to document the EFF wordlist, entry count, and entropy figures. Bumped to v0.7.3.
