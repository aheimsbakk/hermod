---
when: 2026-05-29T19:07:48Z
why: GAP.md medium item — client IPs stored in plaintext in rate limiter, docs out of sync with resolved gaps
what: Implement daily-rotating HMAC-SHA256 IP hashing in RateLimiter; sync BLUEPRINT, CONTEXT, docs with all resolved GAP items
model: github-copilot/claude-sonnet-4.6
tags: [security, privacy, ratelimit, docs]
---

Added daily-rotating salt to `internal/server/ratelimit.go`: bucket keys are now `hex(HMAC-SHA256(salt, ipPrefix))` — raw IPs are never stored. Salt is 32 bytes from `crypto/rand`, replaced every UTC calendar day with buckets cleared on rotation. Three internal tests cover key hashing, rotation clearing, and day-boundary reset (`ratelimit_internal_test.go`). Synced `BLUEPRINT.md`, `CONTEXT.md`, `docs/api.md`, and `docs/protocol.md` to reflect the IP-hashing design, corrected `NewServer` signature (added `maxBlobsPerChannel`/`maxCPaceFailures` params), documented `DefaultMaxBlobsPerChannel`/`DefaultMaxCPaceFailures` constants, added `Cleanup` to the rate-limiter API, and added server enforcement limits to the protocol security considerations section. Bumped to v0.6.0.
