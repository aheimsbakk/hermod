# Symmetric UDP Reflection Protocol

Scope: Phase 1 of the CGNAT UDP reflection handshake is 1B-in→9B-out (9× asymmetry).
Keep rate limiter as defense-in-depth but eliminate the theoretical amplification
factor. Protocol change is deferred to v2.x.x (not breaking v1.x.x wire format).

## Alternatives for v2.x.x protocol change

### Alt 1 — Pad phase 1 request to 9 bytes with zeros
Client sends `[0x10][0x00 x8]` (9B). Server distinguishes phase 1 vs phase 2 by
checking if bytes 1-8 are all zero (phase 1) vs a valid HMAC cookie (phase 2).
No new magic byte needed. Clean but relies on cookie never starting with 8 zero
bytes (~1 in 2^64 chance — acceptable).

### Alt 2 — Use distinct magic bytes (jump to v2 magic)
Phase 1 request: `[0x11]` (or any byte ≠ 0x10) → 9B server response.
Phase 2 request: `[0x10][cookie]` → address response.
Or flip it: v1 0x10 is deprecated, 0x11 becomes new phase 1 probe.
Server accepts both v1 and v2 during transition period, then drops v1 in a later
release. Most explicit but uses two magic bytes.

### Alt 3 — Make client send the 9 bytes always, move discriminator to a flag byte
Both phases are 9B. First byte is the discriminator:
- `[0x10][0x00 x8]` = phase 1 (cookie request)
- `[0x10][cookie]`  = phase 2 (cookie echo)
Identical to Alt 1 in practice but framed as a flag-byte design.
Server logic: if bytes 1-8 compute to a valid cookie → phase 2, else → phase 1.

### Alt 4 — Remove phase 1 entirely (cookie-less symmetric protocol)
Client sends `[0x12]` (just a probe, longer or same length). Server responds with
`[0x12][HMAC[:8]]` — same 9B → 9B. But this breaks the anti-spoofing property
of the current two-phase handshake. Not recommended unless combined with per-IP
rate limiting based on a faster token bucket (e.g. 100/s). Included for completeness.
