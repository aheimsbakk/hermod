# Increase hole-punch probe packet size with crypto padding

## Problem

The hole-punch probe packet is 3 bytes: `[0x01, nonce[0], nonce[1]]`. The ack is also 3 bytes. This is unusually small on the wire and:

1. **Trivially guessable** — only 16 bits (65536 possibilities) of nonce per packet. A local attacker sending UDP packets can brute-force a valid probe within seconds.
2. **Fingerprintable** — tiny 3-byte UDP packets are unusual and may trigger DPI-based firewall rules.
3. **Minimum packet size filters** — some firewalls drop UDP packets below a certain byte threshold (8, 12, or 16 bytes).

## Solution: Use more bytes from the SHA-256 hash

The nonce is already derived from SHA-256(kClassical + "hermod-holepunch-v1"), producing 32 bytes. Currently only 4 bytes are used (2 for probe, 2 for ack). Expand to use 8 bytes each:

- **Probe**: `[0x01, hash[0:7]]` = 8 bytes
- **Ack**: `[0x01, hash[8:15]]` = 8 bytes

This gives 64 bits of entropy per packet — 2^64 possibilities, practically unguessable.

### What keeps the crypto strong

- The hash is session-specific (derived from the CPace PAKE shared key `kClassical`)
- Both sides derive the same hash and can verify all 8 bytes
- The extra bytes cost nothing computationally (already computed)
- No change to the key derivation — only how many bytes of the output we use

### What to change

1. **`internal/cli/tx.go`** — `holePunchNonce()`: change return type from `[4]byte` to `[32]byte`
2. **`internal/network/network.go`** — `HolePunch()`: accept `[32]byte`, build 8-byte probe and ack payloads. Verify all 8 bytes (use `subtle.ConstantTimeCompare`)
3. **`internal/network/network.go`** — `HolePunchDual()`: forward the larger hash
4. **`internal/network/network_internal_test.go`** — update `testProbeNonce` to `[32]byte`, update all test payloads
5. **`internal/cli/rx.go`** — no change needed (calls `holePunchNonce` which returns the new type)

### What does NOT change

- Probe frequency (200ms ticker)
- `probeMarker` byte (0x01)
- `probeCtx` lifecycle (persistent probing)
- Return condition (first valid probe or ack wins)
- Candidate exchange, endpoint bundles, signaling protocol
- QUIC setup
