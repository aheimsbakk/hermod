# Cryptographic Design

Hermod uses three independent key-agreement layers so an attacker must break all three simultaneously to read a transfer. This document explains each layer, how the keys are combined, and how the payload is encrypted.

---

## Threat model

Hermod assumes:

- The **signaling server is untrusted**. An attacker may operate the relay, read all messages it carries, and inject or replace messages.
- An **active attacker on the P2P network** may intercept, replace, or replay frames after NAT punch-through.
- Future **quantum computers** will eventually break classical Diffie-Hellman and RSA. A "Store Now, Decrypt Later" adversary may record ciphertexts today and decrypt them later.

Hermod does not protect against:

- An attacker who compromises the sender's or receiver's machine.
- Denial-of-service against the signaling server itself.

---

## Transfer code

When the sender runs `hermod tx`, the application:

1. Asks the signaling server to allocate a numeric channel ID (e.g. `47392`).
2. Generates three random words from an embedded 256-word list (e.g. `rapid-blue-fox`).
3. Combines them into the transfer code: `47392-rapid-blue-fox`.

The **numeric prefix** is the channel address on the server.  
The **word suffix** is the shared PAKE passphrase — it never leaves the clients.

---

## Layer 1 — SPAKE2 password-authenticated key exchange

**Goal:** Prove both peers know the transfer code without sending it in the clear. Produce a shared classical secret `K_classical`.

**Algorithm:** SPAKE2 over Elliptic Curves (RFC 9382), implemented by the `spake2` Python package.

**How it works:**

1. Sender and receiver each compute a SPAKE2 message from the word portion of the transfer code.
2. They exchange these messages through the signaling relay.
3. Each side derives `K_classical` locally. An eavesdropper who intercepts the SPAKE2 messages cannot compute `K_classical` without knowing the passphrase.
4. A wrong passphrase produces a wrong `K_classical`, causing the MAC check in step 6 below to fail — the session aborts cleanly.

**Property:** SPAKE2 is a zero-knowledge proof. The server relays the messages but learns nothing about the passphrase or `K_classical`.

---

## Layer 2 — Ephemeral X25519 Diffie-Hellman

**Goal:** Add a classical DH layer over the direct P2P link. If the post-quantum KEM is ever broken by a *classical* algorithm, `K_ecdh` alone keeps the session secure.

**Algorithm:** X25519, implemented by the `cryptography` package (`cryptography.hazmat.primitives.asymmetric.x25519`).

**How it works:**

1. Each peer generates a fresh X25519 key pair for this session only.
2. The sender includes its public key in the `PQ_INIT` frame. The receiver includes its public key in `PQ_RESPONSE`.
3. Both sides compute the 32-byte shared secret `K_ecdh = X25519(own_private, peer_public)`.

The X25519 keys are piggybacked on the same two frames used by Layer 3, so no extra round-trip is needed.

---

## Layer 3 — ML-KEM-768 post-quantum KEM

**Goal:** Produce a shared secret `K_pq` that resists quantum computers.

**Algorithm:** ML-KEM-768, NIST FIPS 203. This is the standardised variant of Kyber.

Key and ciphertext sizes:

| Item | Size |
|---|---|
| Encapsulation key (public key) | 1184 bytes |
| Ciphertext | 1088 bytes |
| Shared secret | 32 bytes |

**How it works:**

1. The sender generates an ML-KEM key pair and sends the encapsulation key in `PQ_INIT`.
2. The receiver uses it to encapsulate a random secret, producing a ciphertext and `K_pq`. It sends the ciphertext in `PQ_RESPONSE`.
3. The sender decapsulates the ciphertext to recover the same `K_pq`.

**Backend selection** (automatic, in priority order):

| Priority | Backend | Notes |
|---|---|---|
| 1 | `liboqs` (native C) | Fastest; requires compiled shared library. Install with `uv add "hermod-p2p[pq]"` |
| 2 | `kyber-py` (pure Python) | Default; always installable, no C build required |
| 3 | X25519 fallback | **Not post-quantum.** Used only when neither PQ library is available. A warning is logged. |

---

## MitM protection — MAC binding on PQ frames

**Problem:** After NAT punch-through, an active attacker on the P2P network could intercept the `PQ_INIT` and `PQ_RESPONSE` frames and substitute their own public keys — executing a man-in-the-middle attack against layers 2 and 3.

**Solution:** Every key material field in both frames is authenticated with HMAC-SHA256 keyed by `K_classical`:

| Frame | MAC covers |
|---|---|
| `PQ_INIT` (sender → receiver) | `pk_kem ‖ pk_ecdh` |
| `PQ_RESPONSE` (receiver → sender) | `ct ‖ pk_ecdh` |

The receiver must verify the MAC in `PQ_INIT` before it runs encapsulation.  
The sender must verify the MAC in `PQ_RESPONSE` before it runs decapsulation.

A MAC mismatch raises `ValueError("MAC verification failed")` and aborts the session immediately.

**Implementation:** `crypto/mac.py` — `compute_mac(key, data)` and `verify_mac(key, data, tag)` use `cryptography.hazmat.primitives.hmac` with constant-time comparison (`hmac.compare_digest`).

---

## Key derivation — combining all three secrets

Once both peers have `K_classical`, `K_ecdh`, and `K_pq`, they derive a single 32-byte session key using HKDF-SHA256:

```
Session_Key = HKDF-SHA256(
    ikm  = K_classical ‖ K_ecdh ‖ K_pq,
    salt = random 32 bytes (carried in PQ_INIT),
    info = b"hermod-session-v2",
    len  = 32
)
```

**Security property:** `Session_Key` is secure as long as *any one* of the three input secrets is secure. An attacker must independently break SPAKE2, X25519, and ML-KEM-768 to recover it.

**Implementation:** `crypto/kdf.py` — `derive_session_key(k_classical, k_ecdh, k_pq, salt)`.

---

## Payload encryption — SecretStream (XChaCha20-Poly1305)

**Goal:** Encrypt arbitrarily large payloads in chunks, with automatic key ratcheting and truncation protection.

**Algorithm:** libsodium `crypto_secretstream_xchacha20poly1305`, accessed through `pynacl` bindings.

This API was chosen specifically because:

- It **ratchets the key** after every chunk, so encrypting a 50 GB file under one key never violates AEAD lifecycle limits.
- It uses a **192-bit nonce** (XChaCha20), making random nonce generation safe for every frame.
- It enforces **`TAG_FINAL`** on the last chunk, giving mathematical proof against truncation attacks where an attacker silently drops trailing data.

**Transfer flow:**

1. The sender initialises a `SecretStreamPush` from `Session_Key`. This produces a 24-byte stream header.
2. The stream header is carried in the `stream_header` field of the `META` wire frame.
3. The receiver passes the header to `SecretStreamPull` before processing any `CHUNK` frames.
4. Each 1 MB file chunk is encrypted with `push(plaintext, last=False)`.
5. The final chunk uses `push(plaintext, last=True)`, which sets `TAG_FINAL`.
6. The receiver calls `pull(ciphertext)`. If the EOF frame arrives before a `TAG_FINAL` chunk, it raises `ValueError("Stream truncated")`.

**Implementation:** `crypto/stream.py` — `SecretStreamPush` and `SecretStreamPull`.

---

## Ad-hoc AEAD — ICE candidate encryption

ICE candidates (the IP/port pairs used for NAT punch-through) are small messages exchanged over the signaling channel. They use a simpler scheme:

**Algorithm:** XChaCha20-Poly1305 IETF variant via `pynacl` bindings (`nacl.bindings.crypto_aead_xchacha20poly1305_ietf_*`).

**Wire format:** `nonce (24 bytes) ‖ ciphertext+tag`

A fresh 192-bit random nonce is generated for every encrypt call, so nonce reuse is not possible.

**Key:** The first 32 bytes of `K_classical` (the SPAKE2 output). The signaling server relays the encrypted blob but cannot decrypt it.

**Implementation:** `crypto/aead.py` — `AEADCipher`.

---

## Resume sub-key derivation

Transferring a large file may be interrupted. When a transfer resumes, the session cannot reuse `Session_Key` with a `SecretStream` that starts at a non-zero offset — that would reuse internal nonce state and break the security guarantee.

Instead, each resumed segment gets a fresh sub-key:

```python
resume_key = HKDF-SHA256(
    ikm  = session_key,
    salt = b"",
    info = b"hermod-resume-v1:" + resume_counter.to_bytes(8, "big"),
    len  = 32
)
```

`resume_counter` is a non-negative integer that increments for every resume attempt. The original `Session_Key` is never passed to a `SecretStream` for a resumed segment.

**Implementation:** `crypto/kdf.py` — `derive_resume_key(session_key, resume_counter)`.

---

## TLS and certificate pinning

The signaling channel between clients and the server uses TLS.

**Server-side:** `hermod serve` auto-generates a self-signed X.509 certificate on first run. The certificate and private key are stored as PEM strings inside `~/.config/hermod/config.yaml` (file mode `0600`). No separate certificate files are written to disk.

**Client-side:** Hermod does not use the operating system's CA bundle. Instead it pins the SHA-256 fingerprint of each server's certificate in the `trusted_servers` section of `config.yaml`.

```yaml
trusted_servers:
  wss://my-relay.example.com:8443:
    fingerprint: "ab:cd:ef:12:34:..."
    cert: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
```

`hermod trust <host:port>` fetches the server certificate, computes its fingerprint, stores both, and saves the server URL as the default. All subsequent connections to that server verify the fingerprint against the pinned value.

A fingerprint mismatch terminates the TLS handshake immediately — the server cannot impersonate itself with a new certificate without the user re-running `hermod trust`.

---

## Cryptographic library matrix

| Purpose | Library | Algorithm |
|---|---|---|
| PAKE (Layer 1) | `spake2` | SPAKE2 over Elliptic Curves (RFC 9382) |
| ECDH (Layer 2) | `cryptography` | X25519 |
| Post-quantum KEM (Layer 3) | `kyber-py` or `liboqs-python` | ML-KEM-768 (NIST FIPS 203) |
| MAC binding | `cryptography` | HMAC-SHA256 |
| Key derivation | `cryptography` | HKDF-SHA256 |
| Payload streaming | `pynacl` (libsodium) | XChaCha20-Poly1305 SecretStream |
| Ad-hoc AEAD | `pynacl` (libsodium) | XChaCha20-Poly1305 IETF |
| TLS | `cryptography` | X.509, self-signed |

---

## References

- SPAKE2: [RFC 9382](https://www.rfc-editor.org/rfc/rfc9382.txt)
- ML-KEM: [NIST FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- HKDF: [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)
- AEAD nonce safety: [RFC 5116](https://datatracker.ietf.org/doc/html/rfc5116)
- libsodium SecretStream: [libsodium docs](https://doc.libsodium.org/secret-key_cryptography/secretstream)
