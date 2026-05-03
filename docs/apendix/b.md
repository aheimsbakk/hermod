### Appendix B: Cryptographic Vulnerability Mitigations and Refactoring Directives

This appendix supersedes conflicting cryptographic implementations defined in Sections 4, 11, and 26 of the core blueprint. The following directives address identified structural vulnerabilities regarding session authentication and symmetric encryption lifecycles. The refactored design strictly maintains post-quantum (PQ) resistance, zero-knowledge (ZK) signaling, and relies exclusively on established, audited Python libraries to prevent "roll-your-own" cryptography errors.

#### 1. Vulnerability: Unauthenticated Ephemeral Key Exchange (MitM Risk)
**Identified Weakness:** The original blueprint specifies executing Layer 2 (X25519) and Layer 3 (ML-KEM-768) key exchanges over the direct P2P link. Without cryptographically binding these ephemeral public keys and ciphertexts to the Layer 1 shared secret ($K_{classical}$), an active adversary on the P2P network can intercept and replace the Layer 2/3 parameters, executing a Man-in-the-Middle (MitM) attack.

**Required Mitigations:**
*   **Explicit Key Confirmation (MAC Binding):** All cryptographic material exchanged over the P2P connection (X25519 public keys, ML-KEM encapsulation keys, and ML-KEM ciphertexts) must be authenticated using a Message Authentication Code (MAC).
*   **Implementation Directive:** Use HMAC-SHA256 keyed with $K_{classical}$ (derived via SPAKE2). The receiver must verify the HMAC signature of the incoming public keys before executing the encapsulation or deriving the final `Session_Key`.
*   **Standardized Alternative:** Implement the Noise Protocol Framework using the `noiseprotocol` Python library. Utilize the `Noise_NNpsk0` handshake pattern over the P2P link, injecting $K_{classical}$ as the Pre-Shared Key (PSK). The ML-KEM ciphertext must be transmitted as the encrypted payload of the final Noise handshake message to ensure it is covered by the classical authenticated channel.

#### 2. Vulnerability: Deterministic Nonce Reuse in Session Resumption
**Identified Weakness:** Section 26 mandates deriving AEAD nonces based on the `resume_offset`. Relying on file offsets or non-monotonically strictly increasing counters for AES-256-GCM or ChaCha20-Poly1305 nonces introduces a severe risk of nonce collision. A single nonce collision in these algorithms completely compromises the authentication key and allows payload forgery [Source: RFC 5116 - An Interface and Algorithms for Authenticated Encryption, D. McGrew / Cisco Systems, 2008, [https://datatracker.ietf.org/doc/html/rfc5116](https://datatracker.ietf.org/doc/html/rfc5116)].

**Required Mitigations:**
*   **Migrate to Extended Nonce Algorithms:** Deprecate standard AES-GCM and ChaCha20-Poly1305 for the data payload. Standardize on **XChaCha20-Poly1305** using the `cryptography` Python library. XChaCha20 utilizes a 192-bit nonce, safely allowing random nonce generation for every frame without risk of collision, eliminating the need for complex offset-tracking logic.
*   **Sub-Key Derivation for Resumption:** Never reuse the original `Session_Key` for a resumed transfer. Resuming a transfer must trigger a new HKDF-SHA256 execution to derive a unique sub-key specifically for that session segment.

```python
# Directive: Session resumption key derivation using standard library
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"hermod-resume-v1:" + resume_counter.to_bytes(8, 'big')
)
resume_session_key = hkdf.derive(original_session_key)
```

#### 3. Vulnerability: AEAD Lifecycle and Data Streaming Limits
**Identified Weakness:** Encrypting an arbitrarily large file (e.g., 50GB) under a single symmetric key violates cryptographic lifecycle limits for AEAD constructs, increasing susceptibility to cryptanalysis.

**Required Mitigations:**
*   **Implement Symmetric Key Ratcheting:** The symmetric encryption key must be rotated periodically during large transfers.
*   **Standardized Implementation Directive:** Integrate the `pynacl` library (Python bindings for Libsodium) and utilize the `crypto_secretstream` API.
    *   This API is explicitly designed for secure file streaming.
    *   It automatically handles internal key ratcheting and nonce rotation per block.
    *   It enforces cryptographic EOF tags, mathematically preventing truncation attacks where an adversary silently drops the final TCP/UDP packets.

#### Summary of Approved Cryptographic Stack

To satisfy the requirement of using non-proprietary, standard implementations while maintaining the unique ZK and PQ requirements, the dependency matrix is updated as follows:

1.  **Layer 1 (PAKE):** `spake2` (Python library).
2.  **Layer 2 (Classical ECDH):** `cryptography.hazmat.primitives.asymmetric.x25519`.
3.  **Layer 3 (PQ KEM):** `kyber-py` or `liboqs-python` (FIPS 203 ML-KEM-768).
4.  **Key Binding & Derivation:** `cryptography.hazmat.primitives.kdf.hkdf` (HKDF-SHA256) and `cryptography.hazmat.primitives.hmac` (HMAC-SHA256).
5.  **Payload Transport (AEAD):** `pynacl` (`nacl.secret.SecretStream` via XChaCha20-Poly1305).
