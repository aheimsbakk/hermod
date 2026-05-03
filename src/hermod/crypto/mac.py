"""
HMAC-SHA256 message authentication for P2P key binding.

Appendix B §1 requires all cryptographic material exchanged over the P2P
link (X25519 public keys, ML-KEM encapsulation keys, ML-KEM ciphertexts) to
be authenticated with HMAC-SHA256 keyed by ``k_classical``.  This prevents an
active MitM attacker from substituting ephemeral public keys before the peer
processes them.

Usage (sender, PQ_INIT frame)::

    mac = compute_mac(k_classical, pk_kem + pk_ecdh)
    # include mac in the PQ_INIT frame

Usage (receiver, PQ_INIT verification)::

    verify_mac(k_classical, pk_kem + pk_ecdh, received_mac)
    # raises ValueError if tampered
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as _hmac

_MAC_SIZE = 32  # HMAC-SHA256 produces 32 bytes


def compute_mac(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256 over *data* with *key*.

    Parameters
    ----------
    key:
        Secret MAC key (typically ``k_classical`` from SPAKE2).
    data:
        Byte string to authenticate.

    Returns
    -------
    bytes
        32-byte HMAC-SHA256 tag.
    """
    if not key:
        raise ValueError("MAC key must be non-empty")
    h = _hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def verify_mac(key: bytes, data: bytes, tag: bytes) -> None:
    """Verify HMAC-SHA256 of *data* against *tag*.

    Uses a constant-time comparison to prevent timing side-channel attacks.

    Parameters
    ----------
    key:
        Secret MAC key (same key used in :func:`compute_mac`).
    data:
        Byte string that was authenticated.
    tag:
        Expected 32-byte HMAC-SHA256 tag.

    Raises
    ------
    ValueError
        If the tag length is wrong or verification fails.
    """
    if not key:
        raise ValueError("MAC key must be non-empty")
    if len(tag) != _MAC_SIZE:
        raise ValueError(f"MAC tag must be {_MAC_SIZE} bytes; got {len(tag)}")
    h = _hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(tag)
    except Exception as exc:
        raise ValueError(
            "MAC verification failed: cryptographic material has been tampered with"
        ) from exc
