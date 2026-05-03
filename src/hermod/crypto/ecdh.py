"""
Ephemeral X25519 Diffie-Hellman key exchange.

Provides a classical elliptic-curve DH layer that sits between the
post-quantum ML-KEM exchange and final key derivation. Its purpose is
defence-in-depth: if ML-KEM-768 is ever broken by a classical computer,
the X25519 shared secret keeps the session key secure.

Usage pattern (one instance per session side):

    # Side A
    dh_a = EphemeralX25519()
    pk_a = dh_a.public_key_bytes()   # send to peer

    # Side B
    dh_b = EphemeralX25519()
    pk_b = dh_b.public_key_bytes()   # send to peer

    # Both compute the same shared secret
    k_ecdh_a = dh_a.exchange(pk_b)
    k_ecdh_b = dh_b.exchange(pk_a)
    assert k_ecdh_a == k_ecdh_b      # 32 bytes
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_PK_SIZE = 32  # X25519 raw public key is always 32 bytes


class EphemeralX25519:
    """One-shot ephemeral X25519 DH key exchange.

    A fresh private key is generated at construction time.  Call
    :meth:`public_key_bytes` to get the bytes to send to the peer, then
    call :meth:`exchange` exactly once with the peer's public key to obtain
    the 32-byte shared secret.

    Raises
    ------
    RuntimeError
        If :meth:`exchange` is called more than once (prevents accidental
        key reuse).
    """

    def __init__(self) -> None:
        self._private_key = X25519PrivateKey.generate()
        self._exchanged = False

    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte X25519 public key."""
        return self._private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    def exchange(self, peer_public_key_bytes: bytes) -> bytes:
        """Compute and return the 32-byte X25519 shared secret.

        Parameters
        ----------
        peer_public_key_bytes:
            Raw 32-byte X25519 public key received from the peer.

        Raises
        ------
        ValueError
            If *peer_public_key_bytes* is not exactly 32 bytes.
        RuntimeError
            If called more than once on this instance.
        """
        if len(peer_public_key_bytes) != _PK_SIZE:
            raise ValueError(
                f"X25519 public key must be {_PK_SIZE} bytes; "
                f"got {len(peer_public_key_bytes)}"
            )
        if self._exchanged:
            raise RuntimeError(
                "exchange() may only be called once per EphemeralX25519 instance"
            )
        self._exchanged = True
        peer_pub = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        return self._private_key.exchange(peer_pub)
