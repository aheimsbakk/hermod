"""
Key Encapsulation Mechanism (KEM) abstraction.

Primary implementation uses ML-KEM-768 (NIST FIPS 203) via ``liboqs-python``.
When the native liboqs shared library is unavailable, a structural X25519
fallback is used automatically. The fallback is **NOT post-quantum secure**
and logs a clear warning; it exists solely to allow the test suite to run
in environments where the C library cannot be compiled.
"""

from __future__ import annotations

import logging
import os
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Attempt to load liboqs at module import time
# ---------------------------------------------------------------------------
try:
    import oqs as _oqs  # type: ignore[import-untyped]

    # Probe that the shared library loaded and ML-KEM-768 is available.
    _probe = _oqs.KeyEncapsulation("ML-KEM-768")
    _probe.free()
    del _probe
    _HAS_OQS: bool = True
except Exception:  # pragma: no cover – only triggered when liboqs absent
    _HAS_OQS = False
    logger.warning(
        "liboqs shared library not found. Falling back to X25519 KEM "
        "(NOT post-quantum secure). Install liboqs-python with a bundled "
        "liboqs build to enable ML-KEM-768."
    )


# ---------------------------------------------------------------------------
# Protocol (interface)
# ---------------------------------------------------------------------------


@runtime_checkable
class KEMEngine(Protocol):
    """Interface for a Key Encapsulation Mechanism."""

    def generate_keypair(self) -> bytes:
        """Generate a keypair; return the public key."""
        ...

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate; return ``(ciphertext, shared_secret)``."""
        ...

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate *ciphertext*; return ``shared_secret``."""
        ...


# ---------------------------------------------------------------------------
# ML-KEM-768 implementation (liboqs)
# ---------------------------------------------------------------------------


class MLKEM768:
    """ML-KEM-768 KEM backed by liboqs (NIST FIPS 203).

    Raises
    ------
    RuntimeError
        If the liboqs shared library is not available.
    """

    ALG = "ML-KEM-768"

    def __init__(self) -> None:
        if not _HAS_OQS:
            raise RuntimeError(
                "liboqs shared library not available. "
                "Use get_kem() for automatic fallback selection."
            )
        import oqs  # type: ignore[import-untyped]

        self._kem = oqs.KeyEncapsulation(self.ALG)

    def generate_keypair(self) -> bytes:
        """Generate keypair; return public key bytes."""
        return self._kem.generate_keypair()

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return ``(ciphertext, shared_secret)``."""
        import oqs  # type: ignore[import-untyped]

        enc = oqs.KeyEncapsulation(self.ALG)
        ciphertext, shared_secret = enc.encap_secret(public_key)
        enc.free()
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate and return the shared secret."""
        return self._kem.decap_secret(ciphertext)

    def __del__(self) -> None:
        if hasattr(self, "_kem") and self._kem is not None:
            try:
                self._kem.free()
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# X25519 fallback KEM (NOT post-quantum)
# ---------------------------------------------------------------------------


class X25519KEMFallback:
    """Ephemeral X25519 DH used as a structural KEM fallback.

    WARNING: This is **NOT** post-quantum secure. It is used only when the
    liboqs C library cannot be loaded, to allow the application to run in
    development/test environments.
    """

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
        )

        self._private_key = X25519PrivateKey.generate()

    def generate_keypair(self) -> bytes:
        """Return the X25519 public key (raw 32 bytes)."""
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        return self._private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    def encapsulate(self, public_key_bytes: bytes) -> tuple[bytes, bytes]:
        """Return ``(ephemeral_public_key, shared_secret)``."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        ephemeral = X25519PrivateKey.generate()
        peer_pub = X25519PublicKey.from_public_bytes(public_key_bytes)
        shared_secret = ephemeral.exchange(peer_pub)
        ciphertext = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Return the shared secret given the encapsulator's public key."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PublicKey,
        )

        peer_pub = X25519PublicKey.from_public_bytes(ciphertext)
        return self._private_key.exchange(peer_pub)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def get_kem() -> MLKEM768 | X25519KEMFallback:
    """Return the best available KEM implementation.

    Prefers ML-KEM-768; falls back to X25519 with a logged warning.
    """
    if _HAS_OQS:
        return MLKEM768()
    return X25519KEMFallback()


def generate_kem_salt() -> bytes:
    """Return a fresh 32-byte random salt for HKDF."""
    return os.urandom(32)
