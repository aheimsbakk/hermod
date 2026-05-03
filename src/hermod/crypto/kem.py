"""
Key Encapsulation Mechanism (KEM) abstraction.

Primary implementation uses ML-KEM-768 (NIST FIPS 203).  Two backends are
tried in order:

1. **liboqs-python** (``oqs`` package) — preferred when the native liboqs
   shared library is present.
2. **kyber-py** (``kyber_py`` package) — pure-Python FIPS 203 ML-KEM-768;
   no C compilation required; slower but always installable via uv/pip.
3. **X25519 fallback** — used only when neither PQ library is available;
   **NOT post-quantum secure**; logs a clear warning.
"""

from __future__ import annotations

import logging
import os
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Backend detection (module import time)
# ---------------------------------------------------------------------------

# Tier 1 — liboqs (native C library)
try:
    import oqs as _oqs  # type: ignore[import-untyped]

    _probe = _oqs.KeyEncapsulation("ML-KEM-768")
    _probe.free()
    del _probe
    _HAS_OQS: bool = True
except Exception:  # pragma: no cover – only triggered when liboqs absent
    _HAS_OQS = False

# Tier 2 — kyber-py (pure Python, always installable)
try:
    from kyber_py.ml_kem import ML_KEM_768 as _ML_KEM_768  # type: ignore[import-untyped]

    _HAS_KYBER_PY: bool = True
except Exception:  # pragma: no cover
    _HAS_KYBER_PY = False

if not _HAS_OQS and not _HAS_KYBER_PY:  # pragma: no cover
    logger.warning(
        "No post-quantum KEM library found (liboqs-python or kyber-py). "
        "Falling back to X25519 (NOT post-quantum secure). "
        "Run: uv add kyber-py"
    )
elif not _HAS_OQS and _HAS_KYBER_PY:
    logger.debug("liboqs unavailable; using kyber-py for ML-KEM-768.")


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
# ML-KEM-768 — Tier 1: liboqs
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
# ML-KEM-768 — Tier 2: kyber-py (pure Python)
# ---------------------------------------------------------------------------


class MLKEM768KyberPy:
    """ML-KEM-768 KEM backed by the pure-Python ``kyber-py`` package.

    Implements the same NIST FIPS 203 spec as liboqs without requiring a
    native C library.  Key/ciphertext sizes are identical to liboqs:

    * Encapsulation key (public key): 1184 bytes
    * Ciphertext: 1088 bytes
    * Shared secret: 32 bytes

    Raises
    ------
    RuntimeError
        If ``kyber-py`` is not installed.
    """

    def __init__(self) -> None:
        if not _HAS_KYBER_PY:
            raise RuntimeError("kyber-py is not installed. Run: uv add kyber-py")

    def generate_keypair(self) -> bytes:
        """Generate keypair; return encapsulation key (public key) bytes."""
        from kyber_py.ml_kem import ML_KEM_768  # type: ignore[import-untyped]

        ek, self._dk = ML_KEM_768.keygen()
        self._ek = ek
        return ek

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return ``(ciphertext, shared_secret)`` for *public_key*.

        ``kyber-py`` returns ``(shared_secret, ciphertext)`` from
        ``encaps()``; this method reorders to match the ``KEMEngine``
        protocol ``(ciphertext, shared_secret)``.
        """
        from kyber_py.ml_kem import ML_KEM_768  # type: ignore[import-untyped]

        shared_secret, ciphertext = ML_KEM_768.encaps(public_key)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate and return the shared secret."""
        from kyber_py.ml_kem import ML_KEM_768  # type: ignore[import-untyped]

        return ML_KEM_768.decaps(self._dk, ciphertext)


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


def get_kem() -> MLKEM768 | MLKEM768KyberPy | X25519KEMFallback:
    """Return the best available KEM implementation.

    Priority: liboqs → kyber-py → X25519 (non-PQ fallback).
    """
    if _HAS_OQS:
        return MLKEM768()
    if _HAS_KYBER_PY:
        return MLKEM768KyberPy()
    return X25519KEMFallback()  # pragma: no cover


def generate_kem_salt() -> bytes:
    """Return a fresh 32-byte random salt for HKDF."""
    return os.urandom(32)
