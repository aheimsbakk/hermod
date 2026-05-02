"""
AEAD symmetric encryption.

Provides AES-256-GCM authenticated encryption with associated data.
Each call to ``encrypt`` generates a fresh random 96-bit nonce which is
prepended to the ciphertext so the pair travels together.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_SIZE = 12  # 96-bit nonce required by GCM
_TAG_SIZE = 16  # GCM authentication tag


class AEADCipher:
    """AES-256-GCM authenticated encryption wrapper.

    Parameters
    ----------
    key:
        32-byte (256-bit) symmetric key.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes; got {len(key)}")
        self._cipher = AESGCM(key)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Encrypt *plaintext* and return ``nonce || ciphertext+tag``.

        Parameters
        ----------
        plaintext:
            Raw bytes to encrypt.
        aad:
            Additional authenticated data (not encrypted, but authenticated).
        """
        nonce = os.urandom(_NONCE_SIZE)
        ct = self._cipher.encrypt(nonce, plaintext, aad or None)
        return nonce + ct

    def decrypt(self, data: bytes, aad: bytes = b"") -> bytes:
        """Decrypt ``nonce || ciphertext+tag`` produced by :meth:`encrypt`.

        Raises
        ------
        ValueError
            If *data* is too short to be valid ciphertext.
        cryptography.exceptions.InvalidTag
            If authentication fails (data tampered or wrong key).
        """
        min_len = _NONCE_SIZE + _TAG_SIZE
        if len(data) < min_len:
            raise ValueError(
                f"Ciphertext too short: expected at least {min_len} bytes, "
                f"got {len(data)}"
            )
        nonce, ct = data[:_NONCE_SIZE], data[_NONCE_SIZE:]
        try:
            return self._cipher.decrypt(nonce, ct, aad or None)
        except InvalidTag as exc:
            raise InvalidTag("Decryption failed: authentication tag mismatch") from exc
