"""
AEAD symmetric encryption — XChaCha20-Poly1305.

Appendix B §2 deprecates AES-256-GCM for payload encryption and mandates
migration to XChaCha20-Poly1305.  The 192-bit (24-byte) nonce allows safe
random nonce generation for every frame without collision risk, eliminating
the fragile offset-tracking logic required by the old 96-bit GCM nonces.

Implementation uses ``pynacl`` (libsodium bindings) via the IETF variant of
XChaCha20-Poly1305 (``crypto_aead_xchacha20poly1305_ietf_*``), since the
``cryptography`` package does not yet expose XChaCha20-Poly1305 in its public
API.  Both libraries are audited implementations backed by the same libsodium
primitive.

This module provides ``AEADCipher`` for small, ad-hoc encrypt/decrypt
operations (e.g. ICE candidate lists exchanged over the signaling channel).
For large streaming payloads use :mod:`hermod.crypto.stream` instead.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)
from nacl.exceptions import CryptoError

_NONCE_SIZE: int = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  # 24 bytes (192-bit)
_KEY_SIZE: int = crypto_aead_xchacha20poly1305_ietf_KEYBYTES  # 32 bytes
_TAG_SIZE = 16  # Poly1305 authentication tag


class AEADCipher:
    """XChaCha20-Poly1305 authenticated encryption wrapper.

    Drop-in replacement for the previous AES-256-GCM implementation.
    The nonce grows from 96 to 192 bits, making random nonce generation
    collision-safe over the full AEAD lifecycle.

    Parameters
    ----------
    key:
        32-byte (256-bit) symmetric key.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != _KEY_SIZE:
            raise ValueError(f"Key must be {_KEY_SIZE} bytes; got {len(key)}")
        self._key = key

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Encrypt *plaintext* and return ``nonce || ciphertext+tag``.

        A fresh 192-bit random nonce is generated for every call.

        Parameters
        ----------
        plaintext:
            Raw bytes to encrypt.
        aad:
            Additional authenticated data (authenticated but not encrypted).
        """
        nonce = os.urandom(_NONCE_SIZE)
        ct = crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, aad or b"", nonce, self._key
        )
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
            return crypto_aead_xchacha20poly1305_ietf_decrypt(
                ct, aad or b"", nonce, self._key
            )
        except CryptoError as exc:
            raise InvalidTag("Decryption failed: authentication tag mismatch") from exc
