"""
SecretStream — streaming AEAD with automatic key ratcheting.

Appendix B §3 mandates use of ``pynacl``'s ``crypto_secretstream``
(XChaCha20-Poly1305) for all data payload encryption.  This API provides:

- Automatic internal key ratcheting per block (safe for large files).
- Per-block nonce rotation with no user bookkeeping.
- Cryptographic EOF tags (``TAG_FINAL``) that mathematically prevent
  truncation attacks where an adversary silently drops trailing frames.

Usage (sender)::

    push = SecretStreamPush(session_key)
    stream_header = push.header   # 24 bytes; must be sent to receiver

    for chunk in data_chunks:
        ct = push.push(chunk)
    ct_final = push.push(last_chunk, is_final=True)

Usage (receiver — *header* comes from META frame)::

    pull = SecretStreamPull(session_key, stream_header)
    plaintext, is_final = pull.pull(ct)
"""

from __future__ import annotations

from nacl.bindings import (
    crypto_secretstream_xchacha20poly1305_HEADERBYTES,
    crypto_secretstream_xchacha20poly1305_KEYBYTES,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_init_push,
    crypto_secretstream_xchacha20poly1305_pull,
    crypto_secretstream_xchacha20poly1305_push,
    crypto_secretstream_xchacha20poly1305_state,
)

#: Size of the stream header produced by :class:`SecretStreamPush`.
STREAM_HEADER_SIZE: int = crypto_secretstream_xchacha20poly1305_HEADERBYTES  # 24
#: Required key size (bytes).
STREAM_KEY_SIZE: int = crypto_secretstream_xchacha20poly1305_KEYBYTES  # 32


class SecretStreamPush:
    """Encrypt a sequence of frames with automatic key ratcheting.

    Parameters
    ----------
    key:
        32-byte session key.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != STREAM_KEY_SIZE:
            raise ValueError(
                f"SecretStreamPush key must be {STREAM_KEY_SIZE} bytes; got {len(key)}"
            )
        self._state = crypto_secretstream_xchacha20poly1305_state()
        self._header: bytes = crypto_secretstream_xchacha20poly1305_init_push(
            self._state, key
        )

    @property
    def header(self) -> bytes:
        """24-byte stream header that the receiver needs to initialise pull."""
        return self._header

    def push(self, plaintext: bytes, *, is_final: bool = False) -> bytes:
        """Encrypt one frame.

        Parameters
        ----------
        plaintext:
            Raw data for this frame.
        is_final:
            Set ``True`` for the last frame in the stream.  The receiver can
            detect truncation if this tag is absent when the transfer ends.

        Returns
        -------
        bytes
            Authenticated ciphertext (``len(plaintext) + 17`` bytes).
        """
        tag = (
            crypto_secretstream_xchacha20poly1305_TAG_FINAL
            if is_final
            else crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
        )
        return crypto_secretstream_xchacha20poly1305_push(
            self._state, plaintext, None, tag
        )


class SecretStreamPull:
    """Decrypt a sequence of frames produced by :class:`SecretStreamPush`.

    Parameters
    ----------
    key:
        32-byte session key.
    header:
        24-byte stream header received from the sender (META frame field
        ``stream_header``).
    """

    def __init__(self, key: bytes, header: bytes) -> None:
        if len(key) != STREAM_KEY_SIZE:
            raise ValueError(
                f"SecretStreamPull key must be {STREAM_KEY_SIZE} bytes; got {len(key)}"
            )
        if len(header) != STREAM_HEADER_SIZE:
            raise ValueError(
                f"Stream header must be {STREAM_HEADER_SIZE} bytes; got {len(header)}"
            )
        self._state = crypto_secretstream_xchacha20poly1305_state()
        crypto_secretstream_xchacha20poly1305_init_pull(self._state, header, key)

    def pull(self, ciphertext: bytes) -> tuple[bytes, bool]:
        """Decrypt one frame.

        Parameters
        ----------
        ciphertext:
            Authenticated ciphertext produced by :meth:`SecretStreamPush.push`.

        Returns
        -------
        tuple[bytes, bool]
            ``(plaintext, is_final)`` — ``is_final`` is ``True`` when the
            sender marked this as the last frame (``TAG_FINAL``).

        Raises
        ------
        nacl.exceptions.CryptoError
            If authentication fails (data tampered or wrong key/header).
        """
        plaintext, tag = crypto_secretstream_xchacha20poly1305_pull(
            self._state, ciphertext, None
        )
        return plaintext, tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL
