"""
P2P wire protocol: frame encoding and decoding.

Frame layout (15-byte fixed header followed by variable data):

    ┌──────────────────────────────────────────────┐
    │  Magic (2 B)  │ Ver (1 B) │ HdrLen (4 B)     │
    ├──────────────────────────────────────────────┤
    │  PayloadLen (8 B)                            │
    ├──────────────────────────────────────────────┤
    │  Header  (HdrLen bytes, MessagePack)         │
    ├──────────────────────────────────────────────┤
    │  Payload (PayloadLen bytes, encrypted blob)  │
    └──────────────────────────────────────────────┘

Clients MUST ignore unrecognised keys in the MessagePack header (§11).
"""

from __future__ import annotations

import asyncio
import struct
from enum import StrEnum
from typing import Any

import msgpack

# Protocol constants
MAGIC = b"HD"
VERSION = 0x01

# Struct formats (big-endian)
_PREFIX_FMT = "!2sBIQ"  # magic(2s), version(B), hdr_len(I), payload_len(Q)
_PREFIX_SIZE = struct.calcsize(_PREFIX_FMT)  # 15 bytes


class FrameType(StrEnum):
    """Well-known frame type identifiers placed in the ``type`` header key."""

    HELLO = "HELLO"
    META = "META"
    CHUNK = "CHUNK"
    EOF = "EOF"
    ACK = "ACK"
    ABORT = "ABORT"
    PQ_INIT = "PQ_INIT"
    PQ_RESPONSE = "PQ_RESPONSE"
    ERROR = "ERROR"


def encode_frame(header: dict[str, Any], payload: bytes = b"") -> bytes:
    """Encode a single wire frame.

    Parameters
    ----------
    header:
        Metadata dictionary serialised with MessagePack. Must contain at
        minimum a ``"type"`` key (one of :class:`FrameType`).
    payload:
        Raw binary payload (usually encrypted ciphertext).

    Returns
    -------
    bytes
        Complete frame ready for transmission.

    Raises
    ------
    ValueError
        If *header* does not contain a ``"type"`` key.
    """
    if "type" not in header:
        raise ValueError("Frame header must contain a 'type' key")

    hdr_bytes = msgpack.packb(header, use_bin_type=True)
    assert hdr_bytes is not None
    prefix = struct.pack(
        _PREFIX_FMT,
        MAGIC,
        VERSION,
        len(hdr_bytes),
        len(payload),
    )
    return prefix + hdr_bytes + payload


def decode_frame(data: bytes) -> tuple[dict[str, Any], bytes]:
    """Decode a complete wire frame from *data*.

    Parameters
    ----------
    data:
        Bytes beginning at the start of a frame.

    Returns
    -------
    tuple[dict, bytes]
        ``(header_dict, payload_bytes)``

    Raises
    ------
    ValueError
        On magic mismatch, unsupported version, or truncated data.
    """
    if len(data) < _PREFIX_SIZE:
        raise ValueError(
            f"Frame too short: need at least {_PREFIX_SIZE} bytes, got {len(data)}"
        )

    magic, version, hdr_len, payload_len = struct.unpack_from(_PREFIX_FMT, data)

    if magic != MAGIC:
        raise ValueError(f"Bad magic bytes: expected {MAGIC!r}, got {magic!r}")
    if version != VERSION:
        raise ValueError(f"Unsupported protocol version: {version:#04x}")

    total = _PREFIX_SIZE + hdr_len + payload_len
    if len(data) < total:
        raise ValueError(f"Truncated frame: expected {total} bytes, got {len(data)}")

    hdr_start = _PREFIX_SIZE
    hdr_end = hdr_start + hdr_len
    pay_end = hdr_end + payload_len

    header = msgpack.unpackb(data[hdr_start:hdr_end], raw=False)
    payload = data[hdr_end:pay_end]
    return header, payload


async def read_frame(reader: asyncio.StreamReader) -> tuple[dict[str, Any], bytes]:
    """Read exactly one frame from *reader*.

    Performs two reads: one for the fixed-size prefix, then one for the
    variable-length header + payload.

    Raises
    ------
    ConnectionError
        If the connection closes before a complete frame is received.
    ValueError
        On protocol violations.
    """
    prefix_data = await reader.readexactly(_PREFIX_SIZE)
    magic, version, hdr_len, payload_len = struct.unpack_from(_PREFIX_FMT, prefix_data)

    if magic != MAGIC:
        raise ValueError(f"Bad magic: {magic!r}")
    if version != VERSION:
        raise ValueError(f"Unsupported version: {version:#04x}")

    remainder = await reader.readexactly(hdr_len + payload_len)
    header = msgpack.unpackb(remainder[:hdr_len], raw=False)
    payload = remainder[hdr_len : hdr_len + payload_len]
    return header, payload


async def write_frame(
    writer: asyncio.StreamWriter,
    header: dict[str, Any],
    payload: bytes = b"",
) -> None:
    """Encode and write a single frame to *writer*."""
    data = encode_frame(header, payload)
    writer.write(data)
    await writer.drain()
