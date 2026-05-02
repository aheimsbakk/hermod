"""
Unit tests for hermod.network.stun.

All tests are pure (no network I/O): they exercise the packet encoding and
decoding functions directly.
"""

from __future__ import annotations

import struct

import pytest

from hermod.network.stun import (
    _BINDING_REQUEST,
    _BINDING_RESPONSE_SUCCESS,
    _MAGIC_COOKIE,
    build_binding_request,
    parse_binding_response,
)


# ---------------------------------------------------------------------------
# build_binding_request
# ---------------------------------------------------------------------------


def test_build_request_length() -> None:
    msg, txn_id = build_binding_request()
    assert len(msg) == 20, "Binding request must be exactly 20 bytes (header only)"
    assert len(txn_id) == 12


def test_build_request_type() -> None:
    msg, _ = build_binding_request()
    (msg_type,) = struct.unpack_from(">H", msg, 0)
    assert msg_type == _BINDING_REQUEST


def test_build_request_magic() -> None:
    msg, _ = build_binding_request()
    (magic,) = struct.unpack_from(">I", msg, 4)
    assert magic == _MAGIC_COOKIE


def test_build_request_txn_id_embedded() -> None:
    msg, txn_id = build_binding_request()
    assert msg[8:20] == txn_id


def test_build_request_length_field_zero() -> None:
    """Attribute length in header must be 0 for a bare Binding Request."""
    msg, _ = build_binding_request()
    (attr_len,) = struct.unpack_from(">H", msg, 2)
    assert attr_len == 0


def test_build_request_unique_txn_ids() -> None:
    _, txn1 = build_binding_request()
    _, txn2 = build_binding_request()
    assert txn1 != txn2, "Each request must have a unique transaction ID"


# ---------------------------------------------------------------------------
# parse_binding_response — valid XOR-MAPPED-ADDRESS
# ---------------------------------------------------------------------------


def _make_response(
    ip: str = "203.0.113.5",
    port: int = 54321,
    *,
    txn_id: bytes | None = None,
    use_xor: bool = True,
) -> tuple[bytes, bytes]:
    """Craft a minimal synthetic STUN Binding Response."""
    if txn_id is None:
        import os

        txn_id = os.urandom(12)

    if use_xor:
        attr_type = 0x0020  # XOR-MAPPED-ADDRESS
        xport = port ^ (_MAGIC_COOKIE >> 16)
        ip_parts = [int(x) for x in ip.split(".")]
        ip_int = (
            (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3]
        )
        xip = ip_int ^ _MAGIC_COOKIE
        attr_value = struct.pack(">BBH I", 0x00, 0x01, xport, xip)
    else:
        attr_type = 0x0001  # MAPPED-ADDRESS (legacy)
        ip_bytes = bytes(int(x) for x in ip.split("."))
        attr_value = struct.pack(">BB", 0x00, 0x01) + struct.pack(">H", port) + ip_bytes

    attr_len = len(attr_value)
    attr_block = struct.pack(">HH", attr_type, attr_len) + attr_value
    # Pad to 4-byte boundary
    pad = (-attr_len) % 4
    attr_block += b"\x00" * pad

    msg_len = len(attr_block)
    header = (
        struct.pack(">HHI", _BINDING_RESPONSE_SUCCESS, msg_len, _MAGIC_COOKIE) + txn_id
    )

    return header + attr_block, txn_id


def test_parse_xor_mapped_address() -> None:
    data, txn_id = _make_response("203.0.113.5", 54321, use_xor=True)
    result = parse_binding_response(data, txn_id)
    assert result == ("203.0.113.5", 54321)


def test_parse_mapped_address_fallback() -> None:
    data, txn_id = _make_response("192.168.1.10", 12345, use_xor=False)
    result = parse_binding_response(data, txn_id)
    assert result == ("192.168.1.10", 12345)


def test_parse_returns_none_on_wrong_txn_id() -> None:
    data, _ = _make_response("1.2.3.4", 1234)
    wrong_txn = b"\x00" * 12
    result = parse_binding_response(data, wrong_txn)
    assert result is None


def test_parse_returns_none_on_wrong_type() -> None:
    """Non-success message type must be rejected."""
    data, txn_id = _make_response("1.2.3.4", 1234)
    # Flip response type to 0x0111 (error response)
    patched = struct.pack(">H", 0x0111) + data[2:]
    result = parse_binding_response(patched, txn_id)
    assert result is None


def test_parse_returns_none_on_wrong_magic() -> None:
    data, txn_id = _make_response("1.2.3.4", 1234)
    # Corrupt the magic cookie bytes
    patched = data[:4] + b"\xde\xad\xbe\xef" + data[8:]
    result = parse_binding_response(patched, txn_id)
    assert result is None


def test_parse_returns_none_on_truncated_header() -> None:
    result = parse_binding_response(b"\x01\x01", b"\x00" * 12)
    assert result is None


def test_parse_returns_none_on_empty() -> None:
    result = parse_binding_response(b"", b"\x00" * 12)
    assert result is None


def test_parse_xor_prefers_over_mapped(tmp_path: pytest.fixture) -> None:  # type: ignore[type-arg]
    """When both XOR-MAPPED-ADDRESS and MAPPED-ADDRESS are present,
    XOR-MAPPED-ADDRESS must win."""
    import os

    txn_id = os.urandom(12)

    # Build XOR attr first
    xport = 9999 ^ (_MAGIC_COOKIE >> 16)
    ip_parts = [203, 0, 113, 5]
    ip_int = (
        (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3]
    )
    xip = ip_int ^ _MAGIC_COOKIE
    xor_val = struct.pack(">BBH I", 0x00, 0x01, xport, xip)
    xor_attr = struct.pack(">HH", 0x0020, len(xor_val)) + xor_val

    # Build MAPPED addr with a DIFFERENT ip/port
    mapped_val = (
        struct.pack(">BB", 0x00, 0x01) + struct.pack(">H", 1111) + bytes([10, 0, 0, 1])
    )
    mapped_attr = struct.pack(">HH", 0x0001, len(mapped_val)) + mapped_val

    attrs = xor_attr + mapped_attr
    msg_len = len(attrs)
    header = (
        struct.pack(">HHI", _BINDING_RESPONSE_SUCCESS, msg_len, _MAGIC_COOKIE) + txn_id
    )

    result = parse_binding_response(header + attrs, txn_id)
    assert result == ("203.0.113.5", 9999)
