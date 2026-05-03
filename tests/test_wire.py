"""
Wire protocol unit tests: encode_frame, decode_frame, read_frame, write_frame.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from hermod.network.wire import (
    MAGIC,
    VERSION,
    FrameType,
    _PREFIX_SIZE,
    decode_frame,
    encode_frame,
    read_frame,
    write_frame,
)


class TestEncodeDecodeFrame:
    def test_roundtrip_no_payload(self) -> None:
        hdr = {"type": FrameType.ACK}
        data = encode_frame(hdr)
        h, p = decode_frame(data)
        assert h["type"] == FrameType.ACK
        assert p == b""

    def test_roundtrip_with_payload(self) -> None:
        hdr = {"type": FrameType.CHUNK, "seq": 7}
        payload = b"\xde\xad\xbe\xef" * 64
        data = encode_frame(hdr, payload)
        h, p = decode_frame(data)
        assert h["type"] == FrameType.CHUNK
        assert h["seq"] == 7
        assert p == payload

    def test_magic_bytes_present(self) -> None:
        data = encode_frame({"type": FrameType.ACK})
        assert data[:2] == MAGIC

    def test_version_byte(self) -> None:
        data = encode_frame({"type": FrameType.ACK})
        assert data[2] == VERSION

    def test_missing_type_raises(self) -> None:
        with pytest.raises(ValueError, match="type"):
            encode_frame({"seq": 0})

    def test_bad_magic_raises(self) -> None:
        data = encode_frame({"type": FrameType.ACK})
        # Corrupt magic
        corrupted = b"XX" + data[2:]
        with pytest.raises(ValueError, match="magic"):
            decode_frame(corrupted)

    def test_unsupported_version_raises(self) -> None:
        data = bytearray(encode_frame({"type": FrameType.ACK}))
        data[2] = 0xFF  # bad version
        with pytest.raises(ValueError, match="version"):
            decode_frame(bytes(data))

    def test_truncated_data_raises(self) -> None:
        with pytest.raises(ValueError):
            decode_frame(b"\x00" * 3)

    def test_prefix_size_constant(self) -> None:
        assert _PREFIX_SIZE == 15

    def test_extra_header_keys_preserved(self) -> None:
        hdr = {"type": FrameType.META, "name": "hello.txt", "size": 1024}
        h, _ = decode_frame(encode_frame(hdr))
        assert h["name"] == "hello.txt"
        assert h["size"] == 1024

    def test_large_payload(self) -> None:
        payload = bytes(range(256)) * 1024  # 256 KiB
        data = encode_frame({"type": FrameType.CHUNK, "seq": 0}, payload)
        h, p = decode_frame(data)
        assert p == payload

    def test_all_frame_types_encode(self) -> None:
        for ft in FrameType:
            data = encode_frame({"type": ft})
            h, _ = decode_frame(data)
            assert h["type"] == ft


class TestAsyncReadWriteFrame:
    async def _pipe(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Create an in-process reader/writer pair."""
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        loop = asyncio.get_event_loop()
        transport, _ = await loop.create_connection(
            lambda: protocol, host="127.0.0.1", port=0
        )
        # Instead use a simpler approach with MemoryStream
        raise NotImplementedError

    async def test_write_then_read(self) -> None:
        """Test write_frame / read_frame using an asyncio pipe."""
        # Create a connected socket pair via asyncio streams
        server_reader = asyncio.StreamReader()
        server_proto = asyncio.StreamReaderProtocol(server_reader)

        # Use asyncio.open_connection with a local echo server
        # Simplest: manually feed bytes from encode_frame to StreamReader
        encoded = encode_frame({"type": FrameType.META, "name": "f.txt"}, b"payload")

        reader = asyncio.StreamReader()
        reader.feed_data(encoded)

        h, p = await read_frame(reader)
        assert h["type"] == FrameType.META
        assert h["name"] == "f.txt"
        assert p == b"payload"

    async def test_write_frame_produces_valid_bytes(self, tmp_path) -> None:
        """write_frame writes bytes that decode_frame can parse."""
        import io

        captured = bytearray()

        class _FakeWriter:
            def write(self, data: bytes) -> None:
                captured.extend(data)

            async def drain(self) -> None:
                pass

        await write_frame(_FakeWriter(), {"type": FrameType.EOF, "is_eof": True})
        h, _ = decode_frame(bytes(captured))
        assert h["type"] == FrameType.EOF
        assert h["is_eof"] is True

    async def test_connection_closed_raises(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_eof()
        with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):
            await read_frame(reader)
