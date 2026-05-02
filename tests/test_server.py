"""
SignalingDB and SignalingServer unit tests.
"""

from __future__ import annotations

import asyncio
import time

import msgpack
import pytest

from hermod.server.db import (
    MAX_MESSAGE_SIZE,
    MAX_MESSAGES_PER_CHANNEL,
    SignalingDB,
)
from hermod.server.signaling import SignalingServer


# ---------------------------------------------------------------------------
# SignalingDB
# ---------------------------------------------------------------------------


class TestSignalingDB:
    async def test_create_and_exists(self, in_memory_db: SignalingDB) -> None:
        await in_memory_db.create_channel("10001")
        assert await in_memory_db.channel_exists("10001")

    async def test_nonexistent_channel(self, in_memory_db: SignalingDB) -> None:
        assert not await in_memory_db.channel_exists("99999")

    async def test_delete_channel(self, in_memory_db: SignalingDB) -> None:
        await in_memory_db.create_channel("10002")
        await in_memory_db.delete_channel("10002")
        assert not await in_memory_db.channel_exists("10002")

    async def test_duplicate_channel_raises(self, in_memory_db: SignalingDB) -> None:
        await in_memory_db.create_channel("10003")
        with pytest.raises(ValueError):
            await in_memory_db.create_channel("10003")

    async def test_enqueue_and_dequeue(self, in_memory_db: SignalingDB) -> None:
        await in_memory_db.create_channel("10004")
        blob = b"\xde\xad\xbe\xef"
        await in_memory_db.enqueue_message("10004", "sender", blob)
        msgs = await in_memory_db.dequeue_messages("10004", "sender")
        assert msgs == [blob]

    async def test_dequeue_clears_messages(self, in_memory_db: SignalingDB) -> None:
        await in_memory_db.create_channel("10005")
        await in_memory_db.enqueue_message("10005", "sender", b"msg")
        await in_memory_db.dequeue_messages("10005", "sender")
        # Second dequeue returns empty
        msgs = await in_memory_db.dequeue_messages("10005", "sender")
        assert msgs == []

    async def test_message_size_limit(self, in_memory_db: SignalingDB) -> None:
        await in_memory_db.create_channel("10006")
        big = b"X" * (MAX_MESSAGE_SIZE + 1)
        result = await in_memory_db.enqueue_message("10006", "sender", big)
        assert result is False
        msgs = await in_memory_db.dequeue_messages("10006", "sender")
        assert msgs == []

    async def test_message_count_limit(self, in_memory_db: SignalingDB) -> None:
        await in_memory_db.create_channel("10007")
        for _ in range(MAX_MESSAGES_PER_CHANNEL):
            await in_memory_db.enqueue_message("10007", "sender", b"x")
        overflow = await in_memory_db.enqueue_message("10007", "sender", b"overflow")
        assert overflow is False

    async def test_sweep_expired(self) -> None:
        # Use a tiny TTL so channels expire immediately
        async with SignalingDB(path=":memory:", ttl=0) as db:
            await db.create_channel("exp1")
            await asyncio.sleep(0.01)  # ensure created_at < threshold
            removed = await db.sweep_expired()
            assert removed >= 1
            assert not await db.channel_exists("exp1")

    async def test_dequeue_role_isolation(self, in_memory_db: SignalingDB) -> None:
        await in_memory_db.create_channel("10008")
        await in_memory_db.enqueue_message("10008", "sender", b"from-sender")
        await in_memory_db.enqueue_message("10008", "receiver", b"from-receiver")
        sender_msgs = await in_memory_db.dequeue_messages("10008", "sender")
        recv_msgs = await in_memory_db.dequeue_messages("10008", "receiver")
        assert sender_msgs == [b"from-sender"]
        assert recv_msgs == [b"from-receiver"]


# ---------------------------------------------------------------------------
# SignalingServer (integration via in-process WebSocket)
# ---------------------------------------------------------------------------


def _pack(msg: dict) -> bytes:
    return msgpack.packb(msg, use_bin_type=True)


def _unpack(data: bytes) -> dict:
    return msgpack.unpackb(data, raw=False)


class TestSignalingServer:
    """Test the server's message handling logic via WebSocket connections."""

    async def _make_server(self) -> tuple[SignalingServer, str]:
        """Start a test server on a random port; return (server_obj, url)."""
        from websockets.asyncio.server import serve

        db = SignalingDB(path=":memory:")
        await db.open()
        srv_obj = SignalingServer(db=db)
        srv = await srv_obj.start(host="127.0.0.1", port=0)
        port = srv.sockets[0].getsockname()[1]
        return srv_obj, srv, db, f"ws://127.0.0.1:{port}"

    async def test_register_and_join(self) -> None:
        from websockets.asyncio.client import connect

        srv_obj, srv, db, url = await self._make_server()
        try:
            async with connect(url) as sender:
                # Register
                await sender.send(_pack({"type": "REGISTER"}))
                reg = _unpack(await sender.recv())
                assert reg["type"] == "REGISTERED"
                channel_id = reg["channel_id"]
                assert channel_id.isdigit()

                # Receiver joins in a separate connection
                async with connect(url) as receiver:
                    code = f"{channel_id}-test-word"
                    await receiver.send(_pack({"type": "JOIN", "code": code}))
                    joined = _unpack(await receiver.recv())
                    assert joined["type"] == "JOINED_OK"
                    assert joined["channel_id"] == channel_id

                    # Sender should receive PEER_CONNECTED
                    peer_msg = _unpack(await sender.recv())
                    assert peer_msg["type"] == "PEER_CONNECTED"
        finally:
            srv.close()
            await srv.wait_closed()
            await srv_obj.stop()
            await db.close()

    async def test_join_unknown_channel(self) -> None:
        from websockets.asyncio.client import connect

        srv_obj, srv, db, url = await self._make_server()
        try:
            async with connect(url) as ws:
                await ws.send(_pack({"type": "JOIN", "code": "00000-bad-code"}))
                resp = _unpack(await ws.recv())
                assert resp["type"] == "ERROR"
                assert resp["reason"] == "channel_not_found"
        finally:
            srv.close()
            await srv.wait_closed()
            await srv_obj.stop()
            await db.close()

    async def test_relay_between_peers(self) -> None:
        from websockets.asyncio.client import connect

        srv_obj, srv, db, url = await self._make_server()
        try:
            async with connect(url) as sender:
                await sender.send(_pack({"type": "REGISTER"}))
                reg = _unpack(await sender.recv())
                channel_id = reg["channel_id"]

                async with connect(url) as receiver:
                    await receiver.send(
                        _pack({"type": "JOIN", "code": f"{channel_id}-x"})
                    )
                    await receiver.recv()  # JOINED_OK
                    await sender.recv()  # PEER_CONNECTED

                    # Sender relays to receiver
                    blob = b"secret-blob"
                    await sender.send(_pack({"type": "RELAY", "data": blob}))
                    relayed = _unpack(await receiver.recv())
                    assert relayed["type"] == "RELAY"
                    assert relayed["data"] == blob
        finally:
            srv.close()
            await srv.wait_closed()
            await srv_obj.stop()
            await db.close()
