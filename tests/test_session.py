"""
Session integration tests: full sender ↔ receiver handshake over in-process
WebSocket server + asyncio stream pair.
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import msgpack
import pytest

from hermod.core.session import ReceiverSession, SenderSession, TransferResult
from hermod.server.db import SignalingDB
from hermod.server.signaling import SignalingServer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _start_server() -> tuple[SignalingServer, object, SignalingDB, str]:
    """Start an in-process signaling server; return components + URL."""
    db = SignalingDB(path=":memory:")
    await db.open()
    srv_obj = SignalingServer(db=db)
    srv = await srv_obj.start(host="127.0.0.1", port=0)
    port = srv.sockets[0].getsockname()[1]
    return srv_obj, srv, db, f"ws://127.0.0.1:{port}"


async def _stop_server(srv_obj, srv, db) -> None:
    srv.close()
    await srv.wait_closed()
    await srv_obj.stop()
    await db.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestTextTransfer:
    async def test_send_and_receive_text(self, tmp_path: Path) -> None:
        srv_obj, srv, db, url = await _start_server()
        try:
            message = "Hello, Hermod!"
            received_code: list[str] = []

            sender = SenderSession(
                server_url=url,
                text=message,
                verify_sas=False,
                stun_timeout=0.0,
            )

            def _on_code(code: str) -> None:
                received_code.append(code)

            sender.code_callback = _on_code

            # Run sender and receiver concurrently
            async def _run_sender() -> TransferResult:
                return await sender.run()

            async def _run_receiver(code: str) -> TransferResult:
                return await ReceiverSession(
                    server_url=url,
                    code=code,
                    destination=tmp_path,
                    verify_sas=False,
                    stun_timeout=0.0,
                ).run()

            # Start sender first, wait for code, then start receiver
            sender_task = asyncio.create_task(_run_sender())

            # Poll until the code is available
            for _ in range(100):
                await asyncio.sleep(0.05)
                if received_code:
                    break
            assert received_code, "Sender never emitted a transfer code"

            receiver_result = await _run_receiver(received_code[0])
            sender_result = await sender_task

            assert sender_result.success, f"Sender failed: {sender_result.error}"
            assert receiver_result.success, f"Receiver failed: {receiver_result.error}"
            assert sender_result.bytes_transferred == len(message.encode())
            assert receiver_result.bytes_transferred == len(message.encode())

            # Verify written content
            out = receiver_result.output_path
            assert out is not None and out.exists()
            assert out.read_text(encoding="utf-8") == message

        finally:
            await _stop_server(srv_obj, srv, db)

    async def test_send_and_receive_file(self, tmp_path: Path) -> None:
        srv_obj, srv, db, url = await _start_server()
        try:
            # Create a source file (slightly over 1 MiB to cross chunk boundary)
            src = tmp_path / "source.bin"
            data = bytes(range(256)) * 5000  # ~1.28 MiB
            src.write_bytes(data)

            received_code: list[str] = []

            sender = SenderSession(
                server_url=url,
                file_path=src,
                verify_sas=False,
                stun_timeout=0.0,
            )
            sender.code_callback = lambda c: received_code.append(c)

            async def _run_sender() -> TransferResult:
                return await sender.run()

            async def _run_receiver(code: str) -> TransferResult:
                return await ReceiverSession(
                    server_url=url,
                    code=code,
                    destination=tmp_path / "dest",
                    verify_sas=False,
                    stun_timeout=0.0,
                ).run()

            # Ensure dest dir exists
            (tmp_path / "dest").mkdir()

            sender_task = asyncio.create_task(_run_sender())

            for _ in range(100):
                await asyncio.sleep(0.05)
                if received_code:
                    break
            assert received_code

            receiver_result = await _run_receiver(received_code[0])
            sender_result = await sender_task

            assert sender_result.success, f"Sender failed: {sender_result.error}"
            assert receiver_result.success, f"Receiver failed: {receiver_result.error}"
            assert receiver_result.bytes_transferred == len(data)

            out = receiver_result.output_path
            assert out is not None and out.exists()
            assert (
                hashlib.sha256(out.read_bytes()).hexdigest()
                == hashlib.sha256(data).hexdigest()
            )

        finally:
            await _stop_server(srv_obj, srv, db)
