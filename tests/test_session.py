"""
Session integration tests: full sender ↔ receiver handshake over in-process
WSS signaling server + asyncio stream pair.

Every test asserts that the active KEM backend is ML-KEM-768 via kyber-py,
confirming post-quantum security is live for each transfer.

The signaling server is started with a self-signed TLS certificate (RSA-2048,
generated once per session by the ``server_ssl_ctx`` / ``client_ssl_ctx``
fixtures in conftest.py).  All connections use WSS — plain WS is not allowed.
"""

from __future__ import annotations

import asyncio
import hashlib
import ssl
from pathlib import Path

import pytest

from hermod.core.session import ReceiverSession, SenderSession, TransferResult
from hermod.crypto.kem import MLKEM768KyberPy, get_kem
from hermod.server.db import SignalingDB
from hermod.server.signaling import SignalingServer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _start_server(
    ssl_context: ssl.SSLContext,
) -> tuple[SignalingServer, object, SignalingDB, str]:
    """Start an in-process WSS signaling server; return components + URL."""
    db = SignalingDB(path=":memory:")
    await db.open()
    srv_obj = SignalingServer(db=db)
    srv = await srv_obj.start(host="127.0.0.1", port=0, ssl_context=ssl_context)
    port = srv.sockets[0].getsockname()[1]
    return srv_obj, srv, db, f"wss://127.0.0.1:{port}"


async def _stop_server(srv_obj, srv, db) -> None:
    srv.close()
    await srv.wait_closed()
    await srv_obj.stop()
    await db.close()


def _assert_pq_kem_active() -> None:
    """Fail fast if the active KEM backend is not ML-KEM-768 (kyber-py or liboqs)."""
    kem = get_kem()
    assert isinstance(kem, MLKEM768KyberPy), (
        f"Expected MLKEM768KyberPy as the active KEM backend, got {type(kem).__name__}. "
        "Install kyber-py (uv add kyber-py) or liboqs to enable post-quantum security."
    )


async def _run_transfer(
    url: str,
    client_ssl_ctx: ssl.SSLContext,
    *,
    text: str | None = None,
    file_path: Path | None = None,
    dest: Path,
) -> tuple[TransferResult, TransferResult]:
    """Run a full sender ↔ receiver session; return (sender_result, receiver_result)."""
    received_code: list[str] = []

    sender = SenderSession(
        server_url=url,
        text=text,
        file_path=file_path,
        ssl_context=client_ssl_ctx,
        verify_sas=False,
        stun_timeout=0.0,
    )
    sender.code_callback = lambda c: received_code.append(c)

    async def _recv() -> TransferResult:
        for _ in range(100):
            await asyncio.sleep(0.05)
            if received_code:
                break
        assert received_code, "Sender never emitted a transfer code"
        return await ReceiverSession(
            server_url=url,
            code=received_code[0],
            destination=dest,
            ssl_context=client_ssl_ctx,
            verify_sas=False,
            stun_timeout=0.0,
        ).run()

    sender_task = asyncio.create_task(sender.run())
    receiver_result = await _recv()
    sender_result = await sender_task
    return sender_result, receiver_result


# ---------------------------------------------------------------------------
# End-to-end: text transfer
# ---------------------------------------------------------------------------


class TestTextTransfer:
    async def test_send_and_receive_text(
        self,
        tmp_path: Path,
        server_ssl_ctx: ssl.SSLContext,
        client_ssl_ctx: ssl.SSLContext,
    ) -> None:
        _assert_pq_kem_active()

        srv_obj, srv, db, url = await _start_server(server_ssl_ctx)
        try:
            message = "Hello, Hermod!"
            sender_result, receiver_result = await _run_transfer(
                url, client_ssl_ctx, text=message, dest=tmp_path
            )

            assert sender_result.success, f"Sender failed: {sender_result.error}"
            assert receiver_result.success, f"Receiver failed: {receiver_result.error}"
            assert sender_result.bytes_transferred == len(message.encode())
            assert receiver_result.bytes_transferred == len(message.encode())

            out = receiver_result.output_path
            assert out is not None and out.exists()
            assert out.read_text(encoding="utf-8") == message
        finally:
            await _stop_server(srv_obj, srv, db)

    async def test_unicode_text_roundtrip(
        self,
        tmp_path: Path,
        server_ssl_ctx: ssl.SSLContext,
        client_ssl_ctx: ssl.SSLContext,
    ) -> None:
        """Non-ASCII content must survive the full PQ-encrypted transfer."""
        _assert_pq_kem_active()

        srv_obj, srv, db, url = await _start_server(server_ssl_ctx)
        try:
            message = "こんにちは Hermod! PQ KEM test ✓ 🔐"
            sender_result, receiver_result = await _run_transfer(
                url, client_ssl_ctx, text=message, dest=tmp_path
            )

            assert sender_result.success, f"Sender failed: {sender_result.error}"
            assert receiver_result.success, f"Receiver failed: {receiver_result.error}"

            out = receiver_result.output_path
            assert out is not None
            assert out.read_text(encoding="utf-8") == message
        finally:
            await _stop_server(srv_obj, srv, db)


# ---------------------------------------------------------------------------
# End-to-end: file transfer
# ---------------------------------------------------------------------------


class TestFileTransfer:
    async def test_send_and_receive_small_file(
        self,
        tmp_path: Path,
        server_ssl_ctx: ssl.SSLContext,
        client_ssl_ctx: ssl.SSLContext,
    ) -> None:
        """Small file (< 1 chunk) transfers with correct content and hash."""
        _assert_pq_kem_active()

        srv_obj, srv, db, url = await _start_server(server_ssl_ctx)
        try:
            src = tmp_path / "small.txt"
            src.write_bytes(b"Small file content for Hermod PQ transfer test.")
            dest = tmp_path / "dest"
            dest.mkdir()

            sender_result, receiver_result = await _run_transfer(
                url, client_ssl_ctx, file_path=src, dest=dest
            )

            assert sender_result.success, f"Sender failed: {sender_result.error}"
            assert receiver_result.success, f"Receiver failed: {receiver_result.error}"

            out = receiver_result.output_path
            assert out is not None and out.exists()
            assert out.read_bytes() == src.read_bytes()
        finally:
            await _stop_server(srv_obj, srv, db)

    async def test_send_and_receive_large_file(
        self,
        tmp_path: Path,
        server_ssl_ctx: ssl.SSLContext,
        client_ssl_ctx: ssl.SSLContext,
    ) -> None:
        """Multi-chunk file (~1.28 MiB) verifies SHA-256 integrity end-to-end."""
        _assert_pq_kem_active()

        srv_obj, srv, db, url = await _start_server(server_ssl_ctx)
        try:
            src = tmp_path / "source.bin"
            data = bytes(range(256)) * 5000  # ~1.28 MiB — crosses chunk boundary
            src.write_bytes(data)
            dest = tmp_path / "dest"
            dest.mkdir()

            sender_result, receiver_result = await _run_transfer(
                url, client_ssl_ctx, file_path=src, dest=dest
            )

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

    async def test_filename_is_preserved(
        self,
        tmp_path: Path,
        server_ssl_ctx: ssl.SSLContext,
        client_ssl_ctx: ssl.SSLContext,
    ) -> None:
        """Receiver must save the file under the original filename."""
        _assert_pq_kem_active()

        srv_obj, srv, db, url = await _start_server(server_ssl_ctx)
        try:
            src = tmp_path / "important_document.pdf"
            src.write_bytes(b"%PDF-1.4 fake content")
            dest = tmp_path / "dest"
            dest.mkdir()

            _, receiver_result = await _run_transfer(
                url, client_ssl_ctx, file_path=src, dest=dest
            )

            assert receiver_result.success, f"Receiver failed: {receiver_result.error}"
            out = receiver_result.output_path
            assert out is not None
            assert out.name == "important_document.pdf"
        finally:
            await _stop_server(srv_obj, srv, db)
