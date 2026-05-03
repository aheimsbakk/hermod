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
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from hermod.core.session import ReceiverSession, SenderSession, TransferResult
from hermod.core.trust import TrustStore, pinned_ssl_context
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

            assert receiver_result.text_content == message
            assert receiver_result.output_path is None
        finally:
            await _stop_server(srv_obj, srv, db)


# ---------------------------------------------------------------------------
# Regression: peer_wait_timeout is respected
# ---------------------------------------------------------------------------


async def test_sender_peer_wait_timeout_respected(
    server_ssl_ctx: ssl.SSLContext,
    client_ssl_ctx: ssl.SSLContext,
) -> None:
    """SenderSession must time out at peer_wait_timeout, not the hardcoded 30s.

    Regression for: sender waiting for PEER_CONNECTED used a hardcoded 30-second
    timeout instead of the configured TTL, causing ``hermod tx`` to always exit
    after 30 s regardless of ``--ttl``.
    """
    import msgpack
    from websockets.asyncio.server import serve as ws_serve

    async def _stall_server(ws) -> None:
        """Accept REGISTER, reply REGISTERED, then consume messages until disconnect.

        Never sends PEER_CONNECTED.  Using ``async for`` (instead of
        ``asyncio.sleep``) lets the handler exit promptly when the client
        closes the connection, so the server's ``wait_closed()`` returns fast.
        """
        raw = await ws.recv()
        msg = msgpack.unpackb(raw, raw=False)
        assert msg["type"] == "REGISTER"
        await ws.send(
            msgpack.packb(
                {"type": "REGISTERED", "channel_id": "00001"}, use_bin_type=True
            )
        )
        # Drain incoming messages without responding; exit when client disconnects.
        try:
            async for _ in ws:
                pass
        except Exception:
            pass

    async with ws_serve(_stall_server, "127.0.0.1", 0, ssl=server_ssl_ctx) as server:
        port = server.sockets[0].getsockname()[1]
        url = f"wss://127.0.0.1:{port}"

        session = SenderSession(
            server_url=url,
            text="hi",
            ssl_context=client_ssl_ctx,
            stun_timeout=0.0,
            peer_wait_timeout=0.3,  # 300 ms — must NOT wait 30 s
        )

        t0 = asyncio.get_event_loop().time()
        with pytest.raises((asyncio.TimeoutError, ConnectionError, OSError)):
            await session.run()
        elapsed = asyncio.get_event_loop().time() - t0

        # Must time out well before the old hardcoded 30 s limit.
        assert elapsed < 5.0, f"Took {elapsed:.1f}s — peer_wait_timeout not respected"


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


# ---------------------------------------------------------------------------
# End-to-end: trust workflow → text + file transfer
# ---------------------------------------------------------------------------


class TestTrustAndTransfer:
    """Full end-to-end workflow: start server, pin certificate via trust, then
    verify both a text and a file transfer succeed using the pinned SSL context.

    This exercises the same path a real user follows:
      hermod serve  →  hermod trust host:port  →  hermod tx / hermod rx
    """

    async def test_trust_pin_then_text_and_file(
        self,
        tmp_path: Path,
        server_ssl_ctx: ssl.SSLContext,
    ) -> None:
        _assert_pq_kem_active()

        # 1. Start the signaling server.
        srv_obj, srv, db, url = await _start_server(server_ssl_ctx)
        host = "127.0.0.1"
        port = int(url.rsplit(":", 1)[-1])

        try:
            # 2. Pin the certificate — mirrors what `hermod trust host:port` does.
            #    Use asyncio.open_connection so the event loop keeps serving the
            #    WebSocket server during the TLS handshake.
            fetch_ctx = ssl.create_default_context()
            fetch_ctx.check_hostname = False
            fetch_ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.open_connection(host, port, ssl=fetch_ctx)
            ssl_obj = writer.get_extra_info("ssl_object")
            assert ssl_obj is not None, "Could not retrieve SSL object from connection"
            der = ssl_obj.getpeercert(binary_form=True)
            writer.close()
            await writer.wait_closed()

            assert der is not None, "Server returned no certificate"
            fingerprint = hashlib.sha256(der).hexdigest()
            cert_obj = x509.load_der_x509_certificate(der)
            cert_pem_bytes = cert_obj.public_bytes(serialization.Encoding.PEM)

            store = TrustStore(config_path=tmp_path / "config.yaml")
            store.add(url, fingerprint, cert_pem_bytes)

            pinned_fp = store.get(url)
            pinned_pem = store.get_cert_pem(url)
            assert pinned_fp is not None, "Trust store missing fingerprint"
            assert pinned_pem is not None, "Trust store missing cert PEM"

            client_ctx = pinned_ssl_context(pinned_fp, pinned_pem)

            # 3. Text transfer: send and verify exact content.
            text_dest = tmp_path / "text_dest"
            text_dest.mkdir()
            message = "Trust-pinned text transfer via Hermod PQ!"

            s_res, r_res = await _run_transfer(
                url, client_ctx, text=message, dest=text_dest
            )

            assert s_res.success, f"Text sender failed: {s_res.error}"
            assert r_res.success, f"Text receiver failed: {r_res.error}"
            assert s_res.bytes_transferred == len(message.encode())
            assert r_res.bytes_transferred == len(message.encode())
            assert r_res.text_content == message
            assert r_res.output_path is None

            # 4. File transfer: send and verify SHA-256 integrity.
            src = tmp_path / "payload.bin"
            src.write_bytes(bytes(range(256)) * 200)  # 51.2 KiB
            file_dest = tmp_path / "file_dest"
            file_dest.mkdir()

            s_res, r_res = await _run_transfer(
                url, client_ctx, file_path=src, dest=file_dest
            )

            assert s_res.success, f"File sender failed: {s_res.error}"
            assert r_res.success, f"File receiver failed: {r_res.error}"
            assert r_res.bytes_transferred == len(src.read_bytes())
            out = r_res.output_path
            assert out is not None and out.exists()
            assert out.name == src.name
            assert (
                hashlib.sha256(out.read_bytes()).hexdigest()
                == hashlib.sha256(src.read_bytes()).hexdigest()
            )

        finally:
            await _stop_server(srv_obj, srv, db)
