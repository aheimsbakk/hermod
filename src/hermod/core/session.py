"""
Transfer session orchestration.

``SenderSession`` and ``ReceiverSession`` orchestrate the full eight-step
transfer flow defined in the blueprint (§6):

1. Connect to signaling server
2. REGISTER (sender) / JOIN (receiver)
3. SPAKE2 PAKE exchange via signaling relay
4. Encrypt and exchange P2P endpoint candidates
5. Establish direct P2P TCP connection
6. ML-KEM + ephemeral X25519 key exchange over P2P link
   (all cryptographic material MAC-bound to k_classical — Appendix B §1)
7. HKDF-SHA256 session key derivation (k_classical ‖ k_ecdh ‖ k_pq)
8. Encrypted payload transfer using SecretStream (Appendix B §3)
9. Hash verification and teardown

Cryptographic changes (Appendix B):
- PQ_INIT and PQ_RESPONSE frames carry HMAC-SHA256 tags over all ephemeral
  public keys / ciphertexts, keyed by k_classical, to prevent MitM attacks.
- Payload encryption uses pynacl SecretStream (XChaCha20-Poly1305 with
  automatic key ratcheting) instead of a single AES-GCM instance.
- The 24-byte SecretStream header is piggybacked on the META frame.
- The final CHUNK frame carries TAG_FINAL; the receiver detects truncation
  if EOF arrives without a prior TAG_FINAL chunk.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import msgpack
from websockets.asyncio.client import connect as ws_connect

from hermod.core.streaming import (
    CHUNK_SIZE,
    ChunkedFileReader,
    PartFileWriter,
    hash_bytes,
    hash_file,
    resolve_output_path,
)
from hermod.core.transfer_code import build_code, generate_words, parse_code
from hermod.crypto.aead import AEADCipher
from hermod.crypto.ecdh import EphemeralX25519
from hermod.crypto.kdf import derive_sas, derive_session_key
from hermod.crypto.kem import generate_kem_salt, get_kem
from hermod.crypto.mac import compute_mac, verify_mac
from hermod.crypto.pake import SPAKE2Adapter
from hermod.crypto.stream import SecretStreamPull, SecretStreamPush
from hermod.network.ice import IceCandidate, gather_candidates, ice_connect
from hermod.network.p2p import P2PConnection, PeerListener
from hermod.network.wire import FrameType, read_frame, write_frame

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Internal signaling helpers
# ------------------------------------------------------------------


def _pack(msg: dict[str, Any]) -> bytes:
    result = msgpack.packb(msg, use_bin_type=True)
    assert result is not None
    return result


def _unpack(data: bytes) -> dict[str, Any]:
    return msgpack.unpackb(data, raw=False)


async def _ws_send(ws: Any, msg: dict[str, Any]) -> None:
    await ws.send(_pack(msg))


async def _ws_recv(ws: Any, expected_type: str | None = None) -> dict[str, Any]:
    """Receive and unpack one WebSocket message.

    Raises
    ------
    ConnectionError
        If the message type is ``ERROR``.
    ValueError
        If *expected_type* is given and does not match.
    """
    raw = await asyncio.wait_for(ws.recv(), timeout=30.0)
    if isinstance(raw, str):
        raw = raw.encode()
    msg = _unpack(raw)
    if msg.get("type") == "ERROR":
        raise ConnectionError(f"Server error: {msg.get('reason', 'unknown')}")
    if expected_type and msg.get("type") != expected_type:
        raise ValueError(
            f"Expected message type {expected_type!r}, got {msg.get('type')!r}"
        )
    return msg


# ------------------------------------------------------------------
# Payload container
# ------------------------------------------------------------------


class TransferResult:
    """Outcome of a completed transfer."""

    def __init__(
        self,
        *,
        success: bool,
        bytes_transferred: int = 0,
        output_path: Path | None = None,
        text_content: str | None = None,
        sas: str = "",
        error: str = "",
    ) -> None:
        self.success = success
        self.bytes_transferred = bytes_transferred
        self.output_path = output_path
        self.text_content = text_content
        self.sas = sas
        self.error = error


# ------------------------------------------------------------------
# Sender session
# ------------------------------------------------------------------


class SenderSession:
    """Orchestrates the complete send flow.

    Parameters
    ----------
    server_url:
        WebSocket URL of the signaling server.
    file_path:
        Path to the file to send.  Mutually exclusive with *text*.
    text:
        Literal text to send.  Mutually exclusive with *file_path*.
    ssl_context:
        Optional SSL context for WSS connections.
    verify_sas:
        Pause after key derivation and print the SAS for out-of-band check.
    progress_callback:
        Called with ``(bytes_sent, total_bytes)`` after each chunk.
    """

    def __init__(
        self,
        server_url: str,
        file_path: Path | None = None,
        text: str | None = None,
        ssl_context: Any = None,
        verify_sas: bool = False,
        progress_callback: Any = None,
        stun_timeout: float = 2.0,
    ) -> None:
        if file_path is None and text is None:
            raise ValueError("Either file_path or text must be provided")
        if file_path is not None and text is not None:
            raise ValueError("file_path and text are mutually exclusive")

        self.server_url = server_url
        self.file_path = file_path
        self.text = text
        self.ssl_context = ssl_context
        self.verify_sas = verify_sas
        self.progress_callback = progress_callback
        self.stun_timeout = stun_timeout
        self.code_callback: Callable[[str], None] | None = None
        self._transfer_code = ""

    @property
    def transfer_code(self) -> str:
        """The transfer code displayed to the user (available after connect)."""
        return self._transfer_code

    async def run(self) -> TransferResult:
        """Execute the full send flow."""
        async with ws_connect(
            self.server_url,
            ssl=self.ssl_context,
            open_timeout=15,
        ) as ws:
            return await self._run_with_ws(ws)

    async def _run_with_ws(self, ws: Any) -> TransferResult:
        # Steps 1–2: Register channel
        await _ws_send(ws, {"type": "REGISTER"})
        reg = await _ws_recv(ws, "REGISTERED")
        channel_id: str = reg["channel_id"]
        passphrase = generate_words(3)
        self._transfer_code = build_code(channel_id, passphrase)
        logger.info("Transfer code: %s", self._transfer_code)
        if self.code_callback:
            self.code_callback(self._transfer_code)

        # Step 3: PAKE – start SPAKE2_A
        pake = SPAKE2Adapter(passphrase.encode(), is_sender=True)
        msg_a = pake.start()
        await _ws_send(ws, {"type": "RELAY", "data": _pack({"pake": msg_a})})

        # Wait for peer to join; server sends PEER_CONNECTED
        await _ws_recv(ws, "PEER_CONNECTED")
        logger.debug("Peer connected")

        # Receive PAKE_B
        relay_b = await _ws_recv(ws, "RELAY")
        pake_b_data = _unpack(relay_b["data"])
        msg_b: bytes = pake_b_data["pake"]
        k_classical = pake.finish(msg_b)
        logger.debug("SPAKE2 complete")

        # Step 4: Set up P2P listener, gather ICE candidates, exchange with peer
        from hermod.network.socket_utils import get_local_addresses

        local_addrs = get_local_addresses()
        listen_ip = local_addrs[0][0] if local_addrs else "0.0.0.0"

        listener = PeerListener(host=listen_ip, port=0)
        local_endpoint = await listener.bind()

        my_candidates = await gather_candidates(
            listener, stun_timeout=self.stun_timeout
        )

        aead_ep = AEADCipher(k_classical[:32])
        endpoints_enc = aead_ep.encrypt(
            _pack({"candidates": [c.to_dict() for c in my_candidates]})
        )
        await _ws_send(
            ws, {"type": "RELAY", "data": _pack({"endpoints": endpoints_enc})}
        )

        # Receive receiver's candidates
        relay_ep = await _ws_recv(ws, "RELAY")
        ep_data = _unpack(relay_ep["data"])
        recv_ep_plain = aead_ep.decrypt(ep_data["endpoints"])
        recv_ep_msg = _unpack(recv_ep_plain)
        peer_candidates = [IceCandidate.from_dict(c) for c in recv_ep_msg["candidates"]]

        # Step 5: ICE connectivity — race accept vs outbound probes
        logger.debug(
            "ICE connect; my candidates=%d peer candidates=%d",
            len(my_candidates),
            len(peer_candidates),
        )
        try:
            p2p = await ice_connect(listener, peer_candidates)
        except ConnectionError:
            await listener.close()
            raise
        finally:
            await listener.close()

        # Drop signaling channel
        try:
            await _ws_send(ws, {"type": "ABORT"})
        except Exception:  # noqa: BLE001
            pass

        return await self._run_p2p(p2p, k_classical)

    async def _run_p2p(
        self,
        p2p: P2PConnection,
        k_classical: bytes,
    ) -> TransferResult:
        """Execute post-connection crypto and transfer."""
        try:
            # Step 6a: ML-KEM – sender generates keypair + ephemeral X25519 keypair
            kem = get_kem()
            pk_kem = kem.generate_keypair()
            salt = generate_kem_salt()
            dh = EphemeralX25519()
            pk_ecdh = dh.public_key_bytes()

            # Appendix B §1: MAC-bind all ephemeral keys to k_classical before
            # sending.  Receiver MUST verify the MAC before using the keys.
            mac_init = compute_mac(k_classical, pk_kem + pk_ecdh)

            await write_frame(
                p2p.writer,
                {
                    "type": FrameType.PQ_INIT,
                    "pk": pk_kem,
                    "salt": salt,
                    "pk_ecdh": pk_ecdh,
                    "mac": mac_init,
                },
            )

            hdr, _ = await read_frame(p2p.reader)
            if hdr.get("type") != FrameType.PQ_RESPONSE:
                raise ValueError(f"Expected PQ_RESPONSE, got {hdr.get('type')!r}")
            ciphertext: bytes = hdr["ct"]
            peer_pk_ecdh: bytes = hdr["pk_ecdh"]
            mac_response: bytes = hdr["mac"]

            # Appendix B §1: Verify MAC before decapsulating or using the
            # receiver's keys.  Raises ValueError if tampered.
            verify_mac(k_classical, ciphertext + peer_pk_ecdh, mac_response)

            # Step 6b: Complete both key exchanges
            k_pq = kem.decapsulate(ciphertext)
            k_ecdh = dh.exchange(peer_pk_ecdh)

            # Step 7: Derive session key from all three secrets
            session_key = derive_session_key(k_classical, k_ecdh, k_pq, salt)
            sas = derive_sas(session_key)
            logger.debug("Session key derived; SAS=%s", sas)

            if self.verify_sas:
                print(f"\nVerification code (share verbally): {sas}", file=sys.stderr)
                confirm = input("Peer confirmed? [y/N] ").strip().lower()
                if confirm != "y":
                    await p2p.close()
                    return TransferResult(success=False, sas=sas, error="SAS rejected")

            # Step 8: Transfer payload — Appendix B §3: use SecretStream
            if self.file_path is not None:
                return await self._send_file(p2p, session_key, sas)
            else:
                return await self._send_text(p2p, session_key, sas)
        finally:
            await p2p.close()

    async def _send_file(
        self,
        p2p: P2PConnection,
        session_key: bytes,
        sas: str,
    ) -> TransferResult:
        path = self.file_path
        assert path is not None
        file_hash = hash_file(path)
        file_size = path.stat().st_size

        stream = SecretStreamPush(session_key)

        await write_frame(
            p2p.writer,
            {
                "type": FrameType.META,
                "name": path.name,
                "size": file_size,
                "hash": file_hash,
                "kind": "file",
                "stream_header": stream.header,
            },
        )

        hdr, _ = await read_frame(p2p.reader)
        if hdr.get("type") != FrameType.ACK:
            raise ValueError("Did not receive ACK for metadata")

        total_sent = 0
        with ChunkedFileReader(path) as reader:
            for seq, chunk in reader:
                total_sent += len(chunk)
                is_final = total_sent >= file_size
                enc = stream.push(chunk, is_final=is_final)
                await write_frame(
                    p2p.writer, {"type": FrameType.CHUNK, "seq": seq}, enc
                )
                if self.progress_callback:
                    self.progress_callback(total_sent, file_size)

        await write_frame(p2p.writer, {"type": FrameType.EOF, "is_eof": True})

        hdr, _ = await read_frame(p2p.reader)
        if hdr.get("type") != FrameType.ACK:
            raise ValueError("Did not receive final ACK")

        return TransferResult(success=True, bytes_transferred=total_sent, sas=sas)

    async def _send_text(
        self,
        p2p: P2PConnection,
        session_key: bytes,
        sas: str,
    ) -> TransferResult:
        text = self.text
        assert text is not None
        payload = text.encode("utf-8")
        text_hash = hash_bytes(payload)

        stream = SecretStreamPush(session_key)

        await write_frame(
            p2p.writer,
            {
                "type": FrameType.META,
                "name": "message.txt",
                "size": len(payload),
                "hash": text_hash,
                "kind": "text",
                "stream_header": stream.header,
            },
        )

        hdr, _ = await read_frame(p2p.reader)
        if hdr.get("type") != FrameType.ACK:
            raise ValueError("Did not receive ACK for metadata")

        # Single chunk — always the final frame
        enc = stream.push(payload, is_final=True)
        await write_frame(p2p.writer, {"type": FrameType.CHUNK, "seq": 0}, enc)
        await write_frame(p2p.writer, {"type": FrameType.EOF, "is_eof": True})

        hdr, _ = await read_frame(p2p.reader)
        if hdr.get("type") != FrameType.ACK:
            raise ValueError("Did not receive final ACK")

        return TransferResult(success=True, bytes_transferred=len(payload), sas=sas)


# ------------------------------------------------------------------
# Receiver session
# ------------------------------------------------------------------


class ReceiverSession:
    """Orchestrates the complete receive flow.

    Parameters
    ----------
    server_url:
        WebSocket URL of the signaling server.
    code:
        Transfer code obtained from the sender.
    destination:
        Directory or file path where received content is saved.
    ssl_context:
        Optional SSL context for WSS connections.
    verify_sas:
        Pause after key derivation for SAS verification.
    auto_accept:
        Skip interactive prompts.
    progress_callback:
        Called with ``(bytes_received, total_bytes)`` after each chunk.
    """

    def __init__(
        self,
        server_url: str,
        code: str,
        destination: Path = Path("."),
        ssl_context: Any = None,
        verify_sas: bool = False,
        auto_accept: bool = False,
        progress_callback: Any = None,
        stun_timeout: float = 2.0,
    ) -> None:
        self.server_url = server_url
        self.code = code
        self.destination = destination
        self.ssl_context = ssl_context
        self.verify_sas = verify_sas
        self.auto_accept = auto_accept
        self.progress_callback = progress_callback
        self.stun_timeout = stun_timeout

    async def run(self) -> TransferResult:
        """Execute the full receive flow."""
        async with ws_connect(
            self.server_url,
            ssl=self.ssl_context,
            open_timeout=15,
        ) as ws:
            return await self._run_with_ws(ws)

    async def _run_with_ws(self, ws: Any) -> TransferResult:
        channel_id, passphrase = parse_code(self.code)

        # Step 2: Join channel
        await _ws_send(ws, {"type": "JOIN", "code": self.code})
        joined = await _ws_recv(ws, "JOINED_OK")
        logger.debug(
            "Joined channel %s; sender_ip=%s",
            channel_id,
            joined.get("sender_ip"),
        )

        # Step 3: PAKE – start SPAKE2_B
        pake = SPAKE2Adapter(passphrase.encode(), is_sender=False)
        msg_b = pake.start()

        # Collect queued PAKE_A message (may have arrived before we joined)
        queued: list[bytes] = joined.get("queued_messages") or []
        if queued:
            pake_a_data = _unpack(queued[0])
            msg_a: bytes = pake_a_data["pake"]
        else:
            relay_a = await _ws_recv(ws, "RELAY")
            pake_a_data = _unpack(relay_a["data"])
            msg_a = pake_a_data["pake"]

        k_classical = pake.finish(msg_a)

        # Send PAKE_B
        await _ws_send(ws, {"type": "RELAY", "data": _pack({"pake": msg_b})})
        logger.debug("SPAKE2 complete")

        # Step 4: Decode sender's candidates and send our own
        aead_ep = AEADCipher(k_classical[:32])

        relay_ep = await _ws_recv(ws, "RELAY")
        ep_data = _unpack(relay_ep["data"])
        sender_ep_plain = aead_ep.decrypt(ep_data["endpoints"])
        sender_ep_msg = _unpack(sender_ep_plain)
        sender_candidates = [
            IceCandidate.from_dict(c) for c in sender_ep_msg["candidates"]
        ]
        logger.debug("Sender ICE candidates: %s", sender_candidates)

        # Bind our own listener and gather candidates
        from hermod.network.socket_utils import get_local_addresses

        local_addrs = get_local_addresses()
        listen_ip = local_addrs[0][0] if local_addrs else "0.0.0.0"
        listener = PeerListener(host=listen_ip, port=0)
        await listener.bind()

        my_candidates = await gather_candidates(
            listener, stun_timeout=self.stun_timeout
        )

        endpoints_enc = aead_ep.encrypt(
            _pack({"candidates": [c.to_dict() for c in my_candidates]})
        )
        await _ws_send(
            ws, {"type": "RELAY", "data": _pack({"endpoints": endpoints_enc})}
        )

        # Step 5: ICE connectivity — race accept vs outbound probes
        logger.debug(
            "ICE connect; my candidates=%d sender candidates=%d",
            len(my_candidates),
            len(sender_candidates),
        )
        try:
            p2p = await ice_connect(listener, sender_candidates)
        except ConnectionError:
            await listener.close()
            raise
        finally:
            await listener.close()

        try:
            await _ws_send(ws, {"type": "ABORT"})
        except Exception:  # noqa: BLE001
            pass

        return await self._run_p2p(p2p, k_classical)

    async def _run_p2p(self, p2p: P2PConnection, k_classical: bytes) -> TransferResult:
        """Execute post-connection crypto and receive."""
        try:
            # Step 6a: ML-KEM – receiver reads PQ_INIT, verifies MAC, encapsulates
            hdr, _ = await read_frame(p2p.reader)
            if hdr.get("type") != FrameType.PQ_INIT:
                raise ValueError(f"Expected PQ_INIT, got {hdr.get('type')!r}")
            pk_kem: bytes = hdr["pk"]
            salt: bytes = hdr["salt"]
            sender_pk_ecdh: bytes = hdr["pk_ecdh"]
            mac_init: bytes = hdr["mac"]

            # Appendix B §1: Verify MAC before using sender's keys.
            # Raises ValueError if any key has been replaced by a MitM.
            verify_mac(k_classical, pk_kem + sender_pk_ecdh, mac_init)

            kem = get_kem()
            ciphertext, k_pq = kem.encapsulate(pk_kem)

            dh = EphemeralX25519()
            pk_ecdh = dh.public_key_bytes()

            # Appendix B §1: MAC-bind our response material to k_classical.
            mac_response = compute_mac(k_classical, ciphertext + pk_ecdh)

            await write_frame(
                p2p.writer,
                {
                    "type": FrameType.PQ_RESPONSE,
                    "ct": ciphertext,
                    "pk_ecdh": pk_ecdh,
                    "mac": mac_response,
                },
            )

            # Step 6b: Complete X25519 exchange
            k_ecdh = dh.exchange(sender_pk_ecdh)

            # Step 7: Derive session key from all three secrets
            session_key = derive_session_key(k_classical, k_ecdh, k_pq, salt)
            sas = derive_sas(session_key)
            logger.debug("Session key derived; SAS=%s", sas)

            if self.verify_sas:
                print(f"\nVerification code (share verbally): {sas}", file=sys.stderr)
                if not self.auto_accept:
                    confirm = input("Codes match? [y/N] ").strip().lower()
                    if confirm != "y":
                        await p2p.close()
                        return TransferResult(
                            success=False, sas=sas, error="SAS rejected"
                        )

            return await self._receive_payload(p2p, session_key, sas)
        finally:
            await p2p.close()

    async def _receive_payload(
        self,
        p2p: P2PConnection,
        session_key: bytes,
        sas: str,
    ) -> TransferResult:
        # Metadata frame
        meta_hdr, _ = await read_frame(p2p.reader)
        if meta_hdr.get("type") != FrameType.META:
            raise ValueError(f"Expected META, got {meta_hdr.get('type')!r}")

        name: str = meta_hdr["name"]
        total_size: int = meta_hdr["size"]
        expected_hash: str = meta_hdr["hash"]
        kind: str = meta_hdr.get("kind", "file")
        stream_header: bytes = meta_hdr["stream_header"]

        stream = SecretStreamPull(session_key, stream_header)

        await write_frame(p2p.writer, {"type": FrameType.ACK})

        if kind == "text":
            return await self._receive_text(p2p, stream, sas, total_size, expected_hash)
        return await self._receive_file(
            p2p, stream, sas, name, total_size, expected_hash
        )

    async def _receive_text(
        self,
        p2p: P2PConnection,
        stream: SecretStreamPull,
        sas: str,
        total_size: int,
        expected_hash: str,
    ) -> TransferResult:
        """Collect all chunks in memory and return decoded text_content."""
        chunks: list[bytes] = []
        total_recv = 0
        last_chunk_was_final = False

        while True:
            hdr, payload = await read_frame(p2p.reader)
            frame_type = hdr.get("type")

            if frame_type == FrameType.CHUNK:
                plaintext, is_final = stream.pull(payload)
                chunks.append(plaintext)
                total_recv += len(plaintext)
                last_chunk_was_final = is_final
                if self.progress_callback:
                    self.progress_callback(total_recv, total_size)

            elif frame_type == FrameType.EOF:
                if not last_chunk_was_final:
                    raise ValueError(
                        "Stream truncated: EOF received without TAG_FINAL chunk"
                    )
                break

            elif frame_type == FrameType.ABORT:
                return TransferResult(success=False, error="Transfer aborted by sender")

            else:
                raise ValueError(f"Unexpected frame type {frame_type!r}")

        raw = b"".join(chunks)
        actual_hash = hash_bytes(raw)
        if actual_hash != expected_hash:
            raise ValueError(
                f"Hash mismatch: expected {expected_hash!r}, got {actual_hash!r}"
            )

        await write_frame(p2p.writer, {"type": FrameType.ACK})

        return TransferResult(
            success=True,
            bytes_transferred=total_recv,
            text_content=raw.decode("utf-8"),
            sas=sas,
        )

    async def _receive_file(
        self,
        p2p: P2PConnection,
        stream: SecretStreamPull,
        sas: str,
        name: str,
        total_size: int,
        expected_hash: str,
    ) -> TransferResult:
        """Stream chunks to disk under the original filename."""
        output_path = resolve_output_path(self.destination, name)
        writer = PartFileWriter(output_path)
        last_chunk_was_final = False

        with writer:
            total_recv = 0
            while True:
                hdr, payload = await read_frame(p2p.reader)
                frame_type = hdr.get("type")

                if frame_type == FrameType.CHUNK:
                    plaintext, is_final = stream.pull(payload)
                    writer.write_chunk(plaintext)
                    total_recv += len(plaintext)
                    last_chunk_was_final = is_final
                    if self.progress_callback:
                        self.progress_callback(total_recv, total_size)

                elif frame_type == FrameType.EOF:
                    if not last_chunk_was_final:
                        raise ValueError(
                            "Stream truncated: EOF received without TAG_FINAL chunk"
                        )
                    break

                elif frame_type == FrameType.ABORT:
                    writer.discard()
                    return TransferResult(
                        success=False, error="Transfer aborted by sender"
                    )
                else:
                    raise ValueError(f"Unexpected frame type {frame_type!r}")

            final_path = writer.finalise(expected_hash)

        await write_frame(p2p.writer, {"type": FrameType.ACK})

        return TransferResult(
            success=True,
            bytes_transferred=total_recv,
            output_path=final_path,
            sas=sas,
        )
