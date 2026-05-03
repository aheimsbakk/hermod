"""
WebSocket signaling server.

Acts as an ephemeral blind relay (§7). Each channel connects exactly two
peers: a sender (role ``"sender"``) and a receiver (role ``"receiver"``).
The server:
 - Assigns channel IDs on REGISTER requests
 - Reports the client's public IP back to each peer
 - Relays opaque binary messages between the two peers
 - Enforces message-count and size limits (§8)
 - Runs a background TTL sweep to purge expired channels

Signaling message format (MessagePack):
  All messages are dicts with at least a ``"type"`` key.

Client → Server messages:
  REGISTER  – sender creates a channel; server returns channel_id + public IP
  JOIN      – receiver joins with transfer code
  RELAY     – relay opaque bytes to the peer
  ABORT     – abort and delete the channel

Server → Client messages:
  REGISTERED     – channel_id + public_ip
  JOINED_OK      – receiver acknowledged; includes sender's public IP
  PEER_CONNECTED – sent to sender when receiver joins
  RELAY          – forwarded peer message
  PEER_DISCONNECTED – peer left
  ERROR          – error details
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import msgpack
from websockets.asyncio.server import Server, ServerConnection, serve
from websockets.exceptions import ConnectionClosed

from hermod.server.db import DEFAULT_TTL, SignalingDB
from hermod.server.rate_limit import RateLimiter

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _pack(msg: dict[str, Any]) -> bytes:
    result = msgpack.packb(msg, use_bin_type=True)
    assert result is not None
    return result


def _unpack(data: bytes) -> dict[str, Any]:
    return msgpack.unpackb(data, raw=False)


def _gen_channel_id() -> str:
    """Generate a short random 5-digit numeric channel ID."""
    return str(int.from_bytes(os.urandom(2), "big") % 90000 + 10000)


# ------------------------------------------------------------------
# SignalingServer
# ------------------------------------------------------------------


class SignalingServer:
    """Async WebSocket signaling server.

    Parameters
    ----------
    db:
        An opened :class:`~hermod.server.db.SignalingDB` instance.
    rate_limiter:
        Optional rate limiter; a default one is created if not provided.
    ttl:
        Channel TTL in seconds.
    sweep_interval:
        How often (seconds) to run the TTL sweep background task.
    """

    def __init__(
        self,
        db: SignalingDB,
        rate_limiter: RateLimiter | None = None,
        ttl: int = DEFAULT_TTL,
        sweep_interval: int = 300,
    ) -> None:
        self._db = db
        self._rl = rate_limiter or RateLimiter()
        self._ttl = ttl
        self._sweep_interval = sweep_interval
        # Active connections: channel_id → {role: websocket}
        self._channels: dict[str, dict[str, ServerConnection]] = {}
        self._sweep_task: asyncio.Task | None = None

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    async def start(
        self,
        host: str = "0.0.0.0",
        port: int = 8786,
        ssl_context=None,
    ) -> Server:
        """Start the WebSocket server; return the :class:`Server` handle."""
        self._sweep_task = asyncio.create_task(self._sweep_loop())
        server = await serve(
            self._handle,
            host,
            port,
            ssl=ssl_context,
        )
        logger.info("Signaling server listening on %s:%d", host, port)
        return server

    async def stop(self) -> None:
        """Stop the background sweep task."""
        if self._sweep_task:
            self._sweep_task.cancel()
            try:
                await self._sweep_task
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------

    async def _handle(self, ws: ServerConnection) -> None:
        """Handle one client WebSocket connection."""
        remote = ws.remote_address
        client_ip = remote[0] if remote else "unknown"

        if not self._rl.check_ip(client_ip):
            await ws.send(_pack({"type": "ERROR", "reason": "rate_limited"}))
            return

        logger.debug("New connection from %s", client_ip)
        channel_id: str | None = None
        role: str | None = None

        try:
            async for raw in ws:
                if isinstance(raw, str):
                    raw = raw.encode()

                if not self._rl.is_allowed(client_ip, channel_id):
                    await ws.send(_pack({"type": "ERROR", "reason": "rate_limited"}))
                    continue

                try:
                    msg = _unpack(raw)
                except Exception:
                    await ws.send(_pack({"type": "ERROR", "reason": "invalid_message"}))
                    continue

                msg_type = msg.get("type")

                if msg_type == "REGISTER":
                    channel_id, role = await self._handle_register(ws, client_ip)

                elif msg_type == "JOIN":
                    result = await self._handle_join(ws, msg, client_ip)
                    if result:
                        channel_id, role = result

                elif msg_type == "RELAY":
                    if channel_id and role:
                        await self._handle_relay(channel_id, role, msg)
                    else:
                        await ws.send(
                            _pack({"type": "ERROR", "reason": "not_in_channel"})
                        )

                elif msg_type == "ABORT":
                    if channel_id:
                        await self._handle_abort(channel_id, role, ws)
                    break

                else:
                    await ws.send(
                        _pack({"type": "ERROR", "reason": "unknown_message_type"})
                    )

        except ConnectionClosed:
            logger.debug("Client %s disconnected", client_ip)
        except Exception:
            logger.exception("Unhandled error in signaling handler for %s", client_ip)
        finally:
            if channel_id and role:
                await self._on_disconnect(channel_id, role, ws)

    # ------------------------------------------------------------------
    # Message handlers
    # ------------------------------------------------------------------

    async def _handle_register(
        self, ws: ServerConnection, client_ip: str
    ) -> tuple[str, str]:
        """Allocate channel; return ``(channel_id, role)``."""
        for _ in range(10):
            cid = _gen_channel_id()
            if not await self._db.channel_exists(cid):
                await self._db.create_channel(cid)
                break
        else:
            await ws.send(
                _pack({"type": "ERROR", "reason": "channel_allocation_failed"})
            )
            raise RuntimeError("Could not allocate channel ID")

        self._channels[cid] = {"sender": ws}
        await ws.send(
            _pack(
                {
                    "type": "REGISTERED",
                    "channel_id": cid,
                    "public_ip": client_ip,
                }
            )
        )
        logger.info("Channel %s created by %s", cid, client_ip)
        return cid, "sender"

    async def _handle_join(
        self,
        ws: ServerConnection,
        msg: dict,
        client_ip: str,
    ) -> tuple[str, str] | None:
        """Connect receiver to existing channel; return ``(channel_id, role)``."""
        code: str = msg.get("code", "")
        if not code:
            await ws.send(_pack({"type": "ERROR", "reason": "missing_code"}))
            return None

        # code format: "<channel_id>-<words>"
        channel_id = code.split("-", 1)[0]

        if not await self._db.channel_exists(channel_id):
            await ws.send(_pack({"type": "ERROR", "reason": "channel_not_found"}))
            return None

        ch = self._channels.get(channel_id, {})
        if "receiver" in ch:
            await ws.send(_pack({"type": "ERROR", "reason": "channel_full"}))
            return None

        if channel_id not in self._channels:
            self._channels[channel_id] = {}
        self._channels[channel_id]["receiver"] = ws

        # Flush any messages queued before receiver arrived
        queued = await self._db.dequeue_messages(channel_id, "sender")

        sender_ws = self._channels[channel_id].get("sender")
        sender_ip = "unknown"
        if sender_ws:
            addr = sender_ws.remote_address
            sender_ip = addr[0] if addr else "unknown"

        await ws.send(
            _pack(
                {
                    "type": "JOINED_OK",
                    "channel_id": channel_id,
                    "public_ip": client_ip,
                    "sender_ip": sender_ip,
                    "queued_messages": queued,
                }
            )
        )

        if sender_ws:
            try:
                await sender_ws.send(
                    _pack({"type": "PEER_CONNECTED", "peer_ip": client_ip})
                )
            except Exception:  # noqa: BLE001
                pass

        logger.info("Channel %s joined by %s", channel_id, client_ip)
        return channel_id, "receiver"

    async def _handle_relay(self, channel_id: str, sender_role: str, msg: dict) -> None:
        """Forward a RELAY message to the peer."""
        data = msg.get("data", b"")
        if not isinstance(data, bytes):
            data = str(data).encode()

        ch = self._channels.get(channel_id, {})
        peer_role = "receiver" if sender_role == "sender" else "sender"
        peer_ws = ch.get(peer_role)

        if peer_ws:
            try:
                await peer_ws.send(_pack({"type": "RELAY", "data": data}))
            except Exception:  # noqa: BLE001
                logger.debug(
                    "Failed to relay to %s in channel %s", peer_role, channel_id
                )
        else:
            await self._db.enqueue_message(channel_id, sender_role, data)

    async def _handle_abort(
        self, channel_id: str, role: str | None, ws: ServerConnection
    ) -> None:
        """Abort a channel and notify the peer."""
        ch = self._channels.get(channel_id, {})
        peer_role = "receiver" if role == "sender" else "sender"
        peer_ws = ch.get(peer_role)
        if peer_ws and peer_ws is not ws:
            try:
                await peer_ws.send(
                    _pack({"type": "PEER_DISCONNECTED", "reason": "abort"})
                )
            except Exception:  # noqa: BLE001
                pass
        await self._db.delete_channel(channel_id)
        self._channels.pop(channel_id, None)

    async def _on_disconnect(
        self, channel_id: str, role: str, ws: ServerConnection
    ) -> None:
        """Clean up after a client disconnects."""
        ch = self._channels.get(channel_id, {})
        if ch.get(role) is ws:
            ch.pop(role, None)

        peer_role = "receiver" if role == "sender" else "sender"
        peer_ws = ch.get(peer_role)
        if peer_ws:
            try:
                await peer_ws.send(
                    _pack(
                        {
                            "type": "PEER_DISCONNECTED",
                            "reason": "connection_lost",
                        }
                    )
                )
            except Exception:  # noqa: BLE001
                pass

        if not ch:
            self._channels.pop(channel_id, None)

    # ------------------------------------------------------------------
    # Background TTL sweep
    # ------------------------------------------------------------------

    async def _sweep_loop(self) -> None:
        """Periodically delete expired channels."""
        while True:
            try:
                await asyncio.sleep(self._sweep_interval)
                await self._db.sweep_expired()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in TTL sweep loop")


# ------------------------------------------------------------------
# Convenience coroutine used by the CLI
# ------------------------------------------------------------------


class _SuppressTrustProbe(logging.Filter):
    """Drop the expected EOF error logged by websockets when ``hermod trust``
    connects via raw TLS to read the certificate and closes immediately.

    The trust command never sends an HTTP request, so websockets logs an
    ERROR with message ``"opening handshake failed"`` whose exception chain
    contains an ``EOFError: connection closed while reading HTTP request
    line``.  This is intentional behaviour, not a fault.

    websockets logs the top-level message as ``"opening handshake failed"``
    and attaches the exception via ``exc_info``.  We must walk the exception
    chain — ``record.getMessage()`` only returns the top-level message and
    would never match the nested ``EOFError`` text.
    """

    _MARKER = "connection closed while reading HTTP request line"

    def filter(self, record: logging.LogRecord) -> bool:
        if record.exc_info:
            exc: BaseException | None = record.exc_info[1]
            while exc is not None:
                if self._MARKER in str(exc):
                    return False
                exc = exc.__cause__ or exc.__context__
        return self._MARKER not in record.getMessage()


async def run_server(
    host: str = "0.0.0.0",
    port: int = 8786,
    db_path: str = ":memory:",
    ttl: int = DEFAULT_TTL,
    ssl_context=None,
) -> None:
    """Start the signaling server and block until cancelled (SIGINT / SIGTERM)."""
    # Suppress the harmless EOF that websockets logs whenever ``hermod trust``
    # opens a raw TLS connection just to inspect the certificate.
    _probe_filter = _SuppressTrustProbe()
    logging.getLogger("websockets.server").addFilter(_probe_filter)

    try:
        async with SignalingDB(path=db_path, ttl=ttl) as db:
            server_obj = SignalingServer(db=db, ttl=ttl)
            srv = await server_obj.start(host=host, port=port, ssl_context=ssl_context)
            try:
                await srv.serve_forever()
            finally:
                srv.close()
                await srv.wait_closed()
                await server_obj.stop()
    finally:
        logging.getLogger("websockets.server").removeFilter(_probe_filter)
