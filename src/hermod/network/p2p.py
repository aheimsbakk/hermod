"""
P2P connection management.

Manages the direct TCP connection between sender and receiver after the
signaling exchange is complete. Implements:
 - PeerListener: bind first to get port, then wait for connection
 - connect_to_peer: receiver-side multi-candidate connector
 - Graceful shutdown dispatching PROTOCOL_ABORT
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from hermod.network.wire import FrameType, read_frame, write_frame

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 15.0  # seconds per candidate
_ACCEPT_TIMEOUT = 60.0


@dataclass
class Endpoint:
    """A network endpoint candidate for P2P connection."""

    host: str
    port: int

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class P2PConnection:
    """Holds an established asyncio TCP stream pair."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    local_endpoint: Endpoint
    remote_endpoint: Endpoint

    async def send_frame(self, header: dict, payload: bytes = b"") -> None:
        """Send a single wire frame."""
        await write_frame(self.writer, header, payload)

    async def recv_frame(self) -> tuple[dict, bytes]:
        """Receive a single wire frame."""
        return await read_frame(self.reader)

    async def close(self) -> None:
        """Send ABORT and close the connection."""
        try:
            await write_frame(
                self.writer,
                {"type": FrameType.ABORT, "reason": "normal_close"},
            )
        except Exception:  # noqa: BLE001
            pass
        finally:
            self.writer.close()
            try:
                await asyncio.wait_for(self.writer.wait_closed(), timeout=2.0)
            except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                pass


class PeerListener:
    """Two-phase TCP listener: bind first to get port, then accept.

    Usage::

        listener = PeerListener(host="0.0.0.0")
        endpoint = await listener.bind()          # returns bound Endpoint
        # ... advertise endpoint via signaling ...
        conn = await listener.accept(timeout=30)  # waits for peer
        await listener.close()
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 0) -> None:
        self._host = host
        self._port = port
        self._server: asyncio.Server | None = None
        self._connected = asyncio.Event()
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._endpoint: Endpoint | None = None

    async def bind(self) -> Endpoint:
        """Start the TCP listener; return the bound :class:`Endpoint`."""

        async def _handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            if not self._connected.is_set():
                self._reader = r
                self._writer = w
                self._connected.set()

        self._server = await asyncio.start_server(
            _handler,
            host=self._host,
            port=self._port,
            backlog=5,
            reuse_address=True,
            reuse_port=True,
        )
        bound = self._server.sockets[0].getsockname()
        self._endpoint = Endpoint(host=bound[0], port=bound[1])
        logger.debug("P2P listener bound to %s", self._endpoint)
        return self._endpoint

    async def accept(self, timeout: float = _ACCEPT_TIMEOUT) -> P2PConnection:
        """Wait until a peer connects; return a :class:`P2PConnection`.

        Raises
        ------
        ConnectionError
            If no peer connects within *timeout* seconds.
        """
        try:
            await asyncio.wait_for(self._connected.wait(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise ConnectionError(
                f"Timed out waiting for P2P connection on {self._endpoint}"
            ) from exc

        assert self._reader and self._writer and self._endpoint
        remote_addr = self._writer.get_extra_info("peername")
        remote = Endpoint(host=remote_addr[0], port=remote_addr[1])
        logger.debug("Peer connected from %s", remote)
        return P2PConnection(
            reader=self._reader,
            writer=self._writer,
            local_endpoint=self._endpoint,
            remote_endpoint=remote,
        )

    async def close(self) -> None:
        """Stop the listener server."""
        if self._server:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=2.0)
            except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                pass
            self._server = None


async def connect_to_peer(
    candidates: list[Endpoint],
    *,
    timeout: float = _CONNECT_TIMEOUT,
) -> P2PConnection:
    """Attempt TCP connection to each candidate in order.

    Returns the first successful :class:`P2PConnection`.

    Raises
    ------
    ConnectionError
        If all candidates fail.
    """
    last_exc: Exception | None = None
    for ep in candidates:
        try:
            logger.debug("Trying P2P candidate %s", ep)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ep.host, ep.port),
                timeout=timeout,
            )
            local_addr = writer.get_extra_info("sockname")
            local = Endpoint(host=local_addr[0], port=local_addr[1])
            logger.debug("P2P connected to %s (local %s)", ep, local)
            return P2PConnection(
                reader=reader,
                writer=writer,
                local_endpoint=local,
                remote_endpoint=ep,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            logger.debug("Candidate %s failed: %s", ep, exc)
            last_exc = exc

    raise ConnectionError(
        f"Could not connect to any of {[str(c) for c in candidates]}"
    ) from last_exc
