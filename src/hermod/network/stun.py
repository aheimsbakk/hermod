"""
Minimal STUN Binding client (RFC 5389).

Discovers the server-reflexive (srflx) endpoint for a given local port by
querying public STUN servers. The XOR-MAPPED-ADDRESS attribute in the response
reveals what IP:port the NAT assigns to outbound traffic from that local port.

Only IPv4 is supported (sufficient for the current ICE implementation).
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import struct

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# RFC 5389 constants
# ---------------------------------------------------------------------------

_BINDING_REQUEST: int = 0x0001
_BINDING_RESPONSE_SUCCESS: int = 0x0101
_MAGIC_COOKIE: int = 0x2112A442

# Attribute type codes
_ATTR_XOR_MAPPED_ADDRESS: int = 0x0020
_ATTR_MAPPED_ADDRESS: int = 0x0001

# Well-known public STUN servers
DEFAULT_STUN_SERVERS: list[tuple[str, int]] = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 3478),
    ("stun.cloudflare.com", 3478),
]


# ---------------------------------------------------------------------------
# Pure encoding / decoding helpers (testable without network)
# ---------------------------------------------------------------------------


def build_binding_request() -> tuple[bytes, bytes]:
    """Encode a STUN Binding Request.

    Returns
    -------
    tuple[bytes, bytes]
        ``(message_bytes, transaction_id)`` — transaction_id is 12 random bytes.
    """
    txn_id = os.urandom(12)
    # 20-byte header: type(2) + length(2) + magic(4) + txn_id(12)
    msg = struct.pack(">HHI", _BINDING_REQUEST, 0, _MAGIC_COOKIE) + txn_id
    return msg, txn_id


def parse_binding_response(data: bytes, txn_id: bytes) -> tuple[str, int] | None:
    """Parse a STUN Binding Response and extract the server-reflexive address.

    Prefers ``XOR-MAPPED-ADDRESS`` over the legacy ``MAPPED-ADDRESS`` attribute.

    Parameters
    ----------
    data:
        Raw UDP payload received from the STUN server.
    txn_id:
        The 12-byte transaction ID that was sent in the request.

    Returns
    -------
    tuple[str, int] | None
        ``(ip_address, port)`` on success, or ``None`` on any parse error or
        if the response does not match the supplied transaction ID.
    """
    if len(data) < 20:
        return None

    msg_type, msg_len, magic = struct.unpack_from(">HHI", data, 0)
    resp_txn = data[8:20]

    if msg_type != _BINDING_RESPONSE_SUCCESS:
        return None
    if magic != _MAGIC_COOKIE:
        return None
    if resp_txn != txn_id:
        return None

    # Walk attributes; prefer XOR-MAPPED-ADDRESS
    offset = 20
    end = min(20 + msg_len, len(data))
    mapped_fallback: tuple[str, int] | None = None

    while offset + 4 <= end:
        attr_type, attr_len = struct.unpack_from(">HH", data, offset)
        val_start = offset + 4
        val_end = val_start + attr_len
        if val_end > len(data):
            break

        if attr_type == _ATTR_XOR_MAPPED_ADDRESS and attr_len >= 8:
            family = data[val_start + 1]
            if family == 0x01:  # IPv4
                (xport,) = struct.unpack_from(">H", data, val_start + 2)
                (xip,) = struct.unpack_from(">I", data, val_start + 4)
                port = xport ^ (_MAGIC_COOKIE >> 16)
                ip_int = xip ^ _MAGIC_COOKIE
                ip = ".".join(str((ip_int >> (24 - 8 * i)) & 0xFF) for i in range(4))
                return ip, port  # XOR-MAPPED-ADDRESS takes precedence

        elif attr_type == _ATTR_MAPPED_ADDRESS and attr_len >= 8:
            family = data[val_start + 1]
            if family == 0x01:  # IPv4
                (port,) = struct.unpack_from(">H", data, val_start + 2)
                ip_bytes = data[val_start + 4 : val_start + 8]
                mapped_fallback = (".".join(str(b) for b in ip_bytes), port)

        # Attributes are padded to 4-byte boundaries
        offset = val_end + (-attr_len % 4)

    return mapped_fallback


# ---------------------------------------------------------------------------
# Async STUN protocol handler
# ---------------------------------------------------------------------------


class _STUNProtocol(asyncio.DatagramProtocol):
    """One-shot asyncio UDP datagram protocol for a single STUN exchange."""

    def __init__(self, txn_id: bytes, result: "asyncio.Future[bytes | None]") -> None:
        self._txn_id = txn_id
        self._result = result

    def datagram_received(self, data: bytes, addr: tuple) -> None:  # noqa: ARG002
        if not self._result.done():
            self._result.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._result.done():
            self._result.set_exception(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if not self._result.done():
            self._result.set_result(None)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def get_srflx_candidate(
    local_port: int,
    stun_servers: list[tuple[str, int]] | None = None,
    timeout: float = 2.0,
) -> tuple[str, int] | None:
    """Discover the server-reflexive endpoint via STUN.

    Queries all *stun_servers* concurrently and returns the first valid
    ``XOR-MAPPED-ADDRESS``. A UDP socket is bound to *local_port*
    (using ``SO_REUSEPORT``) so the NAT maps the same external port as the
    P2P TCP listener.

    Parameters
    ----------
    local_port:
        The local TCP port the P2P listener is bound to.
    stun_servers:
        Override the default STUN server list.
    timeout:
        Total seconds allowed for all concurrent queries.

    Returns
    -------
    tuple[str, int] | None
        ``(public_ip, public_port)`` on success, or ``None`` on failure.
    """
    servers = stun_servers or DEFAULT_STUN_SERVERS
    loop = asyncio.get_running_loop()

    async def _query_one(stun_host: str, stun_port: int) -> tuple[str, int] | None:
        transport = None
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(
                    stun_host,
                    stun_port,
                    type=socket.SOCK_DGRAM,
                    proto=socket.IPPROTO_UDP,
                ),
                timeout=timeout,
            )
            if not infos:
                return None
            stun_addr = infos[0][4]

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError:
                    pass
            sock.setblocking(False)
            try:
                sock.bind(("", local_port))
            except OSError:
                sock.bind(("", 0))

            fut: asyncio.Future[bytes | None] = loop.create_future()
            request, txn_id = build_binding_request()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _STUNProtocol(txn_id, fut),
                sock=sock,
            )
            transport.sendto(request, stun_addr)

            raw = await asyncio.wait_for(asyncio.shield(fut), timeout=timeout)
            if raw is None:
                return None
            return parse_binding_response(raw, txn_id)

        except Exception as exc:
            logger.debug("STUN %s:%d → %s", stun_host, stun_port, exc)
            return None
        finally:
            if transport is not None:
                try:
                    transport.close()
                except Exception:  # noqa: BLE001
                    pass

    tasks = [asyncio.create_task(_query_one(h, p)) for h, p in servers]
    result: tuple[str, int] | None = None

    try:
        pending: set[asyncio.Task] = set(tasks)
        deadline = loop.time() + timeout

        while pending:
            time_left = deadline - loop.time()
            if time_left <= 0:
                break
            done, pending = await asyncio.wait(
                pending,
                timeout=time_left,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for t in done:
                try:
                    r = t.result()
                except Exception:
                    continue
                if r is not None:
                    result = r
                    logger.debug("STUN srflx candidate: %s:%d", r[0], r[1])
                    break
            if result is not None:
                break
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    return result
