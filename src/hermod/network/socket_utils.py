"""
Socket utility helpers for NAT traversal.

Configures TCP sockets with ``SO_REUSEADDR`` and ``SO_REUSEPORT`` as required
by the blueprint (§18) to allow local port multiplexing between the signaling
WebSocket connection and the P2P data channel.
"""

from __future__ import annotations

import logging
import socket

logger = logging.getLogger(__name__)


def configure_reuse(sock: socket.socket) -> None:
    """Apply ``SO_REUSEADDR`` and (where supported) ``SO_REUSEPORT``.

    Parameters
    ----------
    sock:
        A socket that has **not** yet been bound.
    """
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            logger.debug("SO_REUSEPORT not supported on this platform; skipping")


def create_tcp_socket(*, reuse: bool = True) -> socket.socket:
    """Create an IPv4 TCP socket with optional reuse flags.

    Parameters
    ----------
    reuse:
        Whether to apply ``SO_REUSEADDR`` / ``SO_REUSEPORT``.

    Returns
    -------
    socket.socket
        An unbound, non-blocking TCP socket.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    if reuse:
        configure_reuse(sock)
    return sock


def get_local_addresses() -> list[tuple[str, int]]:
    """Return the machine's non-loopback IPv4 addresses on port 0.

    Used as local ICE candidates. Callers must replace the port ``0`` with
    the actual bound port after :func:`socket.bind`.

    Returns
    -------
    list[tuple[str, int]]
        List of ``(ip, 0)`` tuples for each local interface.
    """
    addrs: list[tuple[str, int]] = []
    try:
        # getaddrinfo with a public DNS server reveals the default outbound IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            addrs.append((s.getsockname()[0], 0))
    except OSError:
        pass

    # Include loopback only when no other address was found.
    # Adding loopback alongside a real interface IP would advertise two
    # candidates that both reach the same 0.0.0.0 listener; the peer would
    # then fire two simultaneous probes, both succeed, and each side could
    # non-deterministically pick a *different* TCP connection (split-connection
    # bug).  Loopback as sole fallback is still useful for offline / pure
    # container environments and in-process unit tests.
    if not addrs:
        addrs.append(("127.0.0.1", 0))

    return addrs
