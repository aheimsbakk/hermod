"""
Lightweight ICE-inspired candidate gathering and connectivity.

This module implements a simplified version of RFC 8445 Interactive
Connectivity Establishment (ICE) sufficient for direct peer-to-peer TCP
connections through common NATs:

- ``gather_candidates``: collect host candidates from local interfaces and,
  optionally, a server-reflexive (srflx) candidate via STUN.
- ``ice_connect``: race an inbound accept against outbound TCP probes to all
  peer candidates; return the first successful ``P2PConnection``.

Only IPv4 / TCP is supported.  UDP hole-punching is out of scope.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from hermod.network.p2p import Endpoint, P2PConnection, PeerListener
from hermod.network.socket_utils import get_local_addresses

logger = logging.getLogger(__name__)

_PROBE_TIMEOUT = 5.0  # seconds per outbound candidate probe
_ICE_TOTAL_TIMEOUT = 30.0  # total seconds for ice_connect


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class IceCandidate:
    """A single IP:port candidate for P2P connectivity.

    Attributes
    ----------
    ip:
        IPv4 address string.
    port:
        TCP port number.
    candidate_type:
        ``"host"`` for local-interface candidates;
        ``"srflx"`` for server-reflexive (STUN-discovered) candidates.
    priority:
        Lower value = higher preference.  host < srflx in typical LAN scenarios
        but we prefer host first for speed.
    """

    ip: str
    port: int
    candidate_type: str = "host"
    priority: int = field(init=False)

    def __post_init__(self) -> None:
        # Prefer host candidates; srflx useful when behind symmetric NAT
        self.priority = 100 if self.candidate_type == "host" else 200

    def to_endpoint(self) -> Endpoint:
        """Convert to a plain :class:`~hermod.network.p2p.Endpoint`."""
        return Endpoint(host=self.ip, port=self.port)

    def to_dict(self) -> dict[str, str | int]:
        """Serialisable dict for signaling exchange."""
        return {"type": self.candidate_type, "ip": self.ip, "port": self.port}

    @classmethod
    def from_dict(cls, d: dict) -> "IceCandidate":
        """Reconstruct from a signaling dict."""
        return cls(
            ip=str(d["ip"]),
            port=int(d["port"]),
            candidate_type=str(d.get("type", "host")),
        )


# ---------------------------------------------------------------------------
# Candidate gathering
# ---------------------------------------------------------------------------


async def gather_candidates(
    listener: PeerListener,
    *,
    stun_timeout: float = 2.0,
) -> list[IceCandidate]:
    """Gather ICE candidates for *listener*.

    The listener must already be bound (``await listener.bind()`` called).
    Returns candidates sorted by :attr:`IceCandidate.priority` (ascending).

    Parameters
    ----------
    listener:
        A bound ``PeerListener``; supplies the local port for all candidates.
    stun_timeout:
        Seconds to wait for STUN responses.  Pass ``0.0`` to skip STUN
        entirely (useful in unit tests and offline environments).

    Returns
    -------
    list[IceCandidate]
        At least one host candidate; srflx appended if STUN succeeds.
    """
    if listener._endpoint is None:  # noqa: SLF001
        raise RuntimeError("PeerListener must be bound before gathering candidates")

    bound_port: int = listener._endpoint.port  # noqa: SLF001
    candidates: list[IceCandidate] = []

    # Host candidates – one per local interface
    for ip, _ in get_local_addresses():
        candidates.append(IceCandidate(ip=ip, port=bound_port, candidate_type="host"))
        logger.debug("ICE host candidate: %s:%d", ip, bound_port)

    if not candidates:
        # Absolute fallback: loopback
        candidates.append(
            IceCandidate(ip="127.0.0.1", port=bound_port, candidate_type="host")
        )

    # Server-reflexive candidate via STUN
    if stun_timeout > 0.0:
        try:
            from hermod.network.stun import get_srflx_candidate

            srflx = await get_srflx_candidate(
                local_port=bound_port,
                timeout=stun_timeout,
            )
            if srflx is not None:
                srflx_ip, srflx_port = srflx
                # Only add if it differs from all existing host candidates
                if not any(
                    c.ip == srflx_ip and c.port == srflx_port for c in candidates
                ):
                    candidates.append(
                        IceCandidate(
                            ip=srflx_ip,
                            port=srflx_port,
                            candidate_type="srflx",
                        )
                    )
                    logger.debug("ICE srflx candidate: %s:%d", srflx_ip, srflx_port)
        except Exception as exc:  # noqa: BLE001
            logger.debug("STUN gather failed (non-fatal): %s", exc)

    candidates.sort(key=lambda c: c.priority)
    return candidates


# ---------------------------------------------------------------------------
# ICE connectivity
# ---------------------------------------------------------------------------


async def _probe_candidate(
    candidate: IceCandidate,
    timeout: float,
    *,
    delay: float = 0.0,
) -> P2PConnection | None:
    """Try a single outbound TCP connection to *candidate*.

    Parameters
    ----------
    delay:
        Optional seconds to sleep before attempting the connection.  Use this
        on the ICE *controlled* role to let the controlling side's probe arrive
        first so both peers agree on the same TCP connection.

    Returns a :class:`P2PConnection` on success, or ``None`` on any error.
    """
    if delay > 0.0:
        await asyncio.sleep(delay)
    ep = candidate.to_endpoint()
    try:
        logger.debug("ICE probe → %s (%s)", ep, candidate.candidate_type)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ep.host, ep.port),
            timeout=timeout,
        )
        local_addr = writer.get_extra_info("sockname")
        local = Endpoint(host=local_addr[0], port=local_addr[1])
        logger.debug("ICE probe succeeded: local=%s remote=%s", local, ep)
        return P2PConnection(
            reader=reader,
            writer=writer,
            local_endpoint=local,
            remote_endpoint=ep,
        )
    except (OSError, asyncio.TimeoutError) as exc:
        logger.debug("ICE probe %s failed: %s", ep, exc)
        return None


async def ice_connect(
    listener: PeerListener,
    peer_candidates: list[IceCandidate],
    *,
    probe_timeout: float = _PROBE_TIMEOUT,
    total_timeout: float = _ICE_TOTAL_TIMEOUT,
    probe_delay: float = 0.0,
) -> P2PConnection:
    """Race inbound accept against outbound probes to *peer_candidates*.

    Either side may reach the other first.  This function returns whichever
    TCP connection is established first, then cancels all remaining tasks.

    Parameters
    ----------
    listener:
        A bound ``PeerListener`` already waiting for an inbound connection.
    peer_candidates:
        ICE candidates received from the remote peer, sorted by priority.
    probe_timeout:
        Per-probe TCP connect timeout.
    total_timeout:
        Maximum total time before raising ``ConnectionError``.
    probe_delay:
        Seconds to wait before firing each outbound probe.  Set this to a
        small positive value (e.g. ``0.1``) on the ICE *controlled* role so
        the controlling peer's inbound probe arrives first.  Both sides then
        agree on the same TCP connection, preventing the split-connection
        failure that occurs when probes from both sides complete
        simultaneously and each peer picks its own outbound socket.

    Returns
    -------
    P2PConnection
        The first successfully established connection.

    Raises
    ------
    ConnectionError
        If no connection is established within *total_timeout* seconds.
    """
    if not peer_candidates:
        raise ConnectionError("No peer ICE candidates provided")

    loop = asyncio.get_running_loop()

    # Sort by priority to probe host candidates first
    sorted_candidates = sorted(peer_candidates, key=lambda c: c.priority)

    # Outbound probe tasks (one per peer candidate)
    probe_tasks: list[asyncio.Task[P2PConnection | None]] = [
        asyncio.create_task(
            _probe_candidate(c, probe_timeout, delay=probe_delay),
            name=f"ice-probe-{c.ip}:{c.port}",
        )
        for c in sorted_candidates
    ]

    # Inbound accept task
    accept_task: asyncio.Task[P2PConnection] = asyncio.create_task(
        listener.accept(timeout=total_timeout), name="ice-accept"
    )

    all_tasks: list[asyncio.Task] = [accept_task, *probe_tasks]
    result: P2PConnection | None = None

    try:
        deadline = loop.time() + total_timeout
        pending: set[asyncio.Task] = set(all_tasks)

        while pending:
            time_left = deadline - loop.time()
            if time_left <= 0:
                break
            done, pending = await asyncio.wait(
                pending,
                timeout=time_left,
                return_when=asyncio.FIRST_COMPLETED,
            )
            # Iterate in *insertion* order (accept_task first, then probes by
            # priority) rather than over the raw ``done`` set whose iteration
            # order is non-deterministic.  When multiple tasks finish in the
            # same event-loop tick — e.g. two simultaneous probes on a host
            # with multiple IPs — this guarantees both peers choose the same
            # TCP connection: the receiver prefers its accept (the first
            # inbound connection stored by _handler) and the sender prefers
            # the probe to the highest-priority candidate (which is also the
            # first probe task created, i.e. the one most likely to have
            # arrived at the receiver's accept queue first).
            for t in all_tasks:
                if t not in done:
                    continue
                try:
                    val = t.result()
                except Exception as exc:
                    logger.debug("ICE task %s raised: %s", t.get_name(), exc)
                    continue
                if val is not None:
                    result = val
                    logger.debug(
                        "ICE connected via %s: %s → %s",
                        t.get_name(),
                        val.local_endpoint,
                        val.remote_endpoint,
                    )
                    break
            if result is not None:
                break

    finally:
        # Cancel every task that did not produce the winning connection
        for t in all_tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*all_tasks, return_exceptions=True)

    if result is None:
        raise ConnectionError(
            f"ICE connectivity failed: no connection established within "
            f"{total_timeout:.1f}s to candidates "
            f"{[str(c.to_endpoint()) for c in peer_candidates]}"
        )

    return result
