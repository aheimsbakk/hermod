"""
Tests for hermod.network.ice.

Covers:
- IceCandidate dataclass: serialisation and priority ordering
- gather_candidates: host-only (stun_timeout=0), STUN injected via mock
- ice_connect: inbound-accept path and outbound-probe path
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from hermod.network.ice import (
    IceCandidate,
    _probe_candidate,
    gather_candidates,
    ice_connect,
)
from hermod.network.p2p import PeerListener


# ---------------------------------------------------------------------------
# IceCandidate dataclass
# ---------------------------------------------------------------------------


class TestIceCandidate:
    def test_host_priority(self) -> None:
        c = IceCandidate(ip="192.168.1.1", port=5000, candidate_type="host")
        assert c.priority == 100

    def test_srflx_priority(self) -> None:
        c = IceCandidate(ip="1.2.3.4", port=5000, candidate_type="srflx")
        assert c.priority == 200

    def test_host_sorts_before_srflx(self) -> None:
        host = IceCandidate(ip="192.168.1.1", port=5000, candidate_type="host")
        srflx = IceCandidate(ip="1.2.3.4", port=5000, candidate_type="srflx")
        assert sorted([srflx, host], key=lambda c: c.priority) == [host, srflx]

    def test_to_dict_round_trip(self) -> None:
        c = IceCandidate(ip="10.0.0.1", port=1234, candidate_type="srflx")
        d = c.to_dict()
        assert d == {"type": "srflx", "ip": "10.0.0.1", "port": 1234}
        restored = IceCandidate.from_dict(d)
        assert restored.ip == c.ip
        assert restored.port == c.port
        assert restored.candidate_type == c.candidate_type

    def test_from_dict_defaults_to_host(self) -> None:
        c = IceCandidate.from_dict({"ip": "127.0.0.1", "port": 9999})
        assert c.candidate_type == "host"

    def test_to_endpoint(self) -> None:
        c = IceCandidate(ip="10.0.0.1", port=7777)
        ep = c.to_endpoint()
        assert ep.host == "10.0.0.1"
        assert ep.port == 7777


# ---------------------------------------------------------------------------
# gather_candidates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gather_candidates_host_only(tmp_path) -> None:
    """With stun_timeout=0 only host candidates are returned."""
    listener = PeerListener(host="127.0.0.1", port=0)
    endpoint = await listener.bind()
    try:
        candidates = await gather_candidates(listener, stun_timeout=0.0)
        assert len(candidates) >= 1
        for c in candidates:
            assert c.candidate_type == "host"
            assert c.port == endpoint.port
    finally:
        await listener.close()


@pytest.mark.asyncio
async def test_gather_candidates_srflx_appended_when_stun_succeeds(tmp_path) -> None:
    """When STUN returns a new address it is appended as srflx."""
    listener = PeerListener(host="127.0.0.1", port=0)
    await listener.bind()
    try:
        with patch(
            "hermod.network.stun.get_srflx_candidate",
            new=AsyncMock(return_value=("203.0.113.5", 44300)),
        ):
            candidates = await gather_candidates(listener, stun_timeout=1.0)

        types = [c.candidate_type for c in candidates]
        assert "srflx" in types
        srflx = next(c for c in candidates if c.candidate_type == "srflx")
        assert srflx.ip == "203.0.113.5"
        assert srflx.port == 44300
    finally:
        await listener.close()


@pytest.mark.asyncio
async def test_gather_candidates_srflx_not_duplicated_when_same_as_host(
    tmp_path,
) -> None:
    """If STUN returns the same ip:port as an existing host candidate, skip it."""
    listener = PeerListener(host="127.0.0.1", port=0)
    ep = await listener.bind()
    try:
        # Pin get_local_addresses to loopback only so the host candidate is
        # 127.0.0.1; STUN is then mocked to return that same IP, verifying
        # that the deduplication logic drops the srflx entry.
        with (
            patch(
                "hermod.network.ice.get_local_addresses",
                return_value=[("127.0.0.1", 0)],
            ),
            patch(
                "hermod.network.stun.get_srflx_candidate",
                new=AsyncMock(return_value=("127.0.0.1", ep.port)),
            ),
        ):
            candidates = await gather_candidates(listener, stun_timeout=1.0)

        types = [c.candidate_type for c in candidates]
        assert "srflx" not in types
    finally:
        await listener.close()


@pytest.mark.asyncio
async def test_gather_candidates_stun_failure_is_non_fatal(tmp_path) -> None:
    """A STUN exception must not propagate; host candidates are still returned."""
    listener = PeerListener(host="127.0.0.1", port=0)
    await listener.bind()
    try:
        with patch(
            "hermod.network.stun.get_srflx_candidate",
            new=AsyncMock(side_effect=OSError("network unreachable")),
        ):
            candidates = await gather_candidates(listener, stun_timeout=1.0)

        assert len(candidates) >= 1
        assert all(c.candidate_type == "host" for c in candidates)
    finally:
        await listener.close()


@pytest.mark.asyncio
async def test_gather_requires_bound_listener() -> None:
    listener = PeerListener(host="127.0.0.1", port=0)
    with pytest.raises(RuntimeError, match="bound"):
        await gather_candidates(listener, stun_timeout=0.0)


# ---------------------------------------------------------------------------
# ice_connect
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ice_connect_via_inbound_accept() -> None:
    """Sender's listener accepts the receiver's outbound probe."""
    sender_listener = PeerListener(host="127.0.0.1", port=0)
    sender_ep = await sender_listener.bind()

    receiver_listener = PeerListener(host="127.0.0.1", port=0)
    await receiver_listener.bind()

    # Receiver knows sender's loopback candidate
    sender_candidate = IceCandidate(
        ip="127.0.0.1", port=sender_ep.port, candidate_type="host"
    )
    # Sender knows no usable receiver candidates (port=0 → will fail probe)
    bogus_candidate = IceCandidate(ip="127.0.0.1", port=1, candidate_type="host")

    try:
        sender_task = asyncio.create_task(
            ice_connect(sender_listener, [bogus_candidate], total_timeout=5.0)
        )
        receiver_task = asyncio.create_task(
            ice_connect(receiver_listener, [sender_candidate], total_timeout=5.0)
        )

        sender_conn, receiver_conn = await asyncio.gather(sender_task, receiver_task)

        assert sender_conn is not None
        assert receiver_conn is not None
    finally:
        await sender_listener.close()
        await receiver_listener.close()


@pytest.mark.asyncio
async def test_ice_connect_raises_on_no_candidates() -> None:
    listener = PeerListener(host="127.0.0.1", port=0)
    await listener.bind()
    try:
        with pytest.raises(ConnectionError):
            await ice_connect(listener, [], total_timeout=1.0)
    finally:
        await listener.close()


@pytest.mark.asyncio
async def test_ice_connect_raises_on_all_failed_candidates() -> None:
    """All probes fail and accept times out → ConnectionError."""
    listener = PeerListener(host="127.0.0.1", port=0)
    await listener.bind()
    try:
        bad = IceCandidate(ip="127.0.0.1", port=1, candidate_type="host")
        with pytest.raises(ConnectionError):
            await ice_connect(listener, [bad], probe_timeout=0.2, total_timeout=0.5)
    finally:
        await listener.close()


@pytest.mark.asyncio
async def test_probe_candidate_returns_none_on_refused() -> None:
    """_probe_candidate must return None (not raise) on connection refused."""
    c = IceCandidate(ip="127.0.0.1", port=1, candidate_type="host")
    result = await _probe_candidate(c, timeout=1.0)
    assert result is None


@pytest.mark.asyncio
async def test_probe_candidate_respects_delay() -> None:
    """A non-zero delay parameter must be honoured before attempting connect."""
    import time

    c = IceCandidate(ip="127.0.0.1", port=1, candidate_type="host")
    start = time.monotonic()
    result = await _probe_candidate(c, timeout=1.0, delay=0.15)
    elapsed = time.monotonic() - start

    assert result is None  # port 1 refused
    assert elapsed >= 0.14, f"delay not respected: {elapsed:.3f}s"


@pytest.mark.asyncio
async def test_ice_connect_controlled_probe_delay_agrees_on_same_connection() -> None:
    """Both peers must use the *same* TCP connection when controlled uses probe_delay.

    Without probe_delay both outbound probes and both inbound accepts can
    complete within the same event-loop iteration.  set-iteration is
    non-deterministic so each side might pick a different TCP socket, causing
    all subsequent communication to silently fail.

    With probe_delay=0.1 on the controlled role the controlling side's probe
    arrives at the controlled listener first.  The controlled peer's
    accept_task fires before its own probes start, guaranteeing both sides
    select the same connection.
    """
    # Controlling side (sender role)
    ctrl_listener = PeerListener(host="127.0.0.1", port=0)
    ctrl_ep = await ctrl_listener.bind()

    # Controlled side (receiver role)
    ctrd_listener = PeerListener(host="127.0.0.1", port=0)
    ctrd_ep = await ctrd_listener.bind()

    ctrl_candidate = IceCandidate(
        ip="127.0.0.1", port=ctrl_ep.port, candidate_type="host"
    )
    ctrd_candidate = IceCandidate(
        ip="127.0.0.1", port=ctrd_ep.port, candidate_type="host"
    )

    try:
        # Controlling fires probes immediately; controlled delays by 100 ms.
        ctrl_task = asyncio.create_task(
            ice_connect(
                ctrl_listener, [ctrd_candidate], probe_delay=0.0, total_timeout=5.0
            )
        )
        ctrd_task = asyncio.create_task(
            ice_connect(
                ctrd_listener, [ctrl_candidate], probe_delay=0.1, total_timeout=5.0
            )
        )
        ctrl_conn, ctrd_conn = await asyncio.gather(ctrl_task, ctrd_task)

        # Both sides must be on the SAME TCP connection:
        # - ctrl_conn: outbound probe → remote is ctrd's listener port
        # - ctrd_conn: inbound accept → remote is ctrl's ephemeral port
        assert ctrl_conn.remote_endpoint.port == ctrd_ep.port, (
            "controlling side must have connected to controlled listener port"
        )
        assert ctrd_conn.remote_endpoint.port == ctrl_conn.local_endpoint.port, (
            "controlled side must see controlling side's ephemeral port as remote"
        )
    finally:
        await ctrl_listener.close()
        await ctrd_listener.close()
