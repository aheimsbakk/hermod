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
        # Return same ip as loopback host candidate
        with patch(
            "hermod.network.stun.get_srflx_candidate",
            new=AsyncMock(return_value=("127.0.0.1", ep.port)),
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
