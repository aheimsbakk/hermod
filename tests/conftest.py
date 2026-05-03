"""
Shared pytest fixtures for the Hermod test suite.
"""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from hermod.server.db import SignalingDB


@pytest.fixture
def tmp_path_session(tmp_path: Path) -> Path:
    """Alias: a fresh temporary directory for each test."""
    return tmp_path


@pytest.fixture
async def in_memory_db() -> SignalingDB:
    """An open in-memory SignalingDB for server tests."""
    db = SignalingDB(path=":memory:")
    await db.__aenter__()
    yield db
    await db.__aexit__(None, None, None)


@pytest.fixture
def small_file(tmp_path: Path) -> Path:
    """A 4 KiB file of repeating bytes."""
    p = tmp_path / "sample.bin"
    p.write_bytes(b"A" * 4096)
    return p


@pytest.fixture
def medium_file(tmp_path: Path) -> Path:
    """A 3 MiB file (crosses chunk boundary)."""
    p = tmp_path / "medium.bin"
    p.write_bytes(b"B" * (3 * 1024 * 1024))
    return p


# ---------------------------------------------------------------------------
# Session-scoped TLS fixtures
# ---------------------------------------------------------------------------
# A single self-signed cert is generated once per pytest session (RSA-2048 for
# speed) and reused by all session integration tests that need WSS.


@pytest.fixture(scope="session")
def tls_cert_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Generate a self-signed test certificate once for the entire test session."""
    from hermod.server.tls import generate_self_signed

    cert_dir = tmp_path_factory.mktemp("tls")
    generate_self_signed(
        cert_dir / "server.crt",
        cert_dir / "server.key",
        hostname="127.0.0.1",
        key_size=2048,  # RSA-2048 is fast enough for tests
    )
    return cert_dir


@pytest.fixture(scope="session")
def server_ssl_ctx(tls_cert_dir: Path) -> ssl.SSLContext:
    """SSL context for the test signaling server."""
    from hermod.server.tls import get_server_ssl_context

    return get_server_ssl_context(
        tls_cert_dir / "server.crt",
        tls_cert_dir / "server.key",
    )


@pytest.fixture(scope="session")
def client_ssl_ctx(tls_cert_dir: Path) -> ssl.SSLContext:
    """Pinned SSL context that trusts only the test server certificate."""
    from hermod.server.tls import get_client_ssl_context

    return get_client_ssl_context(tls_cert_dir / "server.crt")
