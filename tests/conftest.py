"""
Shared pytest fixtures for the Hermod test suite.
"""

from __future__ import annotations

import asyncio
import tempfile
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
