"""
Signaling server SQLite database layer.

Manages channel lifecycle and queued signaling messages. Acts as an ephemeral
blind relay — the database stores only opaque blobs, never inspecting payload
content (§7 zero-knowledge properties).

Schema
------
channels(id, created_at)
messages(id, channel_id, role, data, created_at)

All timestamps are UNIX epoch integers (seconds).
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import aiosqlite

logger = logging.getLogger(__name__)

# Default TTL matches the CLI default (3600 s = 1 hour)
DEFAULT_TTL = 3600
# Hard limit on signaling messages per channel (DDoS protection §8)
MAX_MESSAGES_PER_CHANNEL = 8
# Hard limit on signaling message size in bytes (§8)
MAX_MESSAGE_SIZE = 4096

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS channels (
    id          TEXT    PRIMARY KEY,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id  TEXT    NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    role        TEXT    NOT NULL,
    data        BLOB    NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id, created_at);
"""


class SignalingDB:
    """Async SQLite store for the signaling server.

    Parameters
    ----------
    path:
        Filesystem path to the SQLite database file. Pass ``":memory:"`` for
        an in-process ephemeral database (useful in tests).
    ttl:
        Channel time-to-live in seconds.
    """

    def __init__(self, path: str | Path = ":memory:", ttl: int = DEFAULT_TTL) -> None:
        self._path = str(path)
        self._ttl = ttl
        self._db: aiosqlite.Connection | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def open(self) -> None:
        """Open the database and run DDL migrations."""
        if self._db is not None:
            return
        db = await aiosqlite.connect(self._path)
        self._db = db
        await db.executescript(_DDL)
        await db.commit()
        logger.debug("SignalingDB opened at %s", self._path)

    async def close(self) -> None:
        """Flush WAL and close the database connection."""
        if self._db is None:
            return
        try:
            await self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            await self._db.commit()
        except Exception:  # noqa: BLE001
            pass
        finally:
            await self._db.close()
            self._db = None
            logger.debug("SignalingDB closed")

    # ------------------------------------------------------------------
    # Channel operations
    # ------------------------------------------------------------------

    async def create_channel(self, channel_id: str) -> None:
        """Insert a new channel row.

        Raises
        ------
        ValueError
            If *channel_id* is already registered.
        """
        assert self._db, "DB not open"
        now = int(time.time())
        try:
            await self._db.execute(
                "INSERT INTO channels (id, created_at) VALUES (?, ?)",
                (channel_id, now),
            )
            await self._db.commit()
        except aiosqlite.IntegrityError as exc:
            raise ValueError(f"Channel '{channel_id}' already exists") from exc

    async def channel_exists(self, channel_id: str) -> bool:
        """Return ``True`` if the channel exists and has not expired."""
        assert self._db, "DB not open"
        threshold = int(time.time()) - self._ttl
        async with self._db.execute(
            "SELECT 1 FROM channels WHERE id = ? AND created_at > ?",
            (channel_id, threshold),
        ) as cur:
            return await cur.fetchone() is not None

    async def delete_channel(self, channel_id: str) -> None:
        """Delete channel and cascade-delete its messages."""
        assert self._db, "DB not open"
        await self._db.execute("DELETE FROM channels WHERE id = ?", (channel_id,))
        await self._db.commit()

    # ------------------------------------------------------------------
    # Message operations
    # ------------------------------------------------------------------

    async def enqueue_message(self, channel_id: str, role: str, data: bytes) -> bool:
        """Store a signaling message for later delivery.

        Returns ``False`` and discards the message if the per-channel message
        count limit has been reached (anti-spam, §8).

        Parameters
        ----------
        channel_id:
            Target channel.
        role:
            ``"sender"`` or ``"receiver"``.
        data:
            Opaque binary blob (≤ MAX_MESSAGE_SIZE bytes).
        """
        assert self._db, "DB not open"
        if len(data) > MAX_MESSAGE_SIZE:
            logger.warning("Message from %s exceeds size limit; dropping", role)
            return False

        async with self._db.execute(
            "SELECT COUNT(*) FROM messages WHERE channel_id = ?", (channel_id,)
        ) as cur:
            row = await cur.fetchone()
            count = row[0] if row else 0

        if count >= MAX_MESSAGES_PER_CHANNEL:
            logger.warning(
                "Channel %s exceeded message limit (%d); dropping",
                channel_id,
                MAX_MESSAGES_PER_CHANNEL,
            )
            return False

        now = int(time.time())
        await self._db.execute(
            "INSERT INTO messages (channel_id, role, data, created_at) VALUES (?,?,?,?)",
            (channel_id, role, data, now),
        )
        await self._db.commit()
        return True

    async def dequeue_messages(self, channel_id: str, role: str) -> list[bytes]:
        """Fetch and delete all stored messages for *role* in *channel_id*.

        Returns
        -------
        list[bytes]
            Messages in insertion order.
        """
        assert self._db, "DB not open"
        async with self._db.execute(
            "SELECT id, data FROM messages "
            "WHERE channel_id = ? AND role = ? ORDER BY id",
            (channel_id, role),
        ) as cur:
            rows = await cur.fetchall()

        if rows:
            ids = [r[0] for r in rows]
            placeholders = ",".join("?" * len(ids))
            await self._db.execute(
                f"DELETE FROM messages WHERE id IN ({placeholders})", ids
            )
            await self._db.commit()

        return [r[1] for r in rows]

    # ------------------------------------------------------------------
    # TTL sweep
    # ------------------------------------------------------------------

    async def sweep_expired(self) -> int:
        """Delete all channels older than the configured TTL.

        Returns
        -------
        int
            Number of channels removed.
        """
        assert self._db, "DB not open"
        threshold = int(time.time()) - self._ttl
        cursor = await self._db.execute(
            "DELETE FROM channels WHERE created_at <= ?", (threshold,)
        )
        await self._db.commit()
        removed = cursor.rowcount
        if removed:
            logger.info("TTL sweep removed %d expired channel(s)", removed)
        return removed

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "SignalingDB":
        await self.open()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()
