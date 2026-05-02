"""
File streaming, chunking, and integrity verification.

Handles:
 - Reading a file in fixed-size chunks (§15)
 - Computing SHA-256 hash of the full plaintext (§16)
 - Output filename collision handling (§19)
 - Resume / partial file management (§26)
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

CHUNK_SIZE = 1 * 1024 * 1024  # 1 MiB
PART_SUFFIX = ".hermod_part"


# ------------------------------------------------------------------
# SHA-256 helpers
# ------------------------------------------------------------------


def hash_file(path: Path) -> str:
    """Return the hex SHA-256 digest of the file at *path*.

    Reads the file in :data:`CHUNK_SIZE` blocks to avoid loading it all
    into memory.
    """
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def hash_bytes(data: bytes) -> str:
    """Return the hex SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------
# Output path utilities
# ------------------------------------------------------------------


def resolve_output_path(destination: Path, filename: str) -> Path:
    """Resolve the final save path, avoiding collisions.

    If *destination* is a directory, the file is placed inside it.
    If the resulting path already exists, a counter suffix is appended
    (e.g. ``document(1).pdf``).

    Parameters
    ----------
    destination:
        Target directory or full file path.
    filename:
        Suggested filename from the sender's metadata.
    """
    if destination.is_dir():
        base = destination / filename
    else:
        base = destination

    if not base.exists():
        return base

    stem = base.stem
    suffix = base.suffix
    parent = base.parent
    counter = 1
    while True:
        candidate = parent / f"{stem}({counter}){suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


# ------------------------------------------------------------------
# Streaming reader / writer
# ------------------------------------------------------------------


class ChunkedFileReader:
    """Reads a file in fixed-size chunks and tracks progress.

    Parameters
    ----------
    path:
        File to read.
    chunk_size:
        Bytes per chunk.
    resume_offset:
        Number of bytes already transferred (for resumption, §26).
    """

    def __init__(
        self,
        path: Path,
        chunk_size: int = CHUNK_SIZE,
        resume_offset: int = 0,
    ) -> None:
        self._path = path
        self._chunk_size = chunk_size
        self._resume_offset = resume_offset
        self._file = None
        self._bytes_sent = 0

    @property
    def file_size(self) -> int:
        """Total size of the source file in bytes."""
        return self._path.stat().st_size

    @property
    def bytes_sent(self) -> int:
        """Number of bytes yielded so far."""
        return self._bytes_sent

    def __enter__(self) -> "ChunkedFileReader":
        self._file = self._path.open("rb")
        if self._resume_offset:
            self._file.seek(self._resume_offset)
            self._bytes_sent = self._resume_offset
        return self

    def __exit__(self, *_: object) -> None:
        if self._file:
            self._file.close()
            self._file = None

    def __iter__(self):
        if self._file is None:
            raise RuntimeError("Must be used as a context manager")
        seq = 0
        while True:
            chunk = self._file.read(self._chunk_size)
            if not chunk:
                break
            self._bytes_sent += len(chunk)
            yield seq, chunk
            seq += 1


class PartFileWriter:
    """Writes received chunks to a ``.hermod_part`` temporary file.

    Parameters
    ----------
    destination:
        Final file path (the ``.hermod_part`` file is created alongside it).
    resume_offset:
        Byte offset to seek to for resumption (§26).
    """

    def __init__(self, destination: Path, resume_offset: int = 0) -> None:
        self._dest = destination
        self._part = destination.with_suffix(PART_SUFFIX)
        self._resume_offset = resume_offset
        self._file = None
        self._digest = hashlib.sha256()
        self._bytes_written = 0

    @property
    def bytes_written(self) -> int:
        """Total bytes written to the part file."""
        return self._bytes_written

    @property
    def part_path(self) -> Path:
        """Path to the temporary part file."""
        return self._part

    def __enter__(self) -> "PartFileWriter":
        mode = "r+b" if self._resume_offset and self._part.exists() else "wb"
        self._file = self._part.open(mode)
        if self._resume_offset:
            self._file.seek(self._resume_offset)
        return self

    def __exit__(self, *_: object) -> None:
        if self._file:
            self._file.close()
            self._file = None

    def write_chunk(self, data: bytes) -> None:
        """Write a plaintext chunk and update the running SHA-256."""
        if self._file is None:
            raise RuntimeError("Must be used as a context manager")
        self._file.write(data)
        self._digest.update(data)
        self._bytes_written += len(data)

    def finalise(self, expected_hash: str) -> Path:
        """Flush, verify SHA-256, rename part file to final path.

        Parameters
        ----------
        expected_hash:
            Hex SHA-256 digest announced in the sender's metadata frame.

        Returns
        -------
        Path
            The final destination path.

        Raises
        ------
        ValueError
            If the computed hash does not match *expected_hash*.
        """
        if self._file:
            self._file.flush()

        actual = self._digest.hexdigest()
        if actual != expected_hash:
            raise ValueError(
                f"File integrity check failed: expected {expected_hash}, got {actual}"
            )

        self._part.rename(self._dest)
        logger.info("File written to %s (%d bytes)", self._dest, self._bytes_written)
        return self._dest

    def discard(self) -> None:
        """Delete the partial file on abort."""
        if self._part.exists():
            self._part.unlink()
            logger.debug("Discarded part file %s", self._part)
