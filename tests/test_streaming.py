"""
Streaming unit tests: hash helpers, resolve_output_path, ChunkedFileReader, PartFileWriter.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from hermod.core.streaming import (
    CHUNK_SIZE,
    ChunkedFileReader,
    PartFileWriter,
    hash_bytes,
    hash_file,
    resolve_output_path,
)


class TestHashHelpers:
    def test_hash_file_matches_hashlib(self, tmp_path: Path) -> None:
        data = b"the quick brown fox" * 500
        f = tmp_path / "data.bin"
        f.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        assert hash_file(f) == expected

    def test_hash_bytes(self) -> None:
        data = b"hello"
        assert hash_bytes(data) == hashlib.sha256(data).hexdigest()

    def test_hash_file_empty(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        assert hash_file(f) == hashlib.sha256(b"").hexdigest()

    def test_hash_bytes_deterministic(self) -> None:
        d = b"test-data-123"
        assert hash_bytes(d) == hash_bytes(d)


class TestResolveOutputPath:
    def test_directory_destination(self, tmp_path: Path) -> None:
        result = resolve_output_path(tmp_path, "file.txt")
        assert result == tmp_path / "file.txt"

    def test_no_collision(self, tmp_path: Path) -> None:
        result = resolve_output_path(tmp_path, "new.txt")
        assert not result.exists()

    def test_collision_appends_counter(self, tmp_path: Path) -> None:
        (tmp_path / "doc.pdf").write_bytes(b"x")
        result = resolve_output_path(tmp_path, "doc.pdf")
        assert result == tmp_path / "doc(1).pdf"

    def test_multiple_collisions(self, tmp_path: Path) -> None:
        (tmp_path / "doc.pdf").write_bytes(b"x")
        (tmp_path / "doc(1).pdf").write_bytes(b"x")
        result = resolve_output_path(tmp_path, "doc.pdf")
        assert result == tmp_path / "doc(2).pdf"

    def test_explicit_file_destination(self, tmp_path: Path) -> None:
        dest = tmp_path / "out.txt"
        result = resolve_output_path(dest, "ignored.txt")
        assert result == dest


class TestChunkedFileReader:
    def test_reads_all_bytes(self, tmp_path: Path) -> None:
        data = b"X" * 5000
        f = tmp_path / "f.bin"
        f.write_bytes(data)
        collected = bytearray()
        with ChunkedFileReader(f) as reader:
            for _, chunk in reader:
                collected.extend(chunk)
        assert bytes(collected) == data

    def test_chunk_count_large_file(self, tmp_path: Path) -> None:
        data = b"Y" * (CHUNK_SIZE * 3 + 1)
        f = tmp_path / "big.bin"
        f.write_bytes(data)
        chunks = []
        with ChunkedFileReader(f) as reader:
            for seq, chunk in reader:
                chunks.append((seq, len(chunk)))
        assert len(chunks) == 4  # 3 full + 1 remainder
        assert chunks[-1][0] == 3  # zero-indexed

    def test_sequence_numbers_increment(self, tmp_path: Path) -> None:
        f = tmp_path / "s.bin"
        f.write_bytes(b"A" * (CHUNK_SIZE * 2))
        seqs = []
        with ChunkedFileReader(f) as reader:
            for seq, _ in reader:
                seqs.append(seq)
        assert seqs == [0, 1]

    def test_context_manager_required(self, tmp_path: Path) -> None:
        f = tmp_path / "x.bin"
        f.write_bytes(b"abc")
        reader = ChunkedFileReader(f)
        with pytest.raises(RuntimeError):
            list(reader)

    def test_file_size_property(self, tmp_path: Path) -> None:
        data = b"Z" * 1234
        f = tmp_path / "z.bin"
        f.write_bytes(data)
        with ChunkedFileReader(f) as reader:
            assert reader.file_size == 1234


class TestPartFileWriter:
    def _write_and_finalise(self, tmp_path: Path, data: bytes) -> Path:
        dest = tmp_path / "output.bin"
        expected_hash = hashlib.sha256(data).hexdigest()
        with PartFileWriter(dest) as w:
            w.write_chunk(data)
            final = w.finalise(expected_hash)
        return final

    def test_creates_final_file(self, tmp_path: Path) -> None:
        data = b"hello world"
        final = self._write_and_finalise(tmp_path, data)
        assert final.exists()
        assert final.read_bytes() == data

    def test_part_file_removed_after_finalise(self, tmp_path: Path) -> None:
        dest = tmp_path / "out.bin"
        part = dest.with_suffix(".hermod_part")
        with PartFileWriter(dest) as w:
            w.write_chunk(b"data")
            w.finalise(hashlib.sha256(b"data").hexdigest())
        assert not part.exists()

    def test_hash_mismatch_raises(self, tmp_path: Path) -> None:
        dest = tmp_path / "bad.bin"
        with pytest.raises(ValueError, match="integrity"):
            with PartFileWriter(dest) as w:
                w.write_chunk(b"data")
                w.finalise("0" * 64)  # wrong hash

    def test_discard_removes_part_file(self, tmp_path: Path) -> None:
        dest = tmp_path / "disc.bin"
        part = dest.with_suffix(".hermod_part")
        with PartFileWriter(dest) as w:
            w.write_chunk(b"partial")
            w.discard()
        assert not part.exists()

    def test_context_manager_required(self, tmp_path: Path) -> None:
        dest = tmp_path / "x.bin"
        w = PartFileWriter(dest)
        with pytest.raises(RuntimeError):
            w.write_chunk(b"data")

    def test_bytes_written_property(self, tmp_path: Path) -> None:
        dest = tmp_path / "bw.bin"
        data = b"A" * 512
        with PartFileWriter(dest) as w:
            w.write_chunk(data)
            assert w.bytes_written == 512
