"""
Transfer code unit tests: generate_words, build_code, parse_code.
"""

from __future__ import annotations

import pytest

from hermod.core.transfer_code import _WORDS, build_code, generate_words, parse_code


class TestGenerateWords:
    def test_default_three_words(self) -> None:
        result = generate_words(3)
        parts = result.split("-")
        assert len(parts) == 3

    def test_all_words_in_wordlist(self) -> None:
        for _ in range(20):
            result = generate_words(3)
            for word in result.split("-"):
                assert word in _WORDS

    def test_single_word(self) -> None:
        result = generate_words(1)
        assert "-" not in result
        assert result in _WORDS

    def test_five_words(self) -> None:
        result = generate_words(5)
        assert len(result.split("-")) == 5


class TestBuildCode:
    def test_basic(self) -> None:
        code = build_code("12345", "rapid-blue-fox")
        assert code == "12345-rapid-blue-fox"

    def test_non_numeric_channel_raises(self) -> None:
        with pytest.raises(ValueError):
            build_code("abc", "rapid-blue-fox")

    def test_empty_passphrase_raises(self) -> None:
        with pytest.raises(ValueError):
            build_code("12345", "")


class TestParseCode:
    def test_basic(self) -> None:
        cid, passphrase = parse_code("12345-rapid-blue-fox")
        assert cid == "12345"
        assert passphrase == "rapid-blue-fox"

    def test_roundtrip_with_build(self) -> None:
        code = build_code("99999", "one-two-three")
        cid, phrase = parse_code(code)
        assert cid == "99999"
        assert phrase == "one-two-three"

    def test_missing_separator_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_code("1234512345")

    def test_non_numeric_prefix_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_code("abc-word-word")

    def test_empty_passphrase_part_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_code("12345-")

    def test_single_word_code_parses(self) -> None:
        # Single-word passphrases are technically valid (belt-and-suspenders)
        cid, phrase = parse_code("10000-word")
        assert cid == "10000"
        assert phrase == "word"
