"""
Transfer code generation and parsing.

A transfer code uniquely identifies a channel and provides the PAKE shared
secret. Format: ``{channel_id}-{word}-{word}-{word}``

Example: ``47392-rapid-blue-fox``

 - ``47392`` → numeric channel ID (server-assigned)
 - ``rapid-blue-fox`` → PAKE passphrase (client-generated, 3 random words)
"""

from __future__ import annotations

import secrets

# ---------------------------------------------------------------------------
# Embedded word list (256 words, BIP-39 style simplicity)
# ---------------------------------------------------------------------------
_WORDS: list[str] = [
    "acid",
    "aged",
    "also",
    "area",
    "army",
    "away",
    "back",
    "ball",
    "band",
    "bank",
    "base",
    "bath",
    "bear",
    "beat",
    "been",
    "bell",
    "best",
    "bird",
    "bite",
    "blue",
    "boat",
    "body",
    "bold",
    "bone",
    "book",
    "bore",
    "born",
    "both",
    "bowl",
    "bulb",
    "burn",
    "cafe",
    "cage",
    "cake",
    "call",
    "calm",
    "came",
    "card",
    "care",
    "cart",
    "case",
    "cave",
    "cell",
    "cent",
    "chip",
    "city",
    "clam",
    "clan",
    "clay",
    "clip",
    "coal",
    "coat",
    "code",
    "coil",
    "coin",
    "cold",
    "come",
    "cook",
    "cool",
    "cope",
    "copy",
    "core",
    "corn",
    "cost",
    "cozy",
    "crab",
    "crew",
    "crop",
    "crow",
    "cube",
    "cure",
    "curl",
    "cute",
    "dare",
    "dark",
    "data",
    "dawn",
    "days",
    "dead",
    "deal",
    "deep",
    "deer",
    "demo",
    "deny",
    "desk",
    "dew",
    "dial",
    "dice",
    "diet",
    "digs",
    "disk",
    "dome",
    "done",
    "door",
    "dove",
    "down",
    "draw",
    "drop",
    "drum",
    "dual",
    "duck",
    "dune",
    "dusk",
    "dust",
    "duty",
    "each",
    "earn",
    "ease",
    "east",
    "edge",
    "else",
    "emit",
    "epic",
    "even",
    "ever",
    "exam",
    "face",
    "fact",
    "fair",
    "fall",
    "fame",
    "farm",
    "fast",
    "fate",
    "fear",
    "feed",
    "feel",
    "feet",
    "fell",
    "felt",
    "fern",
    "file",
    "fill",
    "film",
    "find",
    "fine",
    "fire",
    "firm",
    "fish",
    "fist",
    "fits",
    "five",
    "flag",
    "flat",
    "flew",
    "flip",
    "flow",
    "foam",
    "fold",
    "fond",
    "font",
    "food",
    "fool",
    "fore",
    "fork",
    "form",
    "fort",
    "foul",
    "four",
    "free",
    "from",
    "fuel",
    "full",
    "fund",
    "fuse",
    "gain",
    "game",
    "gave",
    "gaze",
    "gear",
    "germ",
    "gift",
    "gill",
    "give",
    "glad",
    "glow",
    "glue",
    "goat",
    "goes",
    "gold",
    "golf",
    "gone",
    "good",
    "gown",
    "grab",
    "gray",
    "grew",
    "grid",
    "grew",
    "grim",
    "grip",
    "grit",
    "grow",
    "gulf",
    "gust",
    "hack",
    "hall",
    "hand",
    "hang",
    "hard",
    "hare",
    "harm",
    "hash",
    "haze",
    "head",
    "heat",
    "heel",
    "help",
    "herb",
    "here",
    "hide",
    "high",
    "hill",
    "hint",
    "hire",
    "hold",
    "hole",
    "home",
    "hood",
    "hook",
    "hope",
    "hops",
    "horn",
    "host",
    "hour",
    "huge",
    "hull",
    "hump",
    "hunt",
    "hurl",
    "hurt",
    "icon",
    "idle",
    "inch",
    "into",
    "iron",
    "isle",
    "itch",
    "item",
    "jade",
    "join",
    "joke",
    "jump",
    "just",
    "keen",
    "kept",
    "kern",
    "keys",
]

_WORDS_SET: set[str] = set(_WORDS)


def generate_words(n: int = 3) -> str:
    """Return *n* random words joined by hyphens (e.g. ``"rapid-blue-fox"``)."""
    chosen = [secrets.choice(_WORDS) for _ in range(n)]
    return "-".join(chosen)


def build_code(channel_id: str, passphrase: str) -> str:
    """Combine server-assigned *channel_id* with client *passphrase*.

    Parameters
    ----------
    channel_id:
        Numeric string assigned by the signaling server.
    passphrase:
        Hyphen-separated words forming the PAKE secret.

    Returns
    -------
    str
        Full transfer code e.g. ``"47392-rapid-blue-fox"``.
    """
    if not channel_id.isdigit():
        raise ValueError(f"channel_id must be numeric, got {channel_id!r}")
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    return f"{channel_id}-{passphrase}"


def parse_code(code: str) -> tuple[str, str]:
    """Split a transfer code into ``(channel_id, passphrase)``.

    Parameters
    ----------
    code:
        Full transfer code e.g. ``"47392-rapid-blue-fox"``.

    Returns
    -------
    tuple[str, str]
        ``(channel_id, passphrase)``

    Raises
    ------
    ValueError
        If *code* is malformed.
    """
    parts = code.split("-", 1)
    if len(parts) != 2 or not parts[0].isdigit() or not parts[1]:
        raise ValueError(
            f"Invalid transfer code format: {code!r}. "
            "Expected '<channel_id>-<word>[-<word>...]'"
        )
    return parts[0], parts[1]
