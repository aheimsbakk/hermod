"""
Hermod — Secure P2P file and text transfer.

Public library API. Third-party integrators should import from here
rather than from internal sub-packages.
"""

from hermod.core.config import HermodConfig, load_config, save_config
from hermod.core.session import ReceiverSession, SenderSession, TransferResult
from hermod.core.streaming import (
    ChunkedFileReader,
    PartFileWriter,
    hash_bytes,
    hash_file,
    resolve_output_path,
)
from hermod.core.transfer_code import build_code, generate_words, parse_code
from hermod.core.trust import TrustStore

__all__ = [
    "HermodConfig",
    "load_config",
    "save_config",
    "ReceiverSession",
    "SenderSession",
    "TransferResult",
    "ChunkedFileReader",
    "PartFileWriter",
    "hash_bytes",
    "hash_file",
    "resolve_output_path",
    "build_code",
    "generate_words",
    "parse_code",
    "TrustStore",
]
