"""
Hermod Crypto package.

Exports the primary cryptographic building blocks used throughout Hermod.
"""

from hermod.crypto.aead import AEADCipher
from hermod.crypto.kdf import derive_resume_key, derive_sas, derive_session_key
from hermod.crypto.kem import KEMEngine, get_kem
from hermod.crypto.mac import compute_mac, verify_mac
from hermod.crypto.pake import PAKEEngine, SPAKE2Adapter
from hermod.crypto.stream import SecretStreamPull, SecretStreamPush

__all__ = [
    "AEADCipher",
    "compute_mac",
    "verify_mac",
    "derive_session_key",
    "derive_resume_key",
    "derive_sas",
    "KEMEngine",
    "get_kem",
    "PAKEEngine",
    "SPAKE2Adapter",
    "SecretStreamPush",
    "SecretStreamPull",
]
