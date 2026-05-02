"""
Cryptographic unit tests: AEADCipher, KDF, KEM, PAKE.
"""

from __future__ import annotations

import os

import pytest

from hermod.crypto.aead import AEADCipher
from hermod.crypto.kdf import derive_sas, derive_session_key
from hermod.crypto.kem import X25519KEMFallback, get_kem
from hermod.crypto.pake import SPAKE2Adapter


# ---------------------------------------------------------------------------
# AEADCipher
# ---------------------------------------------------------------------------


class TestAEADCipher:
    def test_encrypt_decrypt_roundtrip(self) -> None:
        key = os.urandom(32)
        cipher = AEADCipher(key)
        plaintext = b"hello world"
        ct = cipher.encrypt(plaintext)
        assert cipher.decrypt(ct) == plaintext

    def test_nonce_is_prepended(self) -> None:
        key = os.urandom(32)
        cipher = AEADCipher(key)
        ct = cipher.encrypt(b"data")
        # First 12 bytes are nonce, rest is ciphertext+tag (>= 16 bytes)
        assert len(ct) == 12 + len(b"data") + 16

    def test_two_encryptions_differ(self) -> None:
        key = os.urandom(32)
        cipher = AEADCipher(key)
        ct1 = cipher.encrypt(b"same")
        ct2 = cipher.encrypt(b"same")
        # Different nonces → different ciphertexts
        assert ct1 != ct2

    def test_wrong_key_raises(self) -> None:
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        ct = AEADCipher(key1).encrypt(b"secret")
        with pytest.raises(Exception):
            AEADCipher(key2).decrypt(ct)

    def test_bad_key_length_raises(self) -> None:
        with pytest.raises(ValueError):
            AEADCipher(b"tooshort")

    def test_truncated_ciphertext_raises(self) -> None:
        key = os.urandom(32)
        cipher = AEADCipher(key)
        with pytest.raises(ValueError):
            cipher.decrypt(b"\x00" * 5)

    def test_aad_authenticated(self) -> None:
        key = os.urandom(32)
        cipher = AEADCipher(key)
        ct = cipher.encrypt(b"data", aad=b"header")
        assert cipher.decrypt(ct, aad=b"header") == b"data"
        with pytest.raises(Exception):
            cipher.decrypt(ct, aad=b"wrong-header")

    def test_empty_plaintext(self) -> None:
        key = os.urandom(32)
        cipher = AEADCipher(key)
        assert cipher.decrypt(cipher.encrypt(b"")) == b""


# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------


class TestKDF:
    def _make_inputs(self):
        k_c = os.urandom(32)
        k_pq = os.urandom(32)
        salt = os.urandom(32)
        return k_c, k_pq, salt

    def test_derive_session_key_length(self) -> None:
        k_c, k_pq, salt = self._make_inputs()
        key = derive_session_key(k_c, k_pq, salt)
        assert len(key) == 32

    def test_derive_session_key_deterministic(self) -> None:
        k_c, k_pq, salt = self._make_inputs()
        assert derive_session_key(k_c, k_pq, salt) == derive_session_key(
            k_c, k_pq, salt
        )

    def test_derive_session_key_different_salt(self) -> None:
        k_c, k_pq, _ = self._make_inputs()
        key1 = derive_session_key(k_c, k_pq, os.urandom(32))
        key2 = derive_session_key(k_c, k_pq, os.urandom(32))
        assert key1 != key2

    def test_derive_sas_format(self) -> None:
        key = os.urandom(32)
        sas = derive_sas(key)
        assert len(sas) == 6
        assert sas == sas.upper()
        int(sas, 16)  # must be valid hex

    def test_derive_sas_deterministic(self) -> None:
        key = os.urandom(32)
        assert derive_sas(key) == derive_sas(key)

    def test_derive_sas_wrong_length(self) -> None:
        with pytest.raises(ValueError):
            derive_sas(b"tooshort")

    def test_empty_classical_key_raises(self) -> None:
        with pytest.raises(ValueError):
            derive_session_key(b"", os.urandom(32), os.urandom(32))

    def test_empty_pq_key_raises(self) -> None:
        with pytest.raises(ValueError):
            derive_session_key(os.urandom(32), b"", os.urandom(32))

    def test_empty_salt_raises(self) -> None:
        with pytest.raises(ValueError):
            derive_session_key(os.urandom(32), os.urandom(32), b"")


# ---------------------------------------------------------------------------
# KEM (X25519 fallback — no liboqs C lib in CI)
# ---------------------------------------------------------------------------


class TestX25519KEMFallback:
    def test_roundtrip(self) -> None:
        sender = X25519KEMFallback()
        receiver = X25519KEMFallback()
        # sender generates a keypair; receiver encapsulates against it
        pk = sender.generate_keypair()
        ct, k_recv = receiver.encapsulate(pk)
        k_send = sender.decapsulate(ct)
        assert k_send == k_recv

    def test_shared_secrets_are_32_bytes(self) -> None:
        kem = X25519KEMFallback()
        pk = kem.generate_keypair()
        ct, k = X25519KEMFallback().encapsulate(pk)
        assert len(k) == 32

    def test_different_instances_differ(self) -> None:
        a = X25519KEMFallback()
        b = X25519KEMFallback()
        pk_a = a.generate_keypair()
        _, k1 = b.encapsulate(pk_a)
        _, k2 = b.encapsulate(pk_a)
        # Two encapsulations with different ephemeral keys → different secrets
        assert k1 != k2

    def test_get_kem_returns_kem_engine(self) -> None:
        kem = get_kem()
        pk = kem.generate_keypair()
        ct, k_enc = kem.encapsulate(pk)
        k_dec = kem.decapsulate(ct)
        assert k_enc == k_dec


# ---------------------------------------------------------------------------
# PAKE (SPAKE2)
# ---------------------------------------------------------------------------


class TestSPAKE2Adapter:
    def _run_pake(self, password: bytes) -> tuple[bytes, bytes]:
        """Simulate a full SPAKE2 exchange; return (k_a, k_b)."""
        pake_a = SPAKE2Adapter(password, is_sender=True)
        pake_b = SPAKE2Adapter(password, is_sender=False)
        msg_a = pake_a.start()
        msg_b = pake_b.start()
        k_a = pake_a.finish(msg_b)
        k_b = pake_b.finish(msg_a)
        return k_a, k_b

    def test_shared_secret_matches(self) -> None:
        k_a, k_b = self._run_pake(b"correct-horse-battery")
        assert k_a == k_b

    def test_wrong_password_differs(self) -> None:
        pake_a = SPAKE2Adapter(b"password-a", is_sender=True)
        pake_b = SPAKE2Adapter(b"password-b", is_sender=False)
        msg_a = pake_a.start()
        msg_b = pake_b.start()
        k_a = pake_a.finish(msg_b)
        k_b = pake_b.finish(msg_a)
        assert k_a != k_b

    def test_output_is_bytes(self) -> None:
        k_a, _ = self._run_pake(b"test")
        assert isinstance(k_a, bytes)

    def test_output_non_empty(self) -> None:
        k_a, _ = self._run_pake(b"test")
        assert len(k_a) > 0
