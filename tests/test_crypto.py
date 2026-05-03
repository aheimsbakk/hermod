"""
Cryptographic unit tests: AEADCipher, KDF, KEM, PAKE, MAC, SecretStream.
"""

from __future__ import annotations

import os

import pytest

from hermod.crypto.aead import AEADCipher
from hermod.crypto.ecdh import EphemeralX25519
from hermod.crypto.kdf import derive_resume_key, derive_sas, derive_session_key
from hermod.crypto.kem import MLKEM768KyberPy, X25519KEMFallback, get_kem
from hermod.crypto.mac import compute_mac, verify_mac
from hermod.crypto.pake import SPAKE2Adapter
from hermod.crypto.stream import (
    STREAM_HEADER_SIZE,
    STREAM_KEY_SIZE,
    SecretStreamPull,
    SecretStreamPush,
)


# ---------------------------------------------------------------------------
# AEADCipher — XChaCha20-Poly1305
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
        # First 24 bytes are nonce (XChaCha20 uses 192-bit nonce), rest is ciphertext+tag
        assert len(ct) == 24 + len(b"data") + 16

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
        k_e = os.urandom(32)
        k_pq = os.urandom(32)
        salt = os.urandom(32)
        return k_c, k_e, k_pq, salt

    def test_derive_session_key_length(self) -> None:
        k_c, k_e, k_pq, salt = self._make_inputs()
        key = derive_session_key(k_c, k_e, k_pq, salt)
        assert len(key) == 32

    def test_derive_session_key_deterministic(self) -> None:
        k_c, k_e, k_pq, salt = self._make_inputs()
        assert derive_session_key(k_c, k_e, k_pq, salt) == derive_session_key(
            k_c, k_e, k_pq, salt
        )

    def test_derive_session_key_different_salt(self) -> None:
        k_c, k_e, k_pq, _ = self._make_inputs()
        key1 = derive_session_key(k_c, k_e, k_pq, os.urandom(32))
        key2 = derive_session_key(k_c, k_e, k_pq, os.urandom(32))
        assert key1 != key2

    def test_derive_session_key_all_secrets_contribute(self) -> None:
        """Changing any single secret must change the derived key."""
        k_c, k_e, k_pq, salt = self._make_inputs()
        base = derive_session_key(k_c, k_e, k_pq, salt)
        assert derive_session_key(os.urandom(32), k_e, k_pq, salt) != base
        assert derive_session_key(k_c, os.urandom(32), k_pq, salt) != base
        assert derive_session_key(k_c, k_e, os.urandom(32), salt) != base

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
            derive_session_key(b"", os.urandom(32), os.urandom(32), os.urandom(32))

    def test_empty_ecdh_key_raises(self) -> None:
        with pytest.raises(ValueError):
            derive_session_key(os.urandom(32), b"", os.urandom(32), os.urandom(32))

    def test_empty_pq_key_raises(self) -> None:
        with pytest.raises(ValueError):
            derive_session_key(os.urandom(32), os.urandom(32), b"", os.urandom(32))

    def test_empty_salt_raises(self) -> None:
        with pytest.raises(ValueError):
            derive_session_key(os.urandom(32), os.urandom(32), os.urandom(32), b"")


# ---------------------------------------------------------------------------
# KDF — derive_resume_key (Appendix B §2)
# ---------------------------------------------------------------------------


class TestDeriveResumeKey:
    def test_output_is_32_bytes(self) -> None:
        session_key = os.urandom(32)
        rk = derive_resume_key(session_key, 0)
        assert len(rk) == 32

    def test_different_from_session_key(self) -> None:
        session_key = os.urandom(32)
        assert derive_resume_key(session_key, 0) != session_key

    def test_counter_changes_key(self) -> None:
        session_key = os.urandom(32)
        k0 = derive_resume_key(session_key, 0)
        k1 = derive_resume_key(session_key, 1)
        assert k0 != k1

    def test_deterministic(self) -> None:
        session_key = os.urandom(32)
        assert derive_resume_key(session_key, 3) == derive_resume_key(session_key, 3)

    def test_different_session_keys_produce_different_resume_keys(self) -> None:
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        assert derive_resume_key(k1, 0) != derive_resume_key(k2, 0)

    def test_wrong_key_length_raises(self) -> None:
        with pytest.raises(ValueError):
            derive_resume_key(b"tooshort", 0)

    def test_negative_counter_raises(self) -> None:
        with pytest.raises(ValueError):
            derive_resume_key(os.urandom(32), -1)


# ---------------------------------------------------------------------------
# Ephemeral X25519 ECDH
# ---------------------------------------------------------------------------


class TestEphemeralX25519:
    def test_roundtrip_shared_secret_matches(self) -> None:
        a = EphemeralX25519()
        b = EphemeralX25519()
        k_a = a.exchange(b.public_key_bytes())
        k_b = b.exchange(a.public_key_bytes())
        assert k_a == k_b

    def test_shared_secret_is_32_bytes(self) -> None:
        a = EphemeralX25519()
        b = EphemeralX25519()
        k = a.exchange(b.public_key_bytes())
        assert len(k) == 32

    def test_public_key_is_32_bytes(self) -> None:
        assert len(EphemeralX25519().public_key_bytes()) == 32

    def test_different_pairs_produce_different_secrets(self) -> None:
        a1, b1 = EphemeralX25519(), EphemeralX25519()
        a2, b2 = EphemeralX25519(), EphemeralX25519()
        assert a1.exchange(b1.public_key_bytes()) != a2.exchange(b2.public_key_bytes())

    def test_exchange_twice_raises(self) -> None:
        a = EphemeralX25519()
        b = EphemeralX25519()
        a.exchange(b.public_key_bytes())
        with pytest.raises(RuntimeError, match="once"):
            a.exchange(b.public_key_bytes())

    def test_wrong_key_length_raises(self) -> None:
        a = EphemeralX25519()
        with pytest.raises(ValueError, match="32 bytes"):
            a.exchange(b"\x00" * 16)


# ---------------------------------------------------------------------------
# KEM — kyber-py ML-KEM-768 backend
# ---------------------------------------------------------------------------


class TestMLKEM768KyberPy:
    def test_roundtrip(self) -> None:
        receiver = MLKEM768KyberPy()
        pk = receiver.generate_keypair()
        ct, k_enc = MLKEM768KyberPy().encapsulate(pk)
        k_dec = receiver.decapsulate(ct)
        assert k_enc == k_dec

    def test_shared_secret_is_32_bytes(self) -> None:
        receiver = MLKEM768KyberPy()
        pk = receiver.generate_keypair()
        _, k = MLKEM768KyberPy().encapsulate(pk)
        assert len(k) == 32

    def test_encapsulation_key_is_1184_bytes(self) -> None:
        pk = MLKEM768KyberPy().generate_keypair()
        assert len(pk) == 1184

    def test_ciphertext_is_1088_bytes(self) -> None:
        receiver = MLKEM768KyberPy()
        pk = receiver.generate_keypair()
        ct, _ = MLKEM768KyberPy().encapsulate(pk)
        assert len(ct) == 1088

    def test_two_encapsulations_produce_different_secrets(self) -> None:
        receiver = MLKEM768KyberPy()
        pk = receiver.generate_keypair()
        _, k1 = MLKEM768KyberPy().encapsulate(pk)
        _, k2 = MLKEM768KyberPy().encapsulate(pk)
        assert k1 != k2

    def test_wrong_ciphertext_produces_wrong_secret(self) -> None:
        receiver = MLKEM768KyberPy()
        pk = receiver.generate_keypair()
        ct, k_enc = MLKEM768KyberPy().encapsulate(pk)
        # Corrupt a byte in the ciphertext
        bad_ct = bytes([ct[0] ^ 0xFF]) + ct[1:]
        k_bad = receiver.decapsulate(bad_ct)
        assert k_bad != k_enc


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
        # kyber-py is installed, so get_kem() must prefer it over X25519
        assert isinstance(kem, MLKEM768KyberPy)
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


# ---------------------------------------------------------------------------
# MAC — HMAC-SHA256 key binding (Appendix B §1)
# ---------------------------------------------------------------------------


class TestMAC:
    def test_compute_mac_returns_32_bytes(self) -> None:
        key = os.urandom(32)
        tag = compute_mac(key, b"some data")
        assert len(tag) == 32

    def test_verify_mac_passes_on_correct_tag(self) -> None:
        key = os.urandom(32)
        data = b"pk_kem_bytes" + b"pk_ecdh_bytes"
        tag = compute_mac(key, data)
        verify_mac(key, data, tag)  # should not raise

    def test_verify_mac_fails_on_tampered_data(self) -> None:
        key = os.urandom(32)
        data = b"original data"
        tag = compute_mac(key, data)
        with pytest.raises(ValueError, match="tampered"):
            verify_mac(key, b"modified data", tag)

    def test_verify_mac_fails_on_wrong_key(self) -> None:
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        data = b"some data"
        tag = compute_mac(key1, data)
        with pytest.raises(ValueError):
            verify_mac(key2, data, tag)

    def test_verify_mac_fails_on_wrong_tag_length(self) -> None:
        key = os.urandom(32)
        data = b"some data"
        with pytest.raises(ValueError, match="32 bytes"):
            verify_mac(key, data, b"\x00" * 16)

    def test_compute_mac_empty_key_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            compute_mac(b"", b"data")

    def test_verify_mac_empty_key_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            verify_mac(b"", b"data", b"\x00" * 32)

    def test_different_data_produces_different_tag(self) -> None:
        key = os.urandom(32)
        assert compute_mac(key, b"data-a") != compute_mac(key, b"data-b")

    def test_different_keys_produce_different_tag(self) -> None:
        data = b"same data"
        assert compute_mac(os.urandom(32), data) != compute_mac(os.urandom(32), data)

    def test_mac_is_deterministic(self) -> None:
        key = os.urandom(32)
        data = b"deterministic"
        assert compute_mac(key, data) == compute_mac(key, data)


# ---------------------------------------------------------------------------
# SecretStream — push/pull (Appendix B §3)
# ---------------------------------------------------------------------------


class TestSecretStream:
    def test_constants(self) -> None:
        assert STREAM_HEADER_SIZE == 24
        assert STREAM_KEY_SIZE == 32

    def test_header_is_24_bytes(self) -> None:
        key = os.urandom(32)
        push = SecretStreamPush(key)
        assert len(push.header) == 24

    def test_single_chunk_roundtrip(self) -> None:
        key = os.urandom(32)
        push = SecretStreamPush(key)
        pull = SecretStreamPull(key, push.header)

        plaintext = b"hello secret stream"
        ct = push.push(plaintext, is_final=True)
        recovered, is_final = pull.pull(ct)

        assert recovered == plaintext
        assert is_final is True

    def test_multi_chunk_roundtrip(self) -> None:
        key = os.urandom(32)
        push = SecretStreamPush(key)
        pull = SecretStreamPull(key, push.header)

        chunks = [b"chunk-one", b"chunk-two", b"chunk-three"]
        cts = [
            push.push(c, is_final=(i == len(chunks) - 1)) for i, c in enumerate(chunks)
        ]

        for i, ct in enumerate(cts):
            pt, is_final = pull.pull(ct)
            assert pt == chunks[i]
            assert is_final == (i == len(chunks) - 1)

    def test_non_final_tag_is_false(self) -> None:
        key = os.urandom(32)
        push = SecretStreamPush(key)
        pull = SecretStreamPull(key, push.header)

        ct = push.push(b"middle chunk", is_final=False)
        _, is_final = pull.pull(ct)
        assert is_final is False

    def test_ciphertext_larger_than_plaintext(self) -> None:
        """SecretStream adds a 17-byte ABYTES overhead per message."""
        key = os.urandom(32)
        push = SecretStreamPush(key)
        plaintext = b"x" * 100
        ct = push.push(plaintext)
        assert len(ct) == len(plaintext) + 17

    def test_wrong_key_raises(self) -> None:
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        push = SecretStreamPush(key1)
        pull = SecretStreamPull(key2, push.header)
        ct = push.push(b"secret")
        with pytest.raises(Exception):
            pull.pull(ct)

    def test_wrong_header_raises(self) -> None:
        key = os.urandom(32)
        push = SecretStreamPush(key)
        bad_header = os.urandom(24)
        pull = SecretStreamPull(key, bad_header)
        ct = push.push(b"data")
        with pytest.raises(Exception):
            pull.pull(ct)

    def test_bad_key_length_raises(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            SecretStreamPush(b"tooshort")

    def test_bad_header_length_raises(self) -> None:
        key = os.urandom(32)
        with pytest.raises(ValueError, match="24 bytes"):
            SecretStreamPull(key, b"\x00" * 10)

    def test_empty_plaintext(self) -> None:
        key = os.urandom(32)
        push = SecretStreamPush(key)
        pull = SecretStreamPull(key, push.header)
        ct = push.push(b"", is_final=True)
        pt, is_final = pull.pull(ct)
        assert pt == b""
        assert is_final is True

    def test_large_payload_roundtrip(self) -> None:
        """1 MiB payload must survive a multi-chunk SecretStream transfer."""
        key = os.urandom(32)
        push = SecretStreamPush(key)
        pull = SecretStreamPull(key, push.header)

        chunk_size = 256 * 1024  # 256 KiB
        data = os.urandom(1 * 1024 * 1024)
        chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]

        recovered_parts = []
        for i, chunk in enumerate(chunks):
            is_final = i == len(chunks) - 1
            ct = push.push(chunk, is_final=is_final)
            pt, _ = pull.pull(ct)
            recovered_parts.append(pt)

        assert b"".join(recovered_parts) == data
