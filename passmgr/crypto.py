"""Low-level crypto wrappers.

This is the only module that touches the `cryptography` and `argon2` packages,
so the rest of the code never handles primitives directly.
"""

import os
import unicodedata

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32  # AES-256
IV_LEN = 12  # 96-bit GCM nonce
SALT_LEN = 16
TAG_LEN = 16

GENERIC_AUTH_ERROR = "Authentication failed or corrupted vault."


class AuthFailure(Exception):
    """Wrong password, tampered data or malformed file.

    Deliberately one exception with one message, so callers cannot leak
    *why* unlocking failed (threat A5).
    """


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def zeroize(buf) -> None:
    """Best-effort wipe. Only works on mutable buffers (bytearray)."""
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def derive_kek(password: str, salt: bytes, time_cost: int, memory_cost: int,
               parallelism: int) -> bytearray:
    """Argon2id(password, salt) -> 32-byte Key Encryption Key."""
    pw = unicodedata.normalize("NFKC", password).encode("utf-8")
    raw = hash_secret_raw(
        secret=pw,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,  # KiB
        parallelism=parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )
    return bytearray(raw)


def encrypt(key, plaintext: bytes, aad: bytes):
    """AES-256-GCM with a fresh random IV. Returns (iv, ciphertext||tag)."""
    iv = random_bytes(IV_LEN)
    ct = AESGCM(bytes(key)).encrypt(iv, plaintext, aad)
    return iv, ct


def decrypt(key, iv: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM decrypt. Raises AuthFailure if the tag does not verify."""
    try:
        return AESGCM(bytes(key)).decrypt(iv, ciphertext, aad)
    except (InvalidTag, ValueError):
        raise AuthFailure(GENERIC_AUTH_ERROR) from None
