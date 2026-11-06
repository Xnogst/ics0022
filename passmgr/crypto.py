import os
import unicodedata

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32
IV_LEN = 12
SALT_LEN = 16
TAG_LEN = 16

GENERIC_AUTH_ERROR = "Authentication failed or corrupted vault."


class AuthFailure(Exception):


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def zeroize(buf) -> None:
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def derive_kek(password: str, salt: bytes, time_cost: int, memory_cost: int,
               parallelism: int) -> bytearray:
    pw = unicodedata.normalize("NFKC", password).encode("utf-8")
    raw = hash_secret_raw(
        secret=pw,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )
    return bytearray(raw)


def encrypt(key, plaintext: bytes, aad: bytes):
    iv = random_bytes(IV_LEN)
    ct = AESGCM(bytes(key)).encrypt(iv, plaintext, aad)
    return iv, ct


def decrypt(key, iv: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(bytes(key)).decrypt(iv, ciphertext, aad)
    except (InvalidTag, ValueError):
        raise AuthFailure(GENERIC_AUTH_ERROR) from None
