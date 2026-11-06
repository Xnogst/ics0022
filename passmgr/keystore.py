"""Keystore: Argon2id KEK derivation and wrapping/unwrapping of the Master Key.

    master password --Argon2id(salt)--> KEK --AES-256-GCM--> wraps random Master Key (MK)

The MK encrypts the vault. Changing the master password only re-wraps the MK.
"""

import base64
import binascii
import json

from . import crypto
from .crypto import AuthFailure

FORMAT_VERSION = 1
DEFAULT_KDF = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}  # memory in KiB
MIN_KDF = {"time_cost": 2, "memory_cost": 19456, "parallelism": 1}  # 19 MiB
MAX_KDF = {"time_cost": 10, "memory_cost": 1048576, "parallelism": 16}  # 1 GiB (anti-DoS)

MIN_PASSWORD_LEN = 12


class PasswordPolicyError(Exception):
    pass


def check_password_policy(password: str) -> None:
    """Minimum length 12 plus at least 3 of 4 character classes."""
    if len(password) < MIN_PASSWORD_LEN:
        raise PasswordPolicyError(f"Master password must be at least {MIN_PASSWORD_LEN} characters.")
    classes = [
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ]
    if sum(classes) < 3:
        raise PasswordPolicyError(
            "Master password needs at least 3 of: lowercase, uppercase, digits, symbols."
        )


def validate_kdf(params) -> dict:
    """Enforce min AND max bounds on KDF parameters read from disk (threat A3)."""
    if not isinstance(params, dict) or set(params) != set(DEFAULT_KDF):
        raise ValueError("bad kdf params")
    for key, value in params.items():
        if type(value) is not int or not (MIN_KDF[key] <= value <= MAX_KDF[key]):
            raise ValueError("kdf param out of range")
    return {k: params[k] for k in DEFAULT_KDF}


def _aad(version: int, salt: bytes, kdf: dict) -> bytes:
    """Version, salt and KDF params are bound to the wrapped key as AAD."""
    kdf_json = json.dumps(kdf, sort_keys=True, separators=(",", ":")).encode()
    return b"PMKS" + bytes([version]) + salt + kdf_json


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value, length: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError("not a string")
    raw = base64.b64decode(value, validate=True)
    if len(raw) != length:
        raise ValueError("wrong length")
    return raw


def _wrap(password: str, mk: bytes, kdf: dict) -> dict:
    salt = crypto.random_bytes(crypto.SALT_LEN)
    kek = crypto.derive_kek(password, salt, **kdf)
    try:
        iv, wrapped = crypto.encrypt(kek, bytes(mk), _aad(FORMAT_VERSION, salt, kdf))
    finally:
        crypto.zeroize(kek)
    return {
        "version": FORMAT_VERSION,
        "salt": _b64(salt),
        "kdf_params": dict(kdf),
        "kek_iv": _b64(iv),
        "wrapped_mk": _b64(wrapped),
    }


def create(password: str, kdf: dict = None):
    """Create a new keystore. Returns (keystore_dict, mk)."""
    kdf = validate_kdf(kdf or DEFAULT_KDF)
    mk = bytearray(crypto.random_bytes(crypto.KEY_LEN))
    return _wrap(password, mk, kdf), mk


def unlock(keystore: dict, password: str) -> bytearray:
    """Derive the KEK and unwrap the MK. Any failure raises the same AuthFailure."""
    try:
        if keystore["version"] != FORMAT_VERSION:
            raise ValueError("version")
        salt = _unb64(keystore["salt"], crypto.SALT_LEN)
        iv = _unb64(keystore["kek_iv"], crypto.IV_LEN)
        wrapped = _unb64(keystore["wrapped_mk"], crypto.KEY_LEN + crypto.TAG_LEN)
        kdf = validate_kdf(keystore["kdf_params"])
    except (KeyError, TypeError, ValueError, binascii.Error):
        raise AuthFailure(crypto.GENERIC_AUTH_ERROR) from None

    kek = crypto.derive_kek(password, salt, **kdf)
    try:
        mk = crypto.decrypt(kek, iv, wrapped, _aad(FORMAT_VERSION, salt, kdf))
    finally:
        crypto.zeroize(kek)
    return bytearray(mk)


def rewrap(keystore: dict, old_password: str, new_password: str) -> dict:
    """Unwrap the MK with the old password and wrap the same MK under a new
    salt + KEK. The vault file is not touched."""
    mk = unlock(keystore, old_password)
    try:
        kdf = validate_kdf(keystore["kdf_params"])
        return _wrap(new_password, mk, kdf)
    finally:
        crypto.zeroize(mk)


def dumps(keystore: dict) -> bytes:
    return (json.dumps(keystore, indent=2) + "\n").encode("utf-8")


def loads(data: bytes) -> dict:
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise AuthFailure(crypto.GENERIC_AUTH_ERROR) from None
    if not isinstance(obj, dict):
        raise AuthFailure(crypto.GENERIC_AUTH_ERROR)
    return obj
