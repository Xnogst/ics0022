"""Vault: credential storage, AES-256-GCM (de)serialisation and store orchestration.

vault.enc layout (all authenticated):
    magic "PMVR" (4) | version (1) | reserved (3) | iv (12) | ciphertext | tag (16)
The first 8 header bytes are passed as AAD, so the header cannot be altered.
"""

import json
import os
import time

from . import crypto, keystore, safeio
from .crypto import AuthFailure

MAGIC = b"PMVR"
VERSION = 1
HEADER = MAGIC + bytes([VERSION]) + b"\x00\x00\x00"  # 8 bytes, used as AAD
HEADER_LEN = len(HEADER) + crypto.IV_LEN  # 20
KEYSTORE_NAME = "keystore.json"
VAULT_NAME = "vault.enc"

MAX_SERVICE_LEN = 128
MAX_FIELD_LEN = 1024


class UserError(Exception):
    """A problem the user can fix; message is safe to show."""


# ---------- vault file (de)serialisation ----------

def new_payload() -> dict:
    return {"version": 1, "entries": {}}


def encrypt_vault(mk, payload: dict) -> bytes:
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    iv, ct = crypto.encrypt(mk, plaintext, HEADER)  # fresh random IV every save
    return HEADER + iv + ct


def decrypt_vault(mk, blob: bytes) -> dict:
    if len(blob) < HEADER_LEN + crypto.TAG_LEN or blob[: len(HEADER)] != HEADER:
        raise AuthFailure(crypto.GENERIC_AUTH_ERROR)
    iv = blob[len(HEADER): HEADER_LEN]
    plaintext = crypto.decrypt(mk, iv, blob[HEADER_LEN:], HEADER)
    try:
        payload = json.loads(plaintext.decode("utf-8"))
        if not isinstance(payload.get("entries"), dict):
            raise ValueError
    except (UnicodeDecodeError, ValueError, AttributeError):
        raise AuthFailure(crypto.GENERIC_AUTH_ERROR) from None
    return payload


# ---------- entry validation and operations ----------

def _check_text(value: str, what: str, max_len: int, required: bool) -> str:
    if not isinstance(value, str):
        raise UserError(f"Invalid {what}.")
    if required and not value:
        raise UserError(f"{what.capitalize()} must not be empty.")
    if len(value) > max_len:
        raise UserError(f"{what.capitalize()} is too long (max {max_len}).")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise UserError(f"{what.capitalize()} must not contain control characters.")
    return value


def check_service(service: str) -> str:
    return _check_text(service.strip(), "service name", MAX_SERVICE_LEN, True)


def add_entry(payload: dict, service: str, username: str, password: str,
              notes: str = "", overwrite: bool = False) -> None:
    service = check_service(service)
    username = _check_text(username, "username", 256, False)
    password = _check_text(password, "password", MAX_FIELD_LEN, True)
    notes = _check_text(notes, "notes", MAX_FIELD_LEN, False)
    entries = payload["entries"]
    if service in entries and not overwrite:
        raise UserError(f"An entry for '{service}' already exists (use --force to replace it).")
    now = int(time.time())
    created = entries.get(service, {}).get("created", now)
    entries[service] = {"username": username, "password": password, "notes": notes,
                        "created": created, "updated": now}


def get_entry(payload: dict, service: str) -> dict:
    try:
        return payload["entries"][check_service(service)]
    except KeyError:
        raise UserError(f"No entry named '{service.strip()}'.") from None


def delete_entry(payload: dict, service: str) -> None:
    get_entry(payload, service)
    del payload["entries"][check_service(service)]


def list_entries(payload: dict):
    return sorted((name, e.get("username", "")) for name, e in payload["entries"].items())


# ---------- on-disk store ----------

class Session:
    """An unlocked vault. Holds the MK and decrypted payload only in RAM."""

    def __init__(self, directory: str, mk: bytearray, payload: dict):
        self.directory = directory
        self.mk = mk
        self.payload = payload

    def save(self) -> None:
        blob = encrypt_vault(self.mk, self.payload)
        safeio.atomic_write_private(os.path.join(self.directory, VAULT_NAME), blob)

    def close(self) -> None:
        crypto.zeroize(self.mk)
        self.payload = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _paths(directory: str):
    return os.path.join(directory, KEYSTORE_NAME), os.path.join(directory, VAULT_NAME)


def is_initialized(directory: str) -> bool:
    return os.path.lexists(_paths(directory)[0])


def init_store(directory: str, password: str, kdf: dict = None) -> None:
    keystore.check_password_policy(password)
    safeio.ensure_private_dir(directory)
    ks_path, vault_path = _paths(directory)
    if os.path.lexists(ks_path):
        raise UserError("A vault already exists here. Refusing to overwrite it.")
    ks, mk = keystore.create(password, kdf)
    try:
        safeio.atomic_write_private(vault_path, encrypt_vault(mk, new_payload()))
        safeio.atomic_write_private(ks_path, keystore.dumps(ks))
    finally:
        crypto.zeroize(mk)


def open_store(directory: str, password: str) -> Session:
    if not is_initialized(directory):
        raise UserError("No vault found. Run 'init' first.")
    safeio.ensure_private_dir(directory)
    ks_path, vault_path = _paths(directory)
    try:
        ks = keystore.loads(safeio.read_private_file(ks_path))
        blob = safeio.read_private_file(vault_path)
    except FileNotFoundError:
        raise AuthFailure(crypto.GENERIC_AUTH_ERROR) from None
    mk = keystore.unlock(ks, password)
    try:
        payload = decrypt_vault(mk, blob)
    except BaseException:
        crypto.zeroize(mk)
        raise
    return Session(directory, mk, payload)


def change_password(directory: str, old_password: str, new_password: str) -> None:
    keystore.check_password_policy(new_password)
    safeio.ensure_private_dir(directory)
    ks_path, _ = _paths(directory)
    ks = keystore.loads(safeio.read_private_file(ks_path))
    new_ks = keystore.rewrap(ks, old_password, new_password)
    safeio.atomic_write_private(ks_path, keystore.dumps(new_ks))  # vault untouched
