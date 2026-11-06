import copy
import json
import os
import tempfile
import unittest

from passmgr import crypto, keystore, vault
from passmgr.crypto import AuthFailure
from tests.helpers import FAST_KDF, MASTER, read_bytes, read_text


class KeystoreTests(unittest.TestCase):
    def setUp(self):
        self.ks, self.mk = keystore.create(MASTER, FAST_KDF)

    def test_unlock_roundtrip(self):
        self.assertEqual(bytes(keystore.unlock(self.ks, MASTER)), bytes(self.mk))

    def test_wrong_password(self):
        with self.assertRaises(AuthFailure):
            keystore.unlock(self.ks, "Wrong-Password-1!")

    def test_tampered_wrapped_key(self):
        bad = copy.deepcopy(self.ks)
        raw = bytearray(__import__("base64").b64decode(bad["wrapped_mk"]))
        raw[0] ^= 1
        bad["wrapped_mk"] = __import__("base64").b64encode(bytes(raw)).decode()
        with self.assertRaises(AuthFailure):
            keystore.unlock(bad, MASTER)

    def test_kdf_downgrade_rejected(self):
        bad = copy.deepcopy(self.ks)
        bad["kdf_params"]["time_cost"] = 1
        with self.assertRaises(AuthFailure):
            keystore.unlock(bad, MASTER)

    def test_kdf_dos_values_rejected_before_deriving(self):
        bad = copy.deepcopy(self.ks)
        bad["kdf_params"]["memory_cost"] = 2**31
        with self.assertRaises(AuthFailure):
            keystore.unlock(bad, MASTER)

    def test_kdf_change_within_bounds_still_fails(self):
        bad = copy.deepcopy(self.ks)
        bad["kdf_params"]["time_cost"] = 3
        with self.assertRaises(AuthFailure):
            keystore.unlock(bad, MASTER)

    def test_malformed_keystore_gives_generic_failure(self):
        for bad in ({}, {"version": 1}, {"version": 2}, {"salt": 5}):
            with self.assertRaises(AuthFailure):
                keystore.unlock(bad, MASTER)

    def test_rewrap_keeps_mk_and_changes_salt(self):
        new = keystore.rewrap(self.ks, MASTER, "Another-Pass-77!")
        self.assertNotEqual(new["salt"], self.ks["salt"])
        self.assertEqual(bytes(keystore.unlock(new, "Another-Pass-77!")), bytes(self.mk))
        with self.assertRaises(AuthFailure):
            keystore.unlock(new, MASTER)

    def test_password_policy(self):
        for bad in ("short1A!", "alllowercaseletters", "NoSymbolsOrDigits"):
            with self.assertRaises(keystore.PasswordPolicyError):
                keystore.check_password_policy(bad)
        keystore.check_password_policy(MASTER)


class VaultFormatTests(unittest.TestCase):
    def setUp(self):
        self.mk = bytearray(os.urandom(32))
        self.payload = vault.new_payload()
        vault.add_entry(self.payload, "example.com", "alice", "s3cr3t-Value!")

    def test_roundtrip_and_layout(self):
        blob = vault.encrypt_vault(self.mk, self.payload)
        self.assertEqual(blob[:4], b"PMVR")
        self.assertEqual(blob[4], 1)
        self.assertEqual(vault.decrypt_vault(self.mk, blob), self.payload)

    def test_plaintext_not_in_file(self):
        blob = vault.encrypt_vault(self.mk, self.payload)
        self.assertNotIn(b"s3cr3t-Value!", blob)
        self.assertNotIn(b"example.com", blob)

    def test_fresh_iv_every_save(self):
        a = vault.encrypt_vault(self.mk, self.payload)
        b = vault.encrypt_vault(self.mk, self.payload)
        self.assertNotEqual(a[8:20], b[8:20])

    def test_every_single_bit_flip_region_is_detected(self):
        blob = vault.encrypt_vault(self.mk, self.payload)
        for pos in (0, 4, 5, 8, 19, 20, len(blob) // 2, len(blob) - 1):
            bad = bytearray(blob)
            bad[pos] ^= 0x01
            with self.assertRaises(AuthFailure, msg=f"byte {pos}"):
                vault.decrypt_vault(self.mk, bytes(bad))

    def test_truncation_detected(self):
        blob = vault.encrypt_vault(self.mk, self.payload)
        for n in (0, 10, 19, 20, 35, len(blob) - 1):
            with self.assertRaises(AuthFailure):
                vault.decrypt_vault(self.mk, blob[:n])

    def test_wrong_key(self):
        blob = vault.encrypt_vault(self.mk, self.payload)
        with self.assertRaises(AuthFailure):
            vault.decrypt_vault(bytearray(os.urandom(32)), blob)


class EntryTests(unittest.TestCase):
    def test_duplicate_requires_overwrite(self):
        p = vault.new_payload()
        vault.add_entry(p, "a", "u", "pw")
        with self.assertRaises(vault.UserError):
            vault.add_entry(p, "a", "u", "pw2")
        vault.add_entry(p, "a", "u", "pw2", overwrite=True)
        self.assertEqual(vault.get_entry(p, "a")["password"], "pw2")

    def test_rejects_control_characters(self):
        p = vault.new_payload()
        with self.assertRaises(vault.UserError):
            vault.add_entry(p, "bad\x1b[31mname", "u", "pw")

    def test_missing_and_delete(self):
        p = vault.new_payload()
        with self.assertRaises(vault.UserError):
            vault.get_entry(p, "nope")
        vault.add_entry(p, "a", "u", "pw")
        vault.delete_entry(p, "a")
        self.assertEqual(vault.list_entries(p), [])


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.join(self.tmp.name, "pm")
        self.addCleanup(self.tmp.cleanup)

    def test_init_open_save_cycle(self):
        vault.init_store(self.dir, MASTER, FAST_KDF)
        with vault.open_store(self.dir, MASTER) as s:
            vault.add_entry(s.payload, "x", "u", "pw")
            s.save()
        with vault.open_store(self.dir, MASTER) as s:
            self.assertEqual(vault.get_entry(s.payload, "x")["password"], "pw")

    def test_wrong_master_password_does_not_unlock(self):
        vault.init_store(self.dir, MASTER, FAST_KDF)
        with self.assertRaises(AuthFailure):
            vault.open_store(self.dir, "Wrong-Password-1!")

    def test_corrupt_vault_gives_same_error_as_wrong_password(self):
        vault.init_store(self.dir, MASTER, FAST_KDF)
        path = os.path.join(self.dir, "vault.enc")
        data = bytearray(read_bytes(path))
        data[-1] ^= 1
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, 0o600)
        with self.assertRaises(AuthFailure) as ctx:
            vault.open_store(self.dir, MASTER)
        self.assertEqual(str(ctx.exception), crypto.GENERIC_AUTH_ERROR)

    def test_init_refuses_to_overwrite(self):
        vault.init_store(self.dir, MASTER, FAST_KDF)
        with self.assertRaises(vault.UserError):
            vault.init_store(self.dir, MASTER, FAST_KDF)

    def test_weak_master_rejected_on_init(self):
        with self.assertRaises(keystore.PasswordPolicyError):
            vault.init_store(self.dir, "weak", FAST_KDF)

    def test_passwd_leaves_vault_untouched(self):
        vault.init_store(self.dir, MASTER, FAST_KDF)
        before = read_bytes(os.path.join(self.dir, "vault.enc"))
        vault.change_password(self.dir, MASTER, "Brand-New-Pass-5!")
        self.assertEqual(read_bytes(os.path.join(self.dir, "vault.enc")), before)
        vault.open_store(self.dir, "Brand-New-Pass-5!").close()
        with self.assertRaises(AuthFailure):
            vault.open_store(self.dir, MASTER)

    def test_keystore_contains_no_plaintext_key_or_password(self):
        vault.init_store(self.dir, MASTER, FAST_KDF)
        text = read_text(os.path.join(self.dir, "keystore.json"))
        self.assertNotIn(MASTER, text)
        self.assertEqual(sorted(json.loads(text)),
                         ["kdf_params", "kek_iv", "salt", "version", "wrapped_mk"])


if __name__ == "__main__":
    unittest.main()
