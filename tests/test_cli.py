import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from passmgr import cli, keystore
from tests.helpers import FAST_KDF, MASTER, read_bytes

NEW_MASTER = "Brand-New-Pass-5!"
ENTRY_PW = "Sup3r-Secret-Entry-Pw"


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.join(self.tmp.name, "pm")
        patcher = mock.patch.dict(keystore.DEFAULT_KDF, FAST_KDF)  # keep tests fast
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_cli(self, argv, secrets):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("passmgr.cli.read_secret", side_effect=list(secrets)), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--dir", self.dir] + argv)
        return code, out.getvalue(), err.getvalue()

    def init(self):
        self.assertEqual(self.run_cli(["init"], [MASTER, MASTER])[0], 0)

    def test_full_workflow_never_prints_password(self):
        self.init()
        code, out, err = self.run_cli(["add", "github", "-u", "alice"], [MASTER, ENTRY_PW, ENTRY_PW])
        self.assertEqual(code, 0)
        code, out, err = self.run_cli(["list"], [MASTER])
        self.assertIn("github", out)
        self.assertIn("alice", out)
        code, out, err = self.run_cli(["get", "github"], [MASTER])
        self.assertEqual(code, 0)
        self.assertIn("alice", out)
        for stream in (out, err):
            self.assertNotIn(ENTRY_PW, stream)

    def test_wrong_master_password(self):
        self.init()
        code, out, err = self.run_cli(["list"], ["Wrong-Password-1!"])
        self.assertEqual(code, 1)
        self.assertIn("Authentication failed or corrupted vault.", err)
        self.assertEqual(out, "")

    def test_credentials_not_stored_in_plaintext(self):
        self.init()
        self.run_cli(["add", "mail.example", "-u", "bob"], [MASTER, ENTRY_PW, ENTRY_PW])
        for name in ("vault.enc", "keystore.json"):
            raw = read_bytes(os.path.join(self.dir, name))
            for needle in (ENTRY_PW.encode(), b"mail.example", b"bob", MASTER.encode()):
                self.assertNotIn(needle, raw)

    def test_generate_never_displays_password(self):
        self.init()
        code, out, err = self.run_cli(["add", "site", "--generate", "--length", "24"], [MASTER])
        self.assertEqual(code, 0)
        self.assertNotIn("Password:", out)
        pw = None
        from passmgr import vault
        with vault.open_store(self.dir, MASTER) as s:
            pw = vault.get_entry(s.payload, "site")["password"]
        self.assertEqual(len(pw), 24)
        self.assertNotIn(pw, out + err)

    def test_get_copy_uses_clipboard_not_screen(self):
        self.init()
        self.run_cli(["add", "site"], [MASTER, ENTRY_PW, ENTRY_PW])
        calls = []
        with mock.patch("passmgr.cli.set_clipboard", side_effect=lambda t: calls.append(t) or True), \
             mock.patch("passmgr.cli.time.sleep"):
            code, out, err = self.run_cli(["get", "site", "--copy"], [MASTER])
        self.assertEqual(calls, [ENTRY_PW, ""])  # copied, then cleared
        self.assertNotIn(ENTRY_PW, out + err)

    def test_get_copy_without_clipboard_tool_fails_safely(self):
        self.init()
        self.run_cli(["add", "site"], [MASTER, ENTRY_PW, ENTRY_PW])
        with mock.patch("passmgr.cli.set_clipboard", return_value=False):
            code, out, err = self.run_cli(["get", "site", "--copy"], [MASTER])
        self.assertEqual(code, 1)
        self.assertNotIn(ENTRY_PW, out + err)

    def test_passwd_changes_master_password(self):
        self.init()
        self.run_cli(["add", "site"], [MASTER, ENTRY_PW, ENTRY_PW])
        self.assertEqual(self.run_cli(["passwd"], [MASTER, NEW_MASTER, NEW_MASTER])[0], 0)
        self.assertEqual(self.run_cli(["list"], [MASTER])[0], 1)
        code, out, _ = self.run_cli(["list"], [NEW_MASTER])
        self.assertEqual(code, 0)
        self.assertIn("site", out)

    def test_delete(self):
        self.init()
        self.run_cli(["add", "site"], [MASTER, ENTRY_PW, ENTRY_PW])
        self.assertEqual(self.run_cli(["delete", "site", "--yes"], [MASTER])[0], 0)
        self.assertIn("(vault is empty)", self.run_cli(["list"], [MASTER])[1])

    def test_mismatched_confirmation_and_weak_master(self):
        code, _, err = self.run_cli(["init"], [MASTER, "different"])
        self.assertEqual(code, 1)
        code, _, err = self.run_cli(["init"], ["weak", "weak"])
        self.assertEqual(code, 1)
        self.assertIn("at least 12", err)

    def test_no_traceback_on_unexpected_error(self):
        self.init()
        with mock.patch("passmgr.vault.open_store", side_effect=RuntimeError("secret=hunter2")):
            code, out, err = self.run_cli(["list"], [MASTER])
        self.assertEqual(code, 1)
        self.assertNotIn("hunter2", out + err)
        self.assertNotIn("Traceback", err)

    def test_list_before_init(self):
        code, _, err = self.run_cli(["list"], [MASTER])
        self.assertEqual(code, 1)
        self.assertIn("init", err)


if __name__ == "__main__":
    unittest.main()
