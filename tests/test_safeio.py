import os
import stat
import tempfile
import unittest

from passmgr import safeio
from tests.helpers import read_text

POSIX = os.name == "posix"


@unittest.skipUnless(POSIX, "permission and symlink checks are POSIX-only")
class SafeIOTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.join(self.tmp.name, "pm")
        safeio.ensure_private_dir(self.dir)

    def test_dir_created_0700(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)

    def test_open_dir_rejected(self):
        os.chmod(self.dir, 0o755)
        with self.assertRaises(safeio.SafeIOError):
            safeio.ensure_private_dir(self.dir)

    def test_symlinked_dir_rejected(self):
        link = os.path.join(self.tmp.name, "link")
        os.symlink(self.dir, link)
        with self.assertRaises(safeio.SafeIOError):
            safeio.ensure_private_dir(link)

    def test_write_is_0600_and_leaves_no_temp_files(self):
        path = os.path.join(self.dir, "f.bin")
        safeio.atomic_write_private(path, b"hello")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(os.listdir(self.dir), ["f.bin"])
        self.assertEqual(safeio.read_private_file(path), b"hello")

    def test_overwrite_is_atomic_replace(self):
        path = os.path.join(self.dir, "f.bin")
        safeio.atomic_write_private(path, b"one")
        safeio.atomic_write_private(path, b"two")
        self.assertEqual(safeio.read_private_file(path), b"two")

    def test_read_rejects_symlink(self):
        secret = os.path.join(self.tmp.name, "id_rsa")
        with open(secret, "w") as f:
            f.write("PRIVATE KEY")
        os.chmod(secret, 0o600)
        link = os.path.join(self.dir, "vault.enc")
        os.symlink(secret, link)
        with self.assertRaises(safeio.SafeIOError):
            safeio.read_private_file(link)

    def test_write_never_follows_symlink(self):
        victim = os.path.join(self.tmp.name, "victim")
        with open(victim, "w") as f:
            f.write("original")
        link = os.path.join(self.dir, "vault.enc")
        os.symlink(victim, link)
        with self.assertRaises(safeio.SafeIOError):
            safeio.atomic_write_private(link, b"overwritten")
        self.assertEqual(read_text(victim), "original")

    def test_read_rejects_loose_permissions(self):
        path = os.path.join(self.dir, "f.bin")
        safeio.atomic_write_private(path, b"x")
        os.chmod(path, 0o644)
        with self.assertRaises(safeio.SafeIOError):
            safeio.read_private_file(path)

    def test_missing_file_raises_not_found(self):
        with self.assertRaises(FileNotFoundError):
            safeio.read_private_file(os.path.join(self.dir, "nope"))


if __name__ == "__main__":
    unittest.main()
