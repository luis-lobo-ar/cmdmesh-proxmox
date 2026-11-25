"""Native configuration leases must exclude writers without policy fabrication."""

import fcntl
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_config_lock as lock,
)


class NativeConfigLockTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".generated"
        scratch.mkdir(mode=0o700, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="config-lock-", dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name, value in (("LOCK_ROOT", self.root), ("ROOT_UID", os.geteuid())):
            patch = mock.patch.object(lock, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def path(self, vmid=101):
        return self.root / f"pve-config-{vmid}.lock"

    def test_read_only_absence_creates_nothing(self):
        with self.assertRaises((lock.ConfigLockError, OSError)):
            with lock.read_guest(101):
                self.fail("absent native lock accepted")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_explicit_initialization_preserves_existing_bytes_and_inode(self):
        with lock.read_guest(101, initialize=True):
            pass
        path = self.path()
        before = path.read_bytes(), path.stat().st_ino
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with lock.read_guest(101, initialize=True):
            pass
        self.assertEqual((path.read_bytes(), path.stat().st_ino), before)

    def test_shared_read_excludes_native_writer_and_write_probe(self):
        with lock.read_guest(101, initialize=True):
            with self.path().open("rb") as writer:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(lock.ConfigLockError):
                lock.require_write_available(101)
            with lock.read_guest(101):
                pass
            with lock.read_guest(102, initialize=True):
                pass
        lock.require_write_available(101)

    def test_existing_writer_refuses_reader_without_waiting_or_modification(self):
        with lock.read_guest(101, initialize=True):
            pass
        before = self.path().stat()
        with self.path().open("rb") as writer:
            fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(lock.ConfigLockError):
                with lock.read_guest(101):
                    self.fail("writer bypassed")
        self.assertEqual(self.path().stat().st_ino, before.st_ino)
        self.assertEqual(self.path().read_bytes(), b"")

    def test_invalid_target_refuses_before_any_file_creation(self):
        for vmid in (True, 0, "101", 1000000):
            with self.subTest(vmid=vmid), self.assertRaises(lock.ConfigLockError):
                with lock.read_guest(vmid, initialize=True):
                    self.fail("invalid target accepted")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_foreign_file_is_not_repaired(self):
        path = self.path()
        path.write_bytes(b"preserved")
        path.chmod(0o666)
        with self.assertRaises(lock.ConfigLockError):
            with lock.read_guest(101, initialize=True):
                self.fail("foreign mode accepted")
        self.assertEqual(path.read_bytes(), b"preserved")
        self.assertEqual(path.stat().st_mode & 0o777, 0o666)

    def test_failure_releases_descriptor_and_replacement_remains_visible(self):
        with self.assertRaisesRegex(ValueError, "caller failed"):
            with lock.read_guest(101, initialize=True):
                raise ValueError("caller failed")
        lock.require_write_available(101)
        with self.assertRaises(lock.ConfigLockError):
            with lock.read_guest(101):
                original = self.path().with_name("preserved.lock")
                self.path().rename(original)
                self.path().write_bytes(b"")
                self.path().chmod(0o600)
        self.assertTrue(self.path().exists() and original.exists())


if __name__ == "__main__":
    unittest.main()
