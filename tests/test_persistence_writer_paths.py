"""Read-only directory and writer-lock admission with actual local file FDs."""

from contextlib import ExitStack
import fcntl
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_writer_paths as paths,
)


class WriterPathTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.owner = (os.getuid(), os.getgid())
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.stack.callback(os.close, self.descriptor)
        (self.root / "etc").mkdir(mode=0o755)
        (self.root / "etc/app").mkdir(mode=0o700)
        self.file = self.root / "etc/app/application.json"
        self.file.write_bytes(b"synthetic configuration")
        self.file.chmod(0o600)

    def directory(self):
        descriptor = paths.directory(
            self.stack, self.descriptor, "etc/app", self.owner, self.owner
        )
        return descriptor

    def test_directory_walk_returns_actual_private_fd(self):
        descriptor = self.directory()
        self.assertEqual(
            os.fstat(descriptor).st_ino, (self.root / "etc/app").stat().st_ino
        )
        self.assertEqual(os.fstat(descriptor).st_dev, self.root.stat().st_dev)
        with os.fdopen(
            os.open("application.json", os.O_RDONLY, dir_fd=descriptor), "rb"
        ) as source:
            self.assertEqual(source.read(), b"synthetic configuration")

    def test_symlink_public_mode_or_parent_traversal_refuses(self):
        (self.root / "alias").symlink_to("etc", target_is_directory=True)
        for name in ("../etc/app", "/etc/app", "etc/../etc/app", "alias/app"):
            with self.subTest(name=name), self.assertRaises(
                paths.state.PersistenceError
            ):
                paths.directory(
                    self.stack, self.descriptor, name, self.owner, self.owner
                )
        (self.root / "etc/app").chmod(0o755)
        with self.assertRaises(paths.state.PersistenceError):
            self.directory()

    def test_directory_backing_must_match_host_path_without_symlink(self):
        descriptor = self.directory()
        paths.backing(descriptor, self.root / "etc/app")
        other = self.root / "other"
        other.mkdir(mode=0o700)
        with self.assertRaises(paths.state.PersistenceError):
            paths.backing(descriptor, other)
        (self.root / "linked").symlink_to("etc/app", target_is_directory=True)
        with self.assertRaises(paths.state.PersistenceError):
            paths.backing(descriptor, self.root / "linked")

    def test_actual_writer_flock_is_observed_without_acquiring_a_lock(self):
        descriptor = self.directory()
        with self.file.open("rb") as writer:
            fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = paths.writer_lease(descriptor, os.getpid(), *self.owner)
            self.assertEqual(result["pid"], os.getpid())
            self.assertEqual(result["inode"], os.fstat(writer.fileno()).st_ino)
            with self.assertRaises(paths.state.PersistenceError):
                paths.writer_lease(descriptor, os.getpid() + 1, *self.owner)
        with self.assertRaises(paths.state.PersistenceError):
            paths.writer_lease(descriptor, os.getpid(), *self.owner)

    def test_shared_or_unlocked_configuration_does_not_prove_a_writer(self):
        descriptor = self.directory()
        with self.file.open("rb") as writer:
            fcntl.flock(writer, fcntl.LOCK_SH | fcntl.LOCK_NB)
            with self.assertRaises(paths.state.PersistenceError):
                paths.writer_lease(descriptor, os.getpid(), *self.owner)

    def test_acquisition_pid_without_a_remaining_fd_is_not_a_writer(self):
        descriptor = self.directory()
        writer = self.file.open("rb")
        fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
        read, write = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(write)
            os.read(read, 1)
            os._exit(0)
        os.close(read)
        try:
            writer.close()
            # The kernel still reports our acquisition PID, although only the
            # child's inherited file description retains the lock now.
            with self.assertRaises(paths.state.PersistenceError):
                paths.writer_lease(descriptor, os.getpid(), *self.owner)
        finally:
            writer.close()
            os.close(write)
            os.waitpid(child, 0)


if __name__ == "__main__":
    unittest.main()
