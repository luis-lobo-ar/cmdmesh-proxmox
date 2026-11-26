"""Real disposable-file publication, faults and process death; no managed host."""

import errno
import hashlib
import importlib
import multiprocessing
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1] / ".generated"


def die_during_publication(path, phase):
    atomic = importlib.import_module(
        "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_atomic"
    )
    if phase == "write":
        real_write = os.write

        def interrupted(fd, raw):
            real_write(fd, raw[:3])
            os._exit(73)

        atomic.os.write = interrupted
    else:
        real_sync = os.fsync

        def interrupted(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                os._exit(74)
            return real_sync(fd)

        atomic.os.fsync = interrupted
    atomic.publish_private(Path(path), b'{"candidate":true}', protocol=atomic.PROTOCOL)


class AtomicTests(unittest.TestCase):
    def setUp(self):
        self.atomic = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_atomic"
        )
        ROOT.mkdir(mode=0o700, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "marker.json"
        self.raw = b'{"candidate":true}'

    def publish(self):
        return self.atomic.publish_private(
            self.path, self.raw, protocol=self.atomic.PROTOCOL
        )

    def test_complete_private_bytes_have_one_link_and_no_visible_staging(self):
        self.assertEqual(self.publish(), hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(self.path.read_bytes(), self.raw)
        info = self.path.stat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_nlink, 1)
        self.assertEqual([file.name for file in self.root.iterdir()], [self.path.name])

    def test_existing_final_is_never_replaced_even_if_bytes_match(self):
        for raw in (self.raw, b"foreign"):
            with self.subTest(raw=raw):
                self.path.write_bytes(raw)
                initial = self.path.stat()
                with self.assertRaises(FileExistsError):
                    self.publish()
                self.assertEqual(self.path.read_bytes(), raw)
                self.assertEqual(
                    self.atomic.observe.stable(self.path.stat()),
                    self.atomic.observe.stable(initial),
                )
                self.path.unlink()

    def test_partial_write_failure_leaves_no_named_prefix(self):
        real = self.atomic.os.write

        def interrupted(fd, raw):
            real(fd, raw[:3])
            raise OSError(errno.ENOSPC, "injected write failure")

        with mock.patch.object(self.atomic.os, "write", side_effect=interrupted):
            with self.assertRaises(OSError):
                self.publish()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_short_writes_complete_without_exposing_staging(self):
        real = self.atomic.os.write
        with mock.patch.object(
            self.atomic.os, "write", side_effect=lambda fd, raw: real(fd, raw[:3])
        ):
            self.publish()
        self.assertEqual(self.path.read_bytes(), self.raw)
        self.assertEqual(len(list(self.root.iterdir())), 1)

    def test_file_fsync_failure_keeps_final_absent(self):
        with mock.patch.object(
            self.atomic.os, "fsync", side_effect=OSError(errno.EIO, "file sync")
        ):
            with self.assertRaises(OSError):
                self.publish()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_directory_fsync_failure_preserves_full_unaccepted_candidate(self):
        real = self.atomic.os.fsync

        def interrupted(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, "directory sync")
            return real(fd)

        with mock.patch.object(self.atomic.os, "fsync", side_effect=interrupted):
            with self.assertRaises(OSError):
                self.publish()
        self.assertEqual(self.path.read_bytes(), self.raw)
        self.assertEqual(self.path.stat().st_nlink, 1)

    def test_unsupported_profile_refuses_before_opening_any_path(self):
        with mock.patch.object(
            self.atomic.os, "open", side_effect=AssertionError("unexpected IO")
        ):
            with self.assertRaises(ValueError):
                self.atomic.publish_private(self.path, self.raw, protocol="foreign")

    def test_group_writable_parent_and_destination_symlink_refuse(self):
        self.root.chmod(0o770)
        with self.assertRaises(ValueError):
            self.publish()
        self.root.chmod(0o700)
        foreign = self.root / "foreign.json"
        foreign.write_bytes(b"preserve")
        self.path.symlink_to(foreign)
        with self.assertRaises((ValueError, FileExistsError)):
            self.publish()
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(foreign.read_bytes(), b"preserve")

    def test_process_death_during_write_has_no_named_partial(self):
        process = multiprocessing.get_context("fork").Process(
            target=die_during_publication, args=(str(self.path), "write")
        )
        process.start()
        process.join(10)
        self.assertFalse(process.is_alive())
        self.assertEqual(process.exitcode, 73)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_process_death_after_link_has_only_complete_final_bytes(self):
        process = multiprocessing.get_context("fork").Process(
            target=die_during_publication, args=(str(self.path), "directory-sync")
        )
        process.start()
        process.join(10)
        self.assertFalse(process.is_alive())
        self.assertEqual(process.exitcode, 74)
        self.assertEqual(self.path.read_bytes(), self.raw)
        self.assertEqual(self.path.stat().st_nlink, 1)
        self.assertEqual(len(list(self.root.iterdir())), 1)

    def test_unsupported_tmpfile_has_no_direct_write_fallback(self):
        real = self.atomic.os.open

        def unsupported(path, flags, *args, **kwargs):
            if flags & os.O_TMPFILE == os.O_TMPFILE:
                raise OSError(errno.EOPNOTSUPP, "anonymous files unsupported")
            return real(path, flags, *args, **kwargs)

        with mock.patch.object(self.atomic.os, "open", side_effect=unsupported):
            with self.assertRaises(OSError) as caught:
                self.publish()
        self.assertEqual(caught.exception.errno, errno.EOPNOTSUPP)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_non_proc_filesystem_refuses_before_anonymous_creation_or_link(self):
        library = SimpleNamespace(
            fstatfs=mock.Mock(return_value=0),
            linkat=mock.Mock(side_effect=AssertionError("link before proc validation")),
        )
        with mock.patch.object(self.atomic.ctypes, "CDLL", return_value=library):
            with self.assertRaisesRegex(ValueError, "proc-filesystem"):
                self.publish()
        library.linkat.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_wrong_proc_fd_binding_cannot_publish_another_file(self):
        foreign = self.root / "foreign.json"
        foreign.write_bytes(b"preserve")
        real = self.atomic.os.stat

        def changed(path, *args, **kwargs):
            if isinstance(path, bytes) and path.isdigit():
                return real(foreign)
            return real(path, *args, **kwargs)

        with mock.patch.object(self.atomic.os, "stat", side_effect=changed):
            with self.assertRaisesRegex(ValueError, "proc-fd-binding"):
                self.publish()
        self.assertFalse(self.path.exists())
        self.assertEqual(foreign.read_bytes(), b"preserve")

    def test_late_extra_link_suppresses_success_without_removing_candidate(self):
        alias = self.root / "unexpected.json"
        real = self.atomic.os.fsync

        def changed(fd):
            real(fd)
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                os.link(self.path, alias)

        with mock.patch.object(self.atomic.os, "fsync", side_effect=changed):
            with self.assertRaisesRegex(ValueError, "file-policy"):
                self.publish()
        self.assertEqual(self.path.read_bytes(), self.raw)
        self.assertEqual(alias.read_bytes(), self.raw)

    def test_close_error_suppresses_success_and_closes_remaining_descriptors(self):
        real = self.atomic.os.close
        closed = []

        def changed(fd):
            regular = stat.S_ISREG(os.fstat(fd).st_mode)
            real(fd)
            closed.append(fd)
            if regular:
                raise OSError(errno.EIO, "close outcome uncertain")

        with mock.patch.object(self.atomic.os, "close", side_effect=changed):
            with self.assertRaises(OSError):
                self.publish()
        self.assertTrue(closed)
        for fd in closed:
            with self.assertRaises(OSError):
                os.fstat(fd)
        self.assertEqual(self.path.read_bytes(), self.raw)

    def test_file_change_during_last_parent_probe_suppresses_success(self):
        real = self.atomic.os.fstat
        identity = (self.root.stat().st_dev, self.root.stat().st_ino)
        changed = False

        def late(fd):
            nonlocal changed
            info = real(fd)
            if (
                stat.S_ISDIR(info.st_mode)
                and (info.st_dev, info.st_ino) == identity
                and self.path.exists()
            ):
                changed = True
                self.path.write_bytes(b'{"candidate":null}')
            return info

        with mock.patch.object(self.atomic.os, "fstat", side_effect=late):
            with self.assertRaises(ValueError):
                self.publish()
        self.assertTrue(changed)
        self.assertNotEqual(self.path.read_bytes(), self.raw)
