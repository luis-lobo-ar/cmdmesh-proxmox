"""Observed publication on disposable local files, never a managed witness."""

from dataclasses import FrozenInstanceError, fields
import errno
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_atomic as atomic,
)


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cmdmesh-atomic-receipt-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "complete.json"
        self.raw = b'{"synthetic":true}'

    def publish(self):
        return atomic.publish_observed(self.path, self.raw, protocol=atomic.PROTOCOL)

    def test_receipt_binds_actual_anonymous_name_and_both_inode_states(self):
        readlink = os.readlink
        actual_names = []

        def track(path, *args, **kwargs):
            found = readlink(path, *args, **kwargs)
            actual_names.append(os.fsdecode(found))
            return found

        with mock.patch.object(atomic.os, "readlink", side_effect=track):
            result = self.publish()
        self.assertIsInstance(result, atomic.PublicationReceipt)
        self.assertEqual(result.path, str(self.path))
        self.assertEqual(
            result.parent_identity, tuple(atomic.observe.stable(self.root.stat())[:5])
        )
        self.assertEqual(result.before_identity[:2], result.final_identity[:2])
        self.assertEqual(result.before_identity[5:7], (0, len(self.raw)))
        self.assertEqual(result.final_identity[5:7], (1, len(self.raw)))
        self.assertEqual(
            result.final_identity, tuple(atomic.observe.stable(self.path.stat()))
        )
        self.assertEqual(result.payload_sha256, hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(result.payload_bytes, len(self.raw))
        self.assertEqual(result.protocol, atomic.PROTOCOL)
        self.assertGreaterEqual(len(actual_names), 1)
        self.assertEqual(
            set(actual_names), {str(self.root / result.anonymous_name) + " (deleted)"}
        )
        self.assertFalse((self.root / result.anonymous_name).exists())
        self.assertEqual(set(self.root.iterdir()), {self.path})

    def test_receipt_is_frozen_slotted_and_has_no_descriptor_or_callback(self):
        result = self.publish()
        self.assertEqual(
            {field.name for field in fields(result)},
            {
                "path",
                "parent_identity",
                "anonymous_name",
                "before_identity",
                "final_identity",
                "payload_sha256",
                "payload_bytes",
                "protocol",
            },
        )
        self.assertFalse(hasattr(result, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            result.path = "foreign"
        self.assertTrue(all(type(value) is int for value in result.before_identity))
        self.assertTrue(all(type(value) is int for value in result.final_identity))

    def test_private_string_api_uses_the_same_receipt_implementation(self):
        actual = atomic.publish_observed
        seen = []

        def track(*args, **kwargs):
            receipt = actual(*args, **kwargs)
            seen.append(receipt)
            return receipt

        with mock.patch.object(atomic, "publish_observed", side_effect=track):
            result = atomic.publish_private(
                self.path, self.raw, protocol=atomic.PROTOCOL
            )
        self.assertEqual(len(seen), 1)
        self.assertIs(type(result), str)
        self.assertEqual(result, seen[0].payload_sha256)

    def test_untrusted_proc_link_framing_refuses_before_publication(self):
        bad = (
            str(self.root.parent / "foreign" / "anonymous") + " (deleted)",
            str(self.root / "anonymous"),
            str(self.root / "nested" / "anonymous") + " (deleted)",
            str(self.root) + "/../anonymous (deleted)",
            str(self.root) + "/ (deleted)",
            str(self.root) + "/anonymous\nname (deleted)",
        )
        for link in bad:
            with self.subTest(link=link), mock.patch.object(
                atomic.os, "readlink", return_value=os.fsencode(link)
            ):
                with self.assertRaisesRegex(ValueError, "anonymous-name"):
                    self.publish()
            self.assertFalse(self.path.exists())

    def test_anonymous_name_cannot_be_an_actual_named_child(self):
        readlink = atomic.os.readlink
        made = []

        def collision(path, *args, **kwargs):
            found = readlink(path, *args, **kwargs)
            anonymous = Path(os.fsdecode(found).removesuffix(" (deleted)"))
            anonymous.write_bytes(b"preserved")
            anonymous.chmod(0o600)
            made.append(anonymous)
            return found

        with mock.patch.object(atomic.os, "readlink", side_effect=collision):
            with self.assertRaisesRegex(ValueError, "anonymous-name-present"):
                self.publish()
        self.assertFalse(self.path.exists())
        self.assertEqual(made[0].read_bytes(), b"preserved")

    def test_proc_link_change_after_link_refuses_and_keeps_candidate(self):
        readlink = atomic.os.readlink

        def changed(path, *args, **kwargs):
            found = readlink(path, *args, **kwargs)
            if self.path.exists():
                return os.fsencode(str(self.root / "different") + " (deleted)")
            return found

        with mock.patch.object(atomic.os, "readlink", side_effect=changed):
            with self.assertRaisesRegex(ValueError, "anonymous-name-changed"):
                self.publish()
        self.assertEqual(self.path.read_bytes(), self.raw)

    def test_close_failure_suppresses_receipt_and_closes_all_fds(self):
        close = atomic.os.close
        before = len(os.listdir("/proc/self/fd"))
        returned = []

        def failed(fd):
            regular = stat.S_ISREG(os.fstat(fd).st_mode)
            close(fd)
            if regular:
                raise OSError(errno.EIO, "uncertain close")

        with mock.patch.object(atomic.os, "close", side_effect=failed):
            with self.assertRaisesRegex(OSError, "uncertain close"):
                returned.append(self.publish())
        self.assertEqual(returned, [])
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)
        self.assertEqual(self.path.read_bytes(), self.raw)

    def test_readlink_errors_are_not_absence_or_a_successful_publication(self):
        before = len(os.listdir("/proc/self/fd"))
        for code in (errno.EACCES, errno.EIO, errno.ENOENT):
            with self.subTest(code=code), mock.patch.object(
                atomic.os, "readlink", side_effect=OSError(code, "proc read failed")
            ):
                with self.assertRaises(OSError) as caught:
                    self.publish()
            self.assertEqual(caught.exception.errno, code)
            self.assertFalse(self.path.exists())
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_anonymous_child_stat_error_is_not_treated_as_absence(self):
        actual = atomic.os.stat

        def denied(path, *args, **kwargs):
            if isinstance(path, bytes) and not path.isdigit():
                raise PermissionError(errno.EACCES, "child observation denied")
            return actual(path, *args, **kwargs)

        with mock.patch.object(atomic.os, "stat", side_effect=denied):
            with self.assertRaises(PermissionError):
                self.publish()
        self.assertFalse(self.path.exists())

    def test_after_link_error_and_cleanup_error_preserve_primary_failure(self):
        sync, close = atomic.os.fsync, atomic.os.close
        before = len(os.listdir("/proc/self/fd"))
        first = OSError(errno.EIO, "first directory sync failure")

        def sync_failure(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise first
            return sync(fd)

        def close_failure(fd):
            close(fd)
            raise OSError(errno.EIO, "secondary close failure")

        with mock.patch.object(
            atomic.os, "fsync", side_effect=sync_failure
        ), mock.patch.object(atomic.os, "close", side_effect=close_failure):
            with self.assertRaises(OSError) as caught:
                self.publish()
        self.assertIs(caught.exception, first)
        self.assertTrue(any("secondary atomic" in note for note in first.__notes__))
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)
        self.assertEqual(self.path.read_bytes(), self.raw)

    def test_no_proc_or_parent_walk_follows_last_content_proof(self):
        content = atomic._content
        readlink = atomic.os.readlink
        sequence = []

        def track_content(fd, raw):
            result = content(fd, raw)
            sequence.append("final-content" if result[5] == 1 else "anonymous-content")
            return result

        def track_readlink(*args, **kwargs):
            sequence.append("proc-link")
            return readlink(*args, **kwargs)

        with mock.patch.object(
            atomic, "_content", side_effect=track_content
        ), mock.patch.object(atomic.os, "readlink", side_effect=track_readlink):
            self.publish()
        self.assertIn("proc-link", sequence)
        self.assertEqual(sequence[-1], "final-content")


if __name__ == "__main__":
    unittest.main()
