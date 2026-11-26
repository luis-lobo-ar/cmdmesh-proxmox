"""Disposable metadata forensics; no atomic publisher or native admission proof."""

import base64
import errno
import json
import os
from pathlib import Path
import struct
import unittest
from unittest import mock

import test_persistence_owner_retirement as fixture
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_attempt as attempt,
    persistence_owner_storage_profile as profile,
)


class AttemptTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.RetirementTests("runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.r = self.case.r
        self.h0 = self.r.state.canonical(self.case.prepare())
        self.sha = self.r.state.sha256(self.h0)
        self.enterContext(
            mock.patch.object(profile, "RUNTIME_ROOT", self.r.RUNTIME_ROOT)
        )
        # Only the disposable subtree represents root-owned native paths here.
        self.enterContext(mock.patch.object(attempt, "_WALK_ROOT", self.case.base.root))

    def inspect(self):
        return attempt.inspect_attempt(self.case.owner, self.h0, self.sha)

    def captured(self):
        with self.inspect() as view:
            raw = view.raw
        self.assertTrue(view.seal.closed)
        self.assertEqual(view.sha256, self.r.state.sha256(raw))
        value = json.loads(raw)
        self.assertTrue(value["forensic_only"])
        self.assertFalse(value["publication_authorized"])
        self.assertFalse(value["native_action_dispatched"])
        return value

    def version_two(self):
        self.r.RUNTIME_ROOT.mkdir(mode=0o700, exist_ok=True)
        self.r.backup.write_private(
            self.r.RUNTIME_ROOT / "runtime.json", profile.RUNTIME
        )

    def claim(self):
        # Setup uses old metadata helpers, then explicitly selects profile2.
        # This is not evidence that the future atomic publisher works.
        claim = self.case.begin()
        path = self.r.RUNTIME_ROOT / "runtime.json"
        path.write_bytes(self.r.state.canonical(profile.RUNTIME))
        return claim

    def test_unused_does_not_initialize_or_write(self):
        before = self.case.originals()
        self.assertEqual(self.captured()["status"], "unused")
        self.assertFalse(self.r.RUNTIME_ROOT.exists())
        self.case.assert_preserved(before)

    def test_bootstrap_and_empty_claim_are_not_unused(self):
        self.r.RUNTIME_ROOT.mkdir(mode=0o700)
        self.assertEqual(self.captured()["status"], "bootstrap-incomplete")
        self.r.backup.write_private(
            self.r.RUNTIME_ROOT / "runtime.json", profile.RUNTIME
        )
        self.case.path.mkdir(mode=0o700)
        self.assertEqual(self.captured()["status"], "empty-claim")

    def test_legacy_runtime_is_explicitly_blocked(self):
        self.r.RUNTIME_ROOT.mkdir(mode=0o700)
        self.r.backup.write_private(
            self.r.RUNTIME_ROOT / "runtime.json", self.r.RUNTIME
        )
        value = self.captured()
        self.assertEqual(value["status"], "blocked")
        self.assertIn("legacy-runtime-profile", value["blocked_reasons"])

    def test_valid_h0_and_marker_prefixes(self):
        self.claim()
        self.assertEqual(self.captured()["status"], "h0-only")
        marker = self.r._marker(self.case.owner, self.sha)
        self.r.backup.write_private(self.case.base.path() / self.r.MARKER, marker)
        self.assertEqual(self.captured()["status"], "h0-marker")

    def test_complete_candidate_has_no_execution_or_permission_authority(self):
        completed = self.case.complete()
        (self.r.RUNTIME_ROOT / "runtime.json").write_bytes(
            self.r.state.canonical(profile.RUNTIME)
        )
        value = self.captured()
        self.assertEqual(value["status"], "complete-candidate")
        self.assertEqual(
            value["files"][str(self.case.path / "complete.json")]["sha256"],
            completed.sha256,
        )

    def test_zero_and_partial_known_bytes_are_retained(self):
        self.version_two()
        self.case.path.mkdir(mode=0o700)
        for body in (b"", b'{"partial":', b"\xff\x00"):
            path = self.case.path / "intent.json"
            path.write_bytes(body)
            path.chmod(0o600)
            value = self.captured()
            self.assertEqual(value["status"], "blocked")
            self.assertEqual(
                base64.b64decode(value["files"][str(path)]["raw_base64"]), body
            )

    def test_unknown_directory_is_visible_and_not_descended(self):
        self.version_two()
        self.case.path.mkdir(mode=0o700)
        unknown = self.case.path / "unexpected"
        unknown.mkdir(mode=0o700)
        (unknown / "must-not-read").write_bytes(b"private")
        value = self.captured()
        self.assertEqual(value["status"], "blocked")
        self.assertIn(str(unknown), value["unknown_entries"])
        self.assertNotIn(str(unknown / "must-not-read"), value["files"])

    def test_unknown_shared_legacy_member_is_visible_and_blocked(self):
        path = self.r.legacy.RUNTIME_ROOT / "unexpected"
        path.mkdir(mode=0o700)
        value = self.captured()
        self.assertEqual(value["status"], "blocked")
        self.assertIn(str(path), value["unknown_entries"])

    def test_unsafe_links_are_metadata_only(self):
        self.version_two()
        self.case.path.mkdir(mode=0o700)
        outside = self.case.base.root / "outside"
        outside.write_bytes(b"not-exported")
        path = self.case.path / "intent.json"
        path.symlink_to(outside)
        value = self.captured()
        self.assertNotIn(str(path), value["files"])
        self.assertIn(str(path), value["unsafe_entries"])
        path.unlink()
        os.link(outside, path)
        self.assertIn(str(path), self.captured()["unsafe_entries"])

    def test_legacy_file_hash_and_identity_drift_refuses(self):
        path = self.case.base.path() / "HEAD.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(ValueError):
            self.captured()

    def test_equal_byte_legacy_write_while_held_refuses(self):
        with self.assertRaisesRegex(ValueError, "event|changed"):
            with self.inspect():
                path = self.case.base.path() / "HEAD.json"
                fd = os.open(path, os.O_WRONLY)
                try:
                    os.pwrite(fd, path.read_bytes()[:1], 0)
                finally:
                    os.close(fd)

    def test_new_member_after_last_scan_refuses(self):
        self.claim()
        original = attempt._Reader.check_memberships
        changed = False

        def late(reader):
            nonlocal changed
            original(reader)
            if not changed:
                changed = True
                (self.case.path / "late").write_bytes(b"x")

        with mock.patch.object(attempt._Reader, "check_memberships", late):
            with self.assertRaisesRegex(ValueError, "event|changed"):
                self.captured()

    def test_real_events_refuse_even_with_modeled_equal_metadata(self):
        # The FD observer must work even on a filesystem whose timestamp tuple
        # cannot distinguish the write. Only the metadata closer is modeled.
        with mock.patch.object(attempt._Reader, "close_named"):
            with self.assertRaisesRegex(ValueError, "event"):
                with self.inspect():
                    path = self.case.base.path() / "HEAD.json"
                    fd = os.open(path, os.O_WRONLY)
                    try:
                        os.pwrite(fd, path.read_bytes()[:1], 0)
                    finally:
                        os.close(fd)

    def test_release_cannot_change_binding_after_last_check(self):
        original = attempt._Reader.release

        def changed(reader):
            original(reader)
            self.case.owner.__dict__["authority_sha256"] = "f" * 64

        with mock.patch.object(attempt._Reader, "release", changed):
            with self.assertRaisesRegex(ValueError, "binding-changed"):
                self.captured()

    def test_first_error_survives_secondary_release_failure(self):
        original = attempt._Reader.release
        primary = RuntimeError("original caller error")

        def failed(reader):
            original(reader)
            raise OSError("secondary release error")

        with mock.patch.object(attempt._Reader, "release", failed):
            with self.assertRaises(RuntimeError) as raised:
                with self.inspect():
                    raise primary
        self.assertIs(raised.exception, primary)
        self.assertTrue(any("secondary" in text for text in primary.__notes__))

    def test_read_budget_refuses_before_a_large_file_body_is_read(self):
        self.version_two()
        self.case.path.mkdir(mode=0o700)
        path = self.case.path / "intent.json"
        with path.open("wb") as stream:
            stream.truncate(attempt.FILE_LIMIT + 1)
        path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "read-budget"):
            self.captured()

    def test_growth_reads_use_the_remaining_aggregate_cap(self):
        path = self.case.base.root / "growth.json"
        path.write_bytes(b"1234")
        path.chmod(0o600)
        reader = attempt._Reader()
        reader.pair_key = self.case.owner.pair_key
        reader.budget = attempt.AGGREGATE_LIMIT - 8
        watch, read = reader._watch, os.read
        requested, consumed = [], []

        def growing(fd, policy):
            watch(fd, policy)
            if Path(os.readlink("/proc/self/fd/" + str(fd))) == path:
                path.write_bytes(b"abcdefghijkl")

        def bounded(fd, count):
            raw = read(fd, count)
            if Path(os.readlink("/proc/self/fd/" + str(fd))) == path:
                requested.append(count)
                consumed.append(len(raw))
            return raw

        try:
            with mock.patch.object(reader, "_watch", growing):
                with mock.patch.object(os, "read", bounded):
                    with self.assertRaisesRegex(ValueError, "read-budget"):
                        reader.file(path)
            self.assertLessEqual(max(requested), 9)
            self.assertLessEqual(sum(consumed), 9)
            self.assertNotIn(str(path), reader.raws)
        finally:
            reader.release()

    def test_membership_is_bounded_without_descending_unknowns(self):
        self.version_two()
        self.case.path.mkdir(mode=0o700)
        for number in range(attempt.NAME_LIMIT + 1):
            (self.case.path / str(number)).mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, "membership-limit"):
            self.captured()

    def test_directory_group_and_mode_are_not_relaxed(self):
        self.version_two()
        self.r.RUNTIME_ROOT.chmod(0o775)
        value = self.captured()
        self.assertEqual(value["status"], "blocked")
        self.assertIn(str(self.r.RUNTIME_ROOT), value["unsafe_entries"])

    def test_foreign_directory_group_is_metadata_only_blocked(self):
        self.version_two()
        selected = self.r.RUNTIME_ROOT.stat()
        original = attempt._identity

        def foreign(info):
            value = original(info)
            if value[:2] == [selected.st_dev, selected.st_ino]:
                value[4] += 1
            return value

        with mock.patch.object(attempt, "_identity", side_effect=foreign):
            value = self.captured()
        self.assertEqual(value["status"], "blocked")
        self.assertIn(str(self.r.RUNTIME_ROOT), value["unsafe_entries"])

    def test_last_scan_event_survives_modeled_equal_directory_metadata(self):
        original = attempt._Reader.check_memberships
        armed = False

        def late(reader):
            original(reader)
            if armed:
                (self.case.base.path() / "late").touch(mode=0o600)

        with mock.patch.object(attempt._Reader, "check_memberships", late):
            with mock.patch.object(attempt._Reader, "close_named"):
                with self.assertRaisesRegex(ValueError, "event"):
                    with self.inspect():
                        armed = True

    def test_overflow_refuses_and_fd_resources_close(self):
        before = len(list(Path("/proc/self/fd").iterdir()))
        with self.assertRaisesRegex(ValueError, "event"):
            with self.inspect() as view:
                original = os.read

                def overflow(fd, count):
                    if fd == view.seal.event:
                        return struct.pack("iIII", -1, 0x4000, 0, 0)
                    return original(fd, count)

                self.enterContext(mock.patch.object(os, "read", side_effect=overflow))
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)

    def test_continuous_allowed_event_stream_has_a_finite_budget(self):
        with self.inspect() as view:
            wd = next(
                wd
                for wd, policies in view.seal.watches.items()
                if ("shared", self.case.owner.pair_key) in policies
            )
            name = b"a" * 64 + b"\0" * 4
            frame = struct.pack("iIII", wd, 0x100 | 0x40000000, 0, len(name)) + name
            original = os.read
            calls = 0

            def stream(fd, count):
                nonlocal calls
                if fd == view.seal.event:
                    calls += 1
                    if calls <= 9:
                        return frame
                    raise BlockingIOError()
                return original(fd, count)

            with mock.patch.object(os, "read", side_effect=stream):
                with self.assertRaisesRegex(ValueError, "event-budget"):
                    view.seal.check_events()
            self.assertLessEqual(calls, 8)

    def test_short_eof_is_not_a_complete_file(self):
        original = os.read
        selected = self.case.base.path() / "HEAD.json"

        def short(fd, count):
            if Path(os.readlink("/proc/self/fd/" + str(fd))) == selected:
                return b""
            return original(fd, count)

        before = len(list(Path("/proc/self/fd").iterdir()))
        with mock.patch.object(os, "read", side_effect=short):
            with self.assertRaisesRegex(ValueError, "file-race"):
                self.captured()
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)

    def test_joined_caller_scan_does_not_trigger_a_later_membership_walk(self):
        with self.inspect() as view:
            view.seal.check_memberships()
            view.seal.close_named()
            view.seal.check_events()
            self.enterContext(
                mock.patch.object(
                    view.seal,
                    "check_memberships",
                    side_effect=AssertionError("late unjoined membership scan"),
                )
            )

    def test_unrelated_valid_pair_churn_is_allowed(self):
        self.version_two()
        with self.inspect():
            sibling = self.r.RUNTIME_ROOT / ("a" * 64)
            sibling.mkdir(mode=0o700)
            sibling.rmdir()

    def test_selected_absence_change_refuses(self):
        with self.assertRaisesRegex(ValueError, "event|changed"):
            with self.inspect():
                self.r.RUNTIME_ROOT.mkdir(mode=0o700)

    def test_permission_error_is_not_absence(self):
        original = os.stat

        def denied(path, *args, **kwargs):
            if path == self.r.RUNTIME_ROOT.name and kwargs.get("dir_fd") is not None:
                raise PermissionError(errno.EACCES, "modeled read refusal")
            return original(path, *args, **kwargs)

        with mock.patch.object(os, "stat", side_effect=denied):
            with self.assertRaises(PermissionError):
                self.captured()

    def test_orphan_marker_is_blocked_without_initializing_namespace(self):
        self.r.backup.write_private(
            self.case.base.path() / self.r.MARKER,
            self.r._marker(self.case.owner, self.sha),
        )
        value = self.captured()
        self.assertEqual(value["status"], "blocked")
        self.assertIn("marker-without-intent", value["blocked_reasons"])
        self.assertFalse(self.r.RUNTIME_ROOT.exists())

    def test_coherent_wrong_h0_marker_is_not_a_valid_prefix(self):
        self.claim()
        self.r.backup.write_private(
            self.case.base.path() / self.r.MARKER,
            self.r._marker(self.case.owner, "b" * 64),
        )
        value = self.captured()
        self.assertEqual(value["status"], "blocked")
        self.assertIn("invalid-marker", value["blocked_reasons"])

    def test_valid_completion_with_wrong_actual_descriptor_is_blocked(self):
        candidate = self.case.complete()
        (self.r.RUNTIME_ROOT / "runtime.json").write_bytes(
            self.r.state.canonical(profile.RUNTIME)
        )
        body = json.loads(candidate.raw)
        body["intent_file"]["identity"][1] += 1
        (self.case.path / "complete.json").write_bytes(self.r.state.canonical(body))
        value = self.captured()
        self.assertEqual(value["status"], "blocked")
        self.assertIn("invalid-completion", value["blocked_reasons"])

    def test_input_io_error_is_not_reported_as_unused(self):
        original = os.stat

        def unavailable(path, *args, **kwargs):
            if path == self.r.RUNTIME_ROOT.name and kwargs.get("dir_fd") is not None:
                raise OSError(errno.EIO, "modeled metadata IO error")
            return original(path, *args, **kwargs)

        with mock.patch.object(os, "stat", side_effect=unavailable):
            with self.assertRaises(OSError) as caught:
                self.captured()
        self.assertEqual(caught.exception.errno, errno.EIO)

    def test_candidate_memory_drift_and_release_error_refuse(self):
        with self.assertRaisesRegex(ValueError, "memory"):
            with self.inspect() as view:
                object.__setattr__(view, "raw", b"{}")
        original = attempt._Reader.release

        def failed(reader):
            original(reader)
            raise OSError("modeled release failure")

        with mock.patch.object(attempt._Reader, "release", failed):
            with self.assertRaisesRegex(OSError, "release"):
                self.captured()

    def test_bad_h0_refuses_before_observer_or_files(self):
        with mock.patch.object(attempt, "_Reader", side_effect=AssertionError("IO")):
            with self.assertRaises(ValueError):
                with attempt.inspect_attempt(self.case.owner, self.h0 + b" ", self.sha):
                    self.fail("accepted wrong input")


if __name__ == "__main__":
    unittest.main()
