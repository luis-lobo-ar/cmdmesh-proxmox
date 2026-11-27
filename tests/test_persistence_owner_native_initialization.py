"""Admitted initialization with real local journals, observers and flocks.

Current/kernel, actor and source qualification providers remain modeled. This
does not certify managed initialization, native actions or independent restore.
"""

from contextlib import contextmanager
import importlib
import os
import shutil
import unittest
from unittest import mock

import test_persistence_owner_native_admission as fixtures


class _InitializationFixture:
    @classmethod
    def setUpClass(cls):
        class Fixture(fixtures.NativeAdmissionTests):
            pass

        cls.base = Fixture
        cls.addClassCleanup(Fixture.doClassCleanups)
        Fixture.setUpClass()
        cls.accepted = Fixture("runTest").load()

    def setUp(self):
        self.admission = self.accepted
        self.n = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils."
            "persistence_owner_native_executor"
        )
        self.storage = self.base.n.storage
        self.f = self.base.fixture
        self.f.worker = 0
        self.f.fault = None
        self.f.calls.clear()
        self.binding = self.admission.handoff.journal_binding
        self.genesis = self.n.journal._digest(self.n.journal._genesis(self.binding))
        self.old_complete = (
            self.f.executor.storage.RUNTIME_ROOT
            / self.admission.selection._private_binding.pair_key
            / "complete.json"
        )
        self.old_bytes = self.old_complete.read_bytes()
        root = self.n.journal.RUNTIME_ROOT
        lock = root.parent / self.storage.LOCK_NAME
        self.assertTrue(root.is_relative_to(self.f.root))
        self.assertFalse(root.exists())
        self.assertFalse(lock.exists())

        def clean_owned_native_fixture():
            if root.exists():
                shutil.rmtree(root)
            lock.unlink(missing_ok=True)

        self.addCleanup(clean_owned_native_fixture)
        for name in ("post_guest_action", "post_owner_guest_action"):
            self.enterContext(
                mock.patch.object(
                    self.n.journal.api,
                    name,
                    side_effect=AssertionError("initialization must not POST"),
                )
            )

    def call(self, mode="initialize", **overrides):
        arguments = dict(
            admission=self.admission,
            expected_head_sha256=self.genesis,
            check_mode=False,
        )
        if mode == "initialize":
            arguments["allow_mutation"] = True
        arguments.update(overrides)
        return getattr(self.n, mode)(**arguments)

    def body(self, result):
        self.assertIs(type(result), self.f.executor.Candidate)
        self.assertEqual(self.f.r.state.sha256(result.raw), result.sha256)
        body = self.f.r.observe.decode(result.raw)
        for name in (
            "native_action_dispatched",
            "ack_recovered",
            "original_native_operation_qualified",
            "successor_native_admission_authorized",
        ):
            self.assertIs(body[name], False)
        self.assertEqual(body["head_sha256"], self.genesis)
        self.assertEqual(
            body["complete_sha256"], self.admission.handoff.complete_sha256
        )
        self.assertEqual(self.old_complete.read_bytes(), self.old_bytes)
        return body

    def native_files(self):
        root = self.n.journal.RUNTIME_ROOT
        return {
            str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }


class NativeInitializationBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.n = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils."
            "persistence_owner_native_executor"
        )

    def test_invalid_nominal_admission_refuses_before_lease_io(self):
        with mock.patch.object(
            self.n, "_leased", side_effect=AssertionError("lease IO")
        ):
            for mode in ("initialize", "inspect_initialization"):
                arguments = dict(admission=object(), expected_head_sha256="0" * 64)
                if mode == "initialize":
                    arguments["allow_mutation"] = True
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    getattr(self.n, mode)(**arguments)

    def test_initialization_requires_exact_permission_and_normal_mode_before_io(self):
        codec = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils."
            "persistence_owner_native_admission"
        )
        # No selected evidence: invalid modes must refuse before using it.
        sentinel = object.__new__(codec.NativeAdmission)
        with mock.patch.object(
            self.n, "_leased", side_effect=AssertionError("lease IO")
        ):
            for changes in (
                dict(allow_mutation=False),
                dict(allow_mutation=1),
                dict(allow_mutation=None),
                dict(check_mode=True),
                dict(check_mode=0),
            ):
                arguments = dict(
                    admission=sentinel,
                    expected_head_sha256="0" * 64,
                    allow_mutation=True,
                    check_mode=False,
                )
                arguments.update(changes)
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    self.n.initialize(**arguments)


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class NativeInitializationTests(_InitializationFixture, unittest.TestCase):

    def test_wrong_genesis_refuses_before_lease_or_storage_io(self):
        with mock.patch.object(
            self.n, "_leased", side_effect=AssertionError("lease IO")
        ):
            for mode in ("initialize", "inspect_initialization"):
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    self.call(mode, expected_head_sha256="0" * 64)

    def test_readonly_absent_inspection_creates_no_native_files_or_mutex(self):
        body = self.body(self.call("inspect_initialization", check_mode=True))
        self.assertTrue(body["would_change"])
        self.assertFalse(body["initialized"])
        self.assertFalse(body["changed"])
        self.assertFalse(body["v4_metadata_write_attempted"])
        self.assertFalse(self.n.journal.RUNTIME_ROOT.exists())
        self.assertFalse(
            (self.n.journal.RUNTIME_ROOT.parent / self.storage.LOCK_NAME).exists()
        )
        self.assertEqual(self.f.worker, 2)

    def test_initialize_uses_real_v4_files_and_preserves_original_handoff(self):
        body = self.body(self.call())
        self.assertTrue(body["would_change"])
        self.assertTrue(body["initialized"])
        self.assertTrue(body["changed"])
        self.assertTrue(body["v4_metadata_write_attempted"])
        view = self.n.journal._inspect(self.binding, self.genesis)
        self.assertEqual(view.head["state"], "ready")
        self.assertEqual(view.head["sequence"], 0)
        self.assertEqual(self.f.worker, 2)

    def test_repeated_unused_initialization_is_idempotent(self):
        self.call()
        before = self.native_files()
        body = self.body(self.call())
        self.assertFalse(body["would_change"])
        self.assertFalse(body["changed"])
        self.assertTrue(body["initialized"])
        self.assertEqual(before, self.native_files())

    def test_partial_native_state_is_preserved_and_refused(self):
        root = self.n.journal.RUNTIME_ROOT
        root.mkdir(mode=0o700)
        path = root / "runtime.json"
        path.write_bytes(b'{"incomplete":')
        path.chmod(0o600)
        before = self.native_files()
        with self.assertRaises(ValueError):
            self.call()
        self.assertEqual(self.native_files(), before)
        self.assertFalse((root.parent / self.storage.LOCK_NAME).exists())

    def test_failed_second_current_suppresses_candidate_without_undoing_genesis(self):
        self.f.fault = "second-worker-exit"
        with self.assertRaisesRegex(ValueError, "modeled final worker failure"):
            self.call()
        self.assertEqual(
            self.n.journal._inspect(self.binding, self.genesis).head["sequence"], 0
        )
        self.assertEqual(self.old_complete.read_bytes(), self.old_bytes)

    def test_late_lease_exit_suppresses_computed_initialization_candidate(self):
        original = self.n._leased

        @contextmanager
        def late(*args):
            with original(*args) as scope:
                yield scope
            raise ValueError("modeled late native lease exit")

        with mock.patch.object(self.n, "_leased", side_effect=late):
            with self.assertRaisesRegex(ValueError, "modeled late native lease exit"):
                self.call()
        self.assertEqual(self.old_complete.read_bytes(), self.old_bytes)

    def test_native_head_write_after_final_join_suppresses_candidate(self):
        original = self.f.executor._post_worker
        mutations = []

        def late(*args):
            original(*args)
            path = self.n.journal.RUNTIME_ROOT / self.binding.pair_key / "HEAD.json"
            if self.f.worker == 2 and path.exists():
                self.f.samebyte(path)
                mutations.append(str(path))

        with mock.patch.object(self.f.executor, "_post_worker", side_effect=late):
            with self.assertRaises(ValueError):
                self.call()
        self.assertEqual(len(mutations), 1)

    def test_existing_native_parent_requires_the_qualified_mount(self):
        self.storage._initialize_journal(self.binding)
        root = self.n.journal.RUNTIME_ROOT
        pair = root / self.binding.pair_key
        shutil.rmtree(pair)
        before = self.native_files()
        original = self.f.executor.filesystem.fd_mount_id
        observations = []

        def different_mount(fd):
            value = original(fd)
            # Model a bind/submount: inode/device can stay unchanged while the
            # actual destination-parent descriptor belongs to another mount.
            if os.readlink(f"/proc/self/fd/{fd}") == str(root):
                observations.append(fd)
                return value + 1
            return value

        with mock.patch.object(
            self.f.executor.filesystem, "fd_mount_id", side_effect=different_mount
        ):
            with self.assertRaises(ValueError):
                self.call()
        self.assertTrue(observations)
        self.assertFalse(pair.exists())
        self.assertEqual(self.native_files(), before)

    def test_late_native_namespace_appearance_refuses_readonly_candidate(self):
        original = self.f.executor._post_worker
        root = self.n.journal.RUNTIME_ROOT
        mutations = []

        def late(*args):
            original(*args)
            if self.f.worker == 2 and not root.exists():
                root.mkdir(mode=0o700)
                mutations.append(str(root))

        with mock.patch.object(self.f.executor, "_post_worker", side_effect=late):
            with self.assertRaises(ValueError):
                self.call("inspect_initialization")
        self.assertEqual(len(mutations), 1)

    def test_native_bootstrap_mutex_is_not_held_during_current_workers(self):
        original = self.n.current._current_frames_leased
        probes = []

        def available():
            if (self.n.journal.RUNTIME_ROOT.parent / self.storage.LOCK_NAME).exists():
                with self.storage._locked_bootstrap():
                    probes.append("available")

        @contextmanager
        def frames(*args):
            available()
            with original(*args) as value:
                yield value
            available()

        with mock.patch.object(
            self.n.current, "_current_frames_leased", side_effect=frames
        ):
            self.body(self.call())
        self.assertEqual(probes, ["available", "available"])

    def test_wrong_live_filesystem_epoch_refuses_before_native_initialization(self):
        with mock.patch.object(
            self.f.executor.filesystem,
            "_epoch",
            return_value=dict(boot_id="different", mount_namespace="mnt:[1]"),
        ):
            with self.assertRaises(ValueError):
                self.call()
        self.assertFalse(self.n.journal.RUNTIME_ROOT.exists())


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class NativeInitializationOldControlTests(_InitializationFixture, unittest.TestCase):
    def test_same_byte_old_control_change_before_initialization_is_refused(self):
        original = self.n.current._current_frames_leased

        @contextmanager
        def changed(*args):
            with original(*args) as frames:
                yield frames
                if self.f.worker == 1:
                    self.f.samebyte(self.old_complete)

        with mock.patch.object(
            self.n.current, "_current_frames_leased", side_effect=changed
        ):
            with self.assertRaises(ValueError):
                self.call()
        self.assertFalse(self.n.journal.RUNTIME_ROOT.exists())


if __name__ == "__main__":
    unittest.main()
