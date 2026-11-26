"""Actual disposable mkdir/inotify lifetime; no managed namespace permission."""

from contextlib import ExitStack
import importlib
import os
import stat
import unittest
from unittest import mock

import test_persistence_owner_completion as fixture
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_attempt as attempt,
    persistence_owner_publication_witness as publication,
    persistence_owner_storage_profile as storage,
)


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class DirectoryTests(unittest.TestCase):
    def setUp(self):
        self.module = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_directory"
        )
        self.case = fixture.CompletionTests("runTest")
        self.case.prepare_old_completion = False
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.r = self.case.old.r
        self.enterContext(
            mock.patch.object(attempt, "_WALK_ROOT", self.case.old.base.root.parent)
        )

    def scope(self, role="runtime-root", **changes):
        return self.module.observe_directory_creation_v2(
            **{**self.case.arguments(), "role": role, **changes}
        )

    def runtime(self):
        self.r.RUNTIME_ROOT.mkdir(mode=0o700)
        self.r.backup.write_private(
            self.r.RUNTIME_ROOT / "runtime.json", storage.RUNTIME
        )

    def test_closed_empty_root_has_fixed_identity_and_no_staging(self):
        with self.scope() as operation:
            receipt = operation.create()
            self.assertFalse(operation.completed)
            self.assertEqual(receipt.path, str(self.r.RUNTIME_ROOT))
            self.assertEqual(receipt.role, "runtime-root")
            self.assertEqual(receipt.identity[2], stat.S_IFDIR | 0o700)
        self.assertTrue(operation.completed)
        self.assertTrue(operation.closed)
        self.assertEqual(set(self.r.RUNTIME_ROOT.iterdir()), set())
        self.assertEqual(
            tuple(self.r.observe.stable(self.r.RUNTIME_ROOT.stat())), receipt.identity
        )

    def test_pair_creation_requires_current_profile_and_uses_selected_pair(self):
        self.runtime()
        with self.scope("pair") as operation:
            receipt = operation.create()
        self.assertEqual(receipt.path, str(self.case.old.path))
        self.assertEqual(set(self.case.old.path.iterdir()), set())

    def test_pair_does_not_initialize_or_upgrade_runtime(self):
        self.r.RUNTIME_ROOT.mkdir(mode=0o700)
        for raw in (None, self.r.state.canonical(self.r.RUNTIME), b"partial"):
            path = self.r.RUNTIME_ROOT / "runtime.json"
            if raw is not None:
                path.write_bytes(raw)
                path.chmod(0o600)
            with self.subTest(raw=raw), self.assertRaises((ValueError, OSError)):
                with self.scope("pair") as operation:
                    operation.create()
            self.assertFalse(self.case.old.path.exists())
            if path.exists():
                path.unlink()

    def test_bad_role_checkpoint_or_contract_refuses_before_observer(self):
        for options in (
            {"role": "other"},
            {"role": True},
            {"checkpoint": None},
            {"checkpoint_sha256": "0" * 64},
            {"contract_sha256": "0" * 64},
        ):
            with self.subTest(options=tuple(options)), mock.patch.object(
                attempt,
                "_Reader",
                side_effect=AssertionError("observer before selection"),
            ), self.assertRaises(ValueError):
                with self.scope(**options):
                    pass

    def test_existing_directory_or_symlink_is_not_adopted(self):
        root = self.r.RUNTIME_ROOT
        root.mkdir(mode=0o700)
        before = self.r.observe.stable(root.stat())
        with self.assertRaises(ValueError):
            with self.scope() as operation:
                operation.create()
        self.assertEqual(self.r.observe.stable(root.stat()), before)
        root.rmdir()
        root.symlink_to(self.case.old.base.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            with self.scope() as operation:
                operation.create()
        self.assertTrue(root.is_symlink())

    def test_no_create_and_caught_second_create_never_complete(self):
        with self.assertRaises(ValueError):
            with self.scope():
                pass
        self.assertFalse(self.r.RUNTIME_ROOT.exists())
        with self.assertRaises(ValueError):
            with self.scope() as operation:
                operation.create()
                with self.assertRaises(ValueError):
                    operation.create()
        self.assertFalse(operation.completed)

    def test_child_mutation_before_exit_refuses_even_when_removed(self):
        with self.assertRaises(ValueError):
            with self.scope() as operation:
                operation.create()
                child = self.r.RUNTIME_ROOT / "unexpected"
                child.write_bytes(b"x")
                child.unlink()
        self.assertFalse(operation.completed)

    def test_same_byte_runtime_dependency_write_refuses(self):
        self.runtime()
        path = self.r.RUNTIME_ROOT / "runtime.json"
        with self.assertRaises(ValueError):
            with self.scope("pair") as operation:
                path.write_bytes(path.read_bytes())
                operation.create()
        self.assertFalse(self.case.old.path.exists())

    def test_parent_target_transient_creation_before_create_refuses(self):
        with self.assertRaises(ValueError):
            with self.scope() as operation:
                self.r.RUNTIME_ROOT.mkdir(mode=0o700)
                self.r.RUNTIME_ROOT.rmdir()
                operation.create()
        self.assertFalse(self.r.RUNTIME_ROOT.exists())

    def test_parent_fsync_failure_keeps_unknown_created_prefix(self):
        with mock.patch.object(
            self.module.os, "fsync", side_effect=OSError("synthetic fsync")
        ), self.assertRaises(OSError):
            with self.scope() as operation:
                operation.create()
        self.assertTrue(self.r.RUNTIME_ROOT.is_dir())
        self.assertFalse(operation.completed)

    def test_pair_allows_only_other_private_pair_directory_churn(self):
        self.runtime()
        other = ("a" if self.case.owner.pair_key[0] != "a" else "b") * 64
        with self.scope("pair") as operation:
            path = self.r.RUNTIME_ROOT / other
            path.mkdir(mode=0o700)
            path.rmdir()
            operation.create()
        self.assertTrue(operation.completed)

    def test_pair_unknown_parent_name_refuses(self):
        self.runtime()
        with self.assertRaises(ValueError):
            with self.scope("pair") as operation:
                path = self.r.RUNTIME_ROOT / "unknown"
                path.write_bytes(b"x")
                path.unlink()
                operation.create()
        self.assertFalse(self.case.old.path.exists())

    def test_runtime_parent_uses_only_selected_namespace_projection(self):
        with self.scope() as operation:
            other = self.r.RUNTIME_ROOT.parent / "unrelated-service"
            other.mkdir(mode=0o700)
            other.rmdir()
            operation.create()
        self.assertTrue(operation.completed)

    def test_directory_watch_overlaps_runtime_publication_before_own_write(self):
        with ExitStack() as resources:
            with self.scope() as operation:
                directory = operation.create()
                write = resources.enter_context(
                    publication.observe_control_publication_v2(
                        **self.case.arguments(),
                        action="finish-runtime",
                        event_profile=publication.EVENT_PROFILE
                    )
                )
                self.assertEqual(write.parent_identity, directory.identity)
            self.assertTrue(operation.completed)
            write.publish()
        self.assertEqual(
            (self.r.RUNTIME_ROOT / "runtime.json").read_bytes(),
            self.r.state.canonical(storage.RUNTIME),
        )

    def test_pair_watch_overlaps_h0_publication_before_own_write(self):
        self.runtime()
        with ExitStack() as resources:
            with self.scope("pair") as operation:
                directory = operation.create()
                write = resources.enter_context(
                    publication.observe_control_publication_v2(
                        **self.case.arguments(),
                        action="record-intent",
                        event_profile=publication.EVENT_PROFILE
                    )
                )
                self.assertEqual(write.parent_identity, directory.identity)
            write.publish()
        self.assertEqual(
            (self.case.old.path / "intent.json").read_bytes(), self.case.h0
        )

    def test_checkpoint_change_on_last_parent_event_read_refuses_before_mkdir(self):
        read = self.module.os.read
        armed = False

        def changed(*args):
            if armed:
                self.case.cp["completion"]["runtime"]["application"][
                    "record_count"
                ] += 1
            return read(*args)

        with mock.patch.object(
            self.module.os, "read", side_effect=changed
        ), self.assertRaises(ValueError):
            with self.scope() as operation:
                armed = True
                operation.create()
        self.assertFalse(self.r.RUNTIME_ROOT.exists())

    def test_exit_checkpoint_change_or_caught_check_error_suppresses_completion(self):
        with self.assertRaises(ValueError):
            with self.scope() as operation:
                operation.create()
                self.case.cp["completion"]["runtime"]["application"][
                    "record_count"
                ] += 1
        self.assertFalse(operation.completed)

    def test_changed_parent_descriptor_cannot_create_outside_fixed_destination(self):
        outside = self.case.old.base.root / "outside"
        outside.mkdir(mode=0o700)
        fd = os.open(outside, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        with self.assertRaises((ValueError, OSError)):
            with self.scope() as operation:
                operation.fd = fd
                operation.create()
        self.assertFalse((outside / self.r.RUNTIME_ROOT.name).exists())
        self.assertFalse(self.r.RUNTIME_ROOT.exists())

    def test_cleanup_is_idempotent_after_descriptor_reuse(self):
        with self.scope() as operation:
            operation.create()
            owned = {operation._parent.event, operation._child.event}
        opened = []
        try:
            for _ in range(64):
                fd = os.open(self.case.old.base.root, os.O_RDONLY | os.O_DIRECTORY)
                opened.append(fd)
                if fd in owned:
                    break
            self.assertIn(fd, owned)
            operation.release()
            self.assertTrue(stat.S_ISDIR(os.fstat(fd).st_mode))
        finally:
            for fd in opened:
                os.close(fd)

    def test_caught_public_check_failure_still_poisoned(self):
        with self.assertRaises(ValueError):
            with self.scope() as operation:
                operation.create()
                with mock.patch.object(
                    operation, "_events", side_effect=ValueError("synthetic")
                ), self.assertRaises(ValueError):
                    operation.check_events()
        self.assertFalse(operation.completed)

    def test_receipt_mutation_after_last_selection_check_is_not_closed(self):
        canonical = self.r.state.canonical
        memory = self.module.semantics.Selection._memory
        armed = False
        operation = None
        receipt = None

        def encode(value):
            nonlocal armed
            raw = canonical(value)
            if (
                operation is not None
                and operation.closed
                and type(value) is dict
                and set(value) == {"path", "role", "identity", "parent_identity"}
            ):
                armed = True
            return raw

        def late(selection):
            memory(selection)
            if armed:
                object.__setattr__(receipt, "path", receipt.path + ".forged")

        with ExitStack() as patches, self.assertRaises(ValueError):
            with self.scope() as current:
                operation = current
                receipt = current.create()
                patches.enter_context(
                    mock.patch.object(self.r.state, "canonical", side_effect=encode)
                )
                patches.enter_context(
                    mock.patch.object(
                        self.module.semantics.Selection,
                        "_memory",
                        autospec=True,
                        side_effect=late,
                    )
                )

    def test_full_selection_validation_finishes_before_descriptor_release(self):
        validate = self.module.semantics.Selection.validate
        operation = None

        def check(selection):
            self.assertFalse(operation is not None and operation.closed)
            return validate(selection)

        with mock.patch.object(
            self.module.semantics.Selection,
            "validate",
            autospec=True,
            side_effect=check,
        ):
            with self.scope() as current:
                operation = current
                current.create()
        self.assertTrue(operation.completed)
