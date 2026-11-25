"""Retained startup preparation binds stopped evidence without changing state."""

import copy
from contextlib import contextmanager
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_retained_boot as boot,
)
import test_persistence_retained_runtime as retained


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"),
    "provide the pinned corrected recipe source",
)
class BootPreparationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = retained.QuiescedCollectionTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.request, self.profile = self.fixture.request, self.fixture.profile
        self.root = self.fixture.root
        managed = self.root / "owner-history"
        managed.mkdir(mode=0o700)
        self.recovery_root = managed / "recovery"
        self.publisher_root = managed / "publisher"
        for path in (self.recovery_root, self.publisher_root):
            path.mkdir(mode=0o700)
            (path / "profile.json").write_bytes(boot.state.canonical({"schema": 1}))
            (path / "profile.json").chmod(0o600)
        datasets = self.request["policy"]["datasets"]
        pair = boot.state.pair_key(datasets)
        self.recovery = self.recovery_root / pair
        self.publisher = self.publisher_root / pair
        for path in (self.recovery, self.publisher):
            path.mkdir(mode=0o700)
            for name in ("intent.json", "complete.json"):
                (path / name).write_bytes(boot.state.canonical({"record": name}))
                (path / name).chmod(0o600)
        self.guard_path = self.recovery / "guard.py"
        self.guard_path.write_text(self.profile["guard_python"])
        self.guard_path.chmod(0o600)
        self.request["reference_guard"]["path"] = str(self.guard_path)
        (self.recovery / "policy.json").write_bytes(
            boot.state.canonical(self.request["policy"])
        )
        (self.recovery / "policy.json").chmod(0o600)
        self.parent = {
            "document_type": boot.reconcile.PREPARED,
            "schema_version": 1,
            "parent_prepared": {
                "attachment_prepared": {
                    "recipient_prepared": {
                        "request": {
                            "source_request": {"policy": {"datasets": datasets}}
                        }
                    }
                }
            },
            "parent_prepared_sha256": "a" * 64,
            "parent_failure_sha256": "b" * 64,
            "guard_sha256": boot.reconcile.GUARD_SHA,
            "source_request": self.request,
            "source_before": {},
            "parent_stage": {},
            "candidate_probe": {},
        }
        self.raw = boot.state.canonical(self.parent)
        self.sha = boot.state.sha256(self.raw)
        self.source = {
            "schema_version": 1,
            "source": copy.deepcopy(self.request["source"]),
            "host": copy.deepcopy(self.fixture.value["host"]),
            "guest": {
                **copy.deepcopy(self.fixture.value["guest"]),
                "status": "stopped",
            },
            "quiesced": True,
            "application": copy.deepcopy(self.fixture.value["application"]),
        }
        self.source_sha = boot.state.sha256(boot.state.canonical(self.source))
        self.completion_sha = "c" * 64
        self.accepted = {
            "prepared_sha256": self.sha,
            "completion_sha256": self.completion_sha,
            "phase": "owner-reconciled-starts-denied",
            "source_request": self.request,
            "source_observed": self.source,
            "publication": {"files": {}, "controls": {}},
            "phase_journal_sha256": "d" * 64,
            "owner_reconciliation_verified": True,
            "owner_publication_verified": True,
            "legacy_source_refused": True,
            "boot_verified": False,
            "rebuild_verified": False,
            "restore_verified": False,
        }
        self.events = []
        self.real_pair = boot.pair_lock.locked_pair
        self.guard = boot.runtime.load_profile(self.request, self.profile)[0]
        for target, name, callback in (
            (boot.reconcile, "status", lambda *args: copy.deepcopy(self.accepted)),
            (
                boot.reconcile,
                "current_files",
                lambda *args: self.leased_result(self.accepted["publication"]),
            ),
            (
                boot.reconcile,
                "phase_journal",
                lambda *args: self.leased_result(self.accepted["phase_journal_sha256"]),
            ),
            (boot.observe, "source_state", self.stopped_source),
            (boot.observe, "load_guard", lambda reference: self.guard),
            (
                boot,
                "root_identity",
                lambda profile: copy.deepcopy(profile["rootfs"]["identity"]),
            ),
        ):
            patch = mock.patch.object(target, name, side_effect=callback)
            patch.start()
            self.addCleanup(patch.stop)
        for target, name, value in (
            (boot.reconcile, "RUNTIME_ROOT", self.recovery_root),
            (boot.reconcile.original, "RUNTIME_ROOT", self.publisher_root),
            (boot.reconcile.original, "SYSTEM_ROOT", self.root),
            (boot.reconcile.original, "ROOT_UID", os.geteuid()),
            (boot, "RUNTIME_ROOT", managed / "boot"),
        ):
            patch = mock.patch.object(target, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def scopes(self):
        for vmid in self.fixture.vmids:
            with self.assertRaises(boot.config_lock.ConfigLockError):
                boot.config_lock.require_write_available(vmid)
        with self.assertRaises(boot.state.PersistenceError):
            with self.real_pair(self.request["policy"]["datasets"]):
                self.fail("pair must remain exclusive")

    def leased_result(self, value):
        self.scopes()
        return copy.deepcopy(value)

    @contextmanager
    def stopped_source(self, request, require_stopped=False):
        self.scopes()
        self.assertTrue(require_stopped)
        self.assertEqual(request, self.request)
        self.events.append("source-enter")
        with self.fixture.locked_config(
            self.fixture.config, os.geteuid(), os.getegid()
        ):
            yield copy.deepcopy(self.source)
        self.events.append("source-closed")

    def prepare(self, **changed):
        values = {
            "reconciliation_raw": self.raw,
            "reconciliation_sha256": self.sha,
            "completion_sha256": self.completion_sha,
            "source_sha256": self.source_sha,
            "image_profile": self.profile,
        }
        return boot.prepare(**(values | changed))

    def files(self):
        return {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
        }

    def test_preparation_is_read_only_closes_source_and_binds_raw_history(self):
        before = self.files()
        result = self.prepare()
        self.assertEqual(self.events, ["source-enter", "source-closed"])
        self.assertEqual(result["source_before"], self.source)
        self.assertEqual(result["image_profile"], self.profile)
        self.assertEqual(result["reconciliation_sha256"], self.sha)
        self.assertEqual(len(result["history"]["directories"]), 2)
        self.assertEqual(before, self.files())
        self.assertFalse(boot.RUNTIME_ROOT.exists())
        self.fixture.released()
        raw = boot.state.canonical(result)
        self.assertEqual(boot.decode_prepared(raw, boot.state.sha256(raw)), result)

    def test_wrong_input_hash_refuses_before_reconciliation_or_native_reads(self):
        with mock.patch.object(boot.reconcile, "status") as status:
            with self.assertRaises(ValueError):
                self.prepare(reconciliation_sha256="f" * 64)
        status.assert_not_called()
        self.assertFalse(boot.RUNTIME_ROOT.exists())

    def test_wrong_completion_source_or_qualification_flag_refuses(self):
        for field, value in (
            ("completion_sha256", "e" * 64),
            ("owner_reconciliation_verified", 1),
            ("boot_verified", True),
            ("phase", "unqualified"),
        ):
            original = copy.deepcopy(self.accepted)
            self.accepted[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.prepare()
            self.accepted = original
        with self.assertRaises(ValueError):
            self.prepare(source_sha256="f" * 64)
        self.assertFalse(boot.RUNTIME_ROOT.exists())

    def test_unknown_helper_or_changed_config_root_refuses(self):
        for field in ("guard_python", "config", "rootfs"):
            profile = copy.deepcopy(self.profile)
            if field == "guard_python":
                profile[field] = "raise RuntimeError('must not execute')"
            elif field == "config":
                profile[field]["digest"] = "e" * 40
            else:
                profile[field]["identity"][1] += 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.prepare(image_profile=profile)
        self.assertFalse(boot.RUNTIME_ROOT.exists())

    def test_late_raw_parent_change_refuses_after_slow_phase_check(self):
        def changed(*args):
            (self.publisher / "intent.json").write_bytes(b'{"late":"change"}')
            return self.accepted["phase_journal_sha256"]

        with mock.patch.object(boot.reconcile, "phase_journal", side_effect=changed):
            with self.assertRaises(ValueError):
                self.prepare()
        self.fixture.released()
        self.assertFalse(boot.RUNTIME_ROOT.exists())

    def test_parent_member_added_during_source_close_refuses(self):
        original = self.stopped_source

        @contextmanager
        def changed(*args, **kwargs):
            with original(*args, **kwargs) as value:
                yield value
            path = self.recovery / "unexpected.json"
            path.write_bytes(b"{}")
            path.chmod(0o600)

        with mock.patch.object(boot.observe, "source_state", side_effect=changed):
            with self.assertRaises(ValueError):
                self.prepare()
        self.fixture.released()

    def test_final_history_file_read_cannot_leave_an_earlier_record_stale(self):
        original = boot._history_file
        calls = 0

        def changed(path, **kwargs):
            nonlocal calls
            result = original(path, **kwargs)
            if path == self.publisher_root / "profile.json":
                calls += 1
                if calls == 2:
                    (self.publisher / "intent.json").write_bytes(b'{"late":"change"}')
            return result

        with mock.patch.object(boot, "_history_file", side_effect=changed):
            with self.assertRaises(ValueError):
                self.prepare()
        self.fixture.released()

    def test_existing_pair_claim_refuses_without_observing_or_writing(self):
        boot.RUNTIME_ROOT.mkdir(mode=0o700)
        (boot.RUNTIME_ROOT / "profile.json").write_bytes(
            boot.state.canonical(boot.PROFILE)
        )
        (boot.RUNTIME_ROOT / "profile.json").chmod(0o600)
        boot.claim_path(self.request).mkdir(mode=0o700)
        before = self.files()
        with mock.patch.object(boot.reconcile, "status") as status:
            with self.assertRaises(ValueError):
                self.prepare()
        status.assert_not_called()
        self.assertEqual(before, self.files())

    def test_history_seal_rejects_symlink_or_group_writable_record(self):
        path = self.publisher / "intent.json"
        path.chmod(0o660)
        with self.assertRaises(ValueError):
            self.prepare()
        path.unlink()
        path.symlink_to(self.publisher / "complete.json")
        with self.assertRaises((ValueError, OSError)):
            self.prepare()
        self.assertFalse(boot.RUNTIME_ROOT.exists())

    def test_archived_legacy_guard_keeps_its_original_readable_or_private_mode(self):
        path = self.recovery / "legacy-guard.py"
        path.write_bytes(b"# original immutable legacy program\n")
        for mode in (0o600, 0o644):
            path.chmod(mode)
            self.accepted["publication"]["files"][str(path)] = {
                "path": str(path),
                "sha256": boot.state.sha256(path.read_bytes()),
                "identity": list(boot.observe.stable(path.lstat())),
            }
            with self.subTest(mode=mode):
                prepared = self.prepare()
                self.assertEqual(
                    prepared["history"]["files"][str(path)],
                    self.accepted["publication"]["files"][str(path)],
                )
        path.chmod(0o664)
        with self.assertRaises(ValueError):
            self.prepare()


if __name__ == "__main__":
    unittest.main()
