"""Forward work admits only the preserved pre-retirement guard-refusal stage."""

import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_reconcile as reconcile,
    persistence_owner_publish as original,
    persistence_state as state,
)
import test_persistence_owner_publish as publisher_tests


@unittest.skipUnless(
    os.environ.get("CMDMESH_HANDOFF_GUARD_SOURCE")
    and os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"),
    "provide both pinned standalone guards",
)
class ForwardPolicyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = publisher_tests.PublicationFilesystemTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.guard_raw = Path(
            os.environ["CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"]
        ).read_bytes()
        self.guard = reconcile.load_guard_source(self.guard_raw)
        self.raw, self.sha = self.fixture.prepared()
        self.parent = json.loads(self.raw)
        with mock.patch.object(
            original,
            "guard_cli",
            side_effect=state.PersistenceError(
                "persistence-owner-publish-guard-refused"
            ),
        ):
            with self.assertRaises(state.PersistenceError):
                original.apply(self.raw, self.sha, self.fixture.guard_raw)
        self.directory = original.claim_path(self.fixture.request)
        self.records = {
            name: (self.directory / name).read_bytes()
            for name in reconcile.PARENT_RECORDS
        }
        patch = mock.patch.object(
            reconcile, "RUNTIME_ROOT", self.fixture.managed / "reconciliation"
        )
        patch.start()
        self.addCleanup(patch.stop)

    def test_known_failure_has_exact_intent_and_raw_record_hashes(self):
        digest, stage = reconcile.validate_failure_records(
            self.parent, self.sha, self.records
        )
        self.assertEqual(
            digest,
            state.sha256(
                state.canonical(
                    {name: state.sha256(raw) for name, raw in self.records.items()}
                )
            ),
        )
        self.assertEqual(stage, json.loads(self.records["stage-result.json"]))
        self.assertEqual(self.parent, json.loads(self.raw))

    def test_other_failure_phase_missing_or_changed_dispatch_refuses(self):
        for fault in ("missing", "complete", "reason", "dispatch", "intent"):
            records = dict(self.records)
            if fault == "missing":
                del records["guard-dispatch.json"]
            elif fault == "complete":
                records["complete.json"] = b"{}"
            elif fault == "reason":
                records["failed.json"] = state.canonical(
                    {"error_code": "persistence-owner-publish-source-changed"}
                )
            elif fault == "dispatch":
                records["guard-dispatch.json"] = state.canonical(
                    {"argv": ["/wrong/program"]}
                )
            else:
                records["intent.json"] = state.canonical(
                    {"prepared": self.parent, "prepared_sha256": "f" * 64}
                )
            with self.subTest(fault=fault), self.assertRaises(state.PersistenceError):
                reconcile.validate_failure_records(self.parent, self.sha, records)

    def test_new_source_changes_only_the_known_reference(self):
        source = reconcile.source_from(self.parent, self.guard)
        expected = copy.deepcopy(self.parent["source_request"])
        expected["reference_guard"] = {
            "path": str(reconcile.claim_path(self.parent) / "guard.py"),
            "sha256": reconcile.GUARD_SHA,
        }
        self.assertEqual(source, expected)
        self.assertEqual(source["policy"], self.parent["policy"])
        self.assertEqual(self.parent, json.loads(self.raw))

    def test_reconciliation_controls_cannot_live_inside_retained_datasets(self):
        root = Path(self.parent["policy"]["datasets"]["data"]["mountpoint"])
        with mock.patch.object(reconcile, "RUNTIME_ROOT", root / "unsafe"):
            with self.assertRaises(state.PersistenceError):
                reconcile.source_from(self.parent, self.guard)

    def test_unknown_guard_source_cannot_execute(self):
        with self.assertRaises(state.PersistenceError):
            reconcile.load_guard_source(b"raise RuntimeError('must not execute')\n")


@unittest.skipUnless(
    os.environ.get("CMDMESH_HANDOFF_GUARD_SOURCE")
    and os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"),
    "provide both pinned standalone guards",
)
class ForwardPreparationTests(unittest.TestCase):
    def setUp(self):
        self.model = ForwardPolicyTests("runTest")
        self.model.setUp()
        self.addCleanup(self.model.doCleanups)
        self.fixture = self.model.fixture
        self.checksum = state.sha256(
            state.canonical(
                {name: state.sha256(raw) for name, raw in self.model.records.items()}
            )
        )
        old_loader = reconcile.load_guard_source

        def loaded(raw):
            guard = old_loader(raw)
            guard.owner_path.__globals__["OWNERS_ROOT"] = (
                self.fixture.managed / "owners"
            )
            return guard

        for patch in (
            mock.patch.object(reconcile, "load_guard_source", side_effect=loaded),
            mock.patch.object(reconcile, "probe_candidate", side_effect=self.probe),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def probe(self, *args):
        self.fixture.assert_both_leased()
        self.assertTrue(self.fixture.app_locked)
        return {
            "exit_code": 0,
            "payload": {"outcome": "qualified"},
            "stderr_bytes": 0,
            "stdout_sha256": state.sha256(b'{"outcome":"qualified"}\n'),
            "stderr_sha256": state.sha256(b""),
        }

    def prepare(self):
        return reconcile.prepare(
            self.model.raw, self.model.sha, self.checksum, self.model.guard_raw
        )

    def test_prepared_source_rejects_boolean_and_float_integer_fields(self):
        for field, replacement in (
            ("schema_version", True),
            ("count", True),
            ("count", 1.0),
        ):
            prepared = self.prepare()
            if field == "schema_version":
                prepared["source_request"][field] = replacement
            else:
                prepared["source_request"]["policy"]["cpu_policy"][field] = replacement
            raw = state.canonical(prepared)
            with self.subTest(field=field, replacement=replacement), self.assertRaises(
                state.PersistenceError
            ):
                reconcile.load_prepared(raw, state.sha256(raw), self.model.guard)

    def test_preparation_keeps_parent_owner_denials_and_creates_no_reconciliation_files(
        self,
    ):
        controls = self.fixture.controls()
        before = {
            path.name: path.read_bytes() for path in self.model.directory.iterdir()
        }
        value = self.prepare()
        self.assertEqual(value["parent_failure_sha256"], self.checksum)
        self.assertEqual(value["source_before"], self.fixture.old_facts)
        self.assertEqual(
            value["source_request"]["reference_guard"]["sha256"], reconcile.GUARD_SHA
        )
        self.assertFalse(reconcile.RUNTIME_ROOT.exists())
        self.assertEqual(controls, self.fixture.controls())
        self.assertEqual(
            before,
            {path.name: path.read_bytes() for path in self.model.directory.iterdir()},
        )

    def test_wrong_parent_journal_refuses_before_candidate_execution(self):
        changed = {"error_code": "persistence-owner-publish-completion-state-changed"}
        (self.model.directory / "failed.json").write_bytes(state.canonical(changed))
        with self.assertRaises(state.PersistenceError):
            self.prepare()
        reconcile.probe_candidate.assert_not_called()
        self.assertFalse(reconcile.RUNTIME_ROOT.exists())

    def test_extra_parent_marker_refuses_before_candidate_execution(self):
        (self.model.directory / "retire-dispatch.json").write_bytes(b"{}")
        with self.assertRaises(state.PersistenceError):
            self.prepare()
        reconcile.probe_candidate.assert_not_called()

    def test_changed_source_refuses_before_creating_a_claim(self):
        self.fixture.application["record_count"] += 1
        with self.assertRaises(state.PersistenceError):
            self.prepare()
        self.assertFalse(reconcile.RUNTIME_ROOT.exists())

    def test_changed_owner_record_refuses_before_candidate_execution(self):
        path = self.fixture.guard.owner_path(self.model.parent["policy"])
        path.write_bytes(b"{}")
        with self.assertRaises(state.PersistenceError):
            self.prepare()
        reconcile.probe_candidate.assert_not_called()

    def test_parent_journal_change_during_the_last_native_query_refuses(self):
        generated = original.current_generated
        count = 0

        def queried(request):
            nonlocal count
            result = generated(request)
            count += 1
            if count == 3:
                (self.model.directory / "failed.json").write_bytes(
                    state.canonical({"error_code": "changed-after-read"})
                )
            return result

        with mock.patch.object(original, "current_generated", side_effect=queried):
            with self.assertRaises(state.PersistenceError):
                self.prepare()

    def test_legacy_reference_change_during_the_last_native_query_refuses(self):
        generated = original.current_generated
        count = 0

        def queried(request):
            nonlocal count
            result = generated(request)
            count += 1
            if count == 3:
                self.fixture.legacy.write_bytes(original.RETIRED_STUB)
            return result

        with mock.patch.object(original, "current_generated", side_effect=queried):
            with self.assertRaises(state.PersistenceError):
                self.prepare()

    def test_changed_parent_runtime_profile_refuses_before_candidate_execution(self):
        (original.RUNTIME_ROOT / "profile.json").write_bytes(
            state.canonical({"document_type": "foreign", "schema_version": 1})
        )
        with self.assertRaises(state.PersistenceError):
            self.prepare()
        reconcile.probe_candidate.assert_not_called()


@unittest.skipUnless(
    os.environ.get("CMDMESH_HANDOFF_GUARD_SOURCE")
    and os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"),
    "provide both pinned standalone guards",
)
class ForwardPublicationTests(unittest.TestCase):
    def setUp(self):
        self.base = ForwardPreparationTests("runTest")
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.fixture = self.base.fixture
        self.prepared = self.base.prepare()
        self.raw = state.canonical(self.prepared)
        self.sha = state.sha256(self.raw)
        self.old_bytes = {
            path.name: path.read_bytes() for path in self.base.model.directory.iterdir()
        }
        for patch in (
            mock.patch.object(reconcile, "ROOT_UID", os.geteuid()),
            mock.patch.object(reconcile, "run_guard", side_effect=self.run_guard),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def run_guard(self, *args):
        self.fixture.assert_both_leased()
        self.assertTrue(self.fixture.app_locked)
        self.fixture.events.append("fixed-guard")
        return self.base.probe()

    def test_forward_publication_preserves_parent_owner_denials_and_lock_order(self):
        owner = self.fixture.guard.owner_path(self.base.model.parent["policy"])
        owner_before = original.file_info(owner)[0]
        self.fixture.events.clear()
        result = reconcile.apply(self.raw, self.sha, self.base.model.guard_raw)
        self.assertTrue(
            result["owner_reconciliation_verified"]
            and result["owner_publication_verified"]
            and result["legacy_source_refused"]
        )
        self.assertFalse(any(result[key] for key in original.FLAGS))
        self.assertEqual(self.fixture.legacy.read_bytes(), original.RETIRED_STUB)
        self.assertEqual(owner_before, original.file_info(owner)[0])
        self.assertEqual(
            self.old_bytes,
            {
                path.name: path.read_bytes()
                for path in self.base.model.directory.iterdir()
            },
        )
        self.assertIn("fixed-guard", self.fixture.events)
        self.assertEqual(
            self.fixture.events[self.fixture.events.index("enter3") - 1], "close2"
        )
        for control in self.fixture.controls().values():
            self.assertIn(original.attach.DENIAL_NAME, control["files"])
        observed = reconcile.status(self.raw, self.sha)
        self.assertEqual(result["completion_sha256"], observed["completion_sha256"])
        with self.assertRaises(state.PersistenceError):
            reconcile.apply(self.raw, self.sha, self.base.model.guard_raw)

    def test_refused_guard_result_is_retained_before_failure_and_legacy_is_not_retired(
        self,
    ):
        before = self.fixture.legacy.read_bytes()
        result = {
            **self.prepared["candidate_probe"],
            "exit_code": 1,
            "payload": {"outcome": "refused", "reason": "fixture-refusal"},
        }
        with mock.patch.object(reconcile, "run_guard", return_value=result):
            with self.assertRaises(state.PersistenceError):
                reconcile.apply(self.raw, self.sha, self.base.model.guard_raw)
        directory = reconcile.claim_path(self.base.model.parent)
        self.assertEqual(
            json.loads((directory / "guard-result.json").read_bytes()), result
        )
        self.assertTrue((directory / "failed.json").exists())
        self.assertEqual(self.fixture.legacy.read_bytes(), before)
        self.assertEqual(
            self.old_bytes,
            {
                path.name: path.read_bytes()
                for path in self.base.model.directory.iterdir()
            },
        )
        with self.assertRaises(state.PersistenceError):
            reconcile.apply(self.raw, self.sha, self.base.model.guard_raw)

    def test_installed_reference_loader_refusal_precedes_legacy_retirement(self):
        before = self.fixture.legacy.read_bytes()
        with mock.patch.object(
            reconcile.observe,
            "load_guard",
            side_effect=state.PersistenceError("persistence-guard-unsupported"),
        ):
            with self.assertRaises(state.PersistenceError):
                reconcile.apply(self.raw, self.sha, self.base.model.guard_raw)
        self.assertEqual(self.fixture.legacy.read_bytes(), before)
        self.assertFalse(any(reconcile.RUNTIME_ROOT.rglob("retire-dispatch.json")))

    def test_input_hash_refusal_precedes_all_filesystem_access(self):
        with mock.patch.object(reconcile, "load_parent") as parent, mock.patch.object(
            original, "file_info"
        ) as file:
            with self.assertRaises(state.PersistenceError):
                reconcile.apply(self.raw, "f" * 64, self.base.model.guard_raw)
        parent.assert_not_called()
        file.assert_not_called()

    def test_source_two_exit_error_keeps_legacy_reference_and_failed_claim(self):
        source = reconcile.observe.source_state
        before = self.fixture.legacy.read_bytes()

        @contextmanager
        def observed(request, **kwargs):
            with source(request, **kwargs) as value:
                yield value
            if (
                request["policy"]["schema_version"] == 2
                and reconcile.claim_path(self.base.model.parent).exists()
            ):
                raise state.PersistenceError("source-two-exit-failed")

        with mock.patch.object(reconcile.observe, "source_state", side_effect=observed):
            with self.assertRaises(state.PersistenceError):
                reconcile.apply(self.raw, self.sha, self.base.model.guard_raw)
        self.assertEqual(self.fixture.legacy.read_bytes(), before)
        self.assertTrue(
            (reconcile.claim_path(self.base.model.parent) / "failed.json").exists()
        )

    def test_owner_change_during_final_native_query_refuses_before_completion(self):
        generated = original.current_generated

        def queried(request):
            value = generated(request)
            if self.fixture.legacy.read_bytes() == original.RETIRED_STUB:
                self.fixture.guard.owner_path(
                    self.base.model.parent["policy"]
                ).write_bytes(b"{}")
            return value

        with mock.patch.object(original, "current_generated", side_effect=queried):
            with self.assertRaises(state.PersistenceError):
                reconcile.apply(self.raw, self.sha, self.base.model.guard_raw)
        directory = reconcile.claim_path(self.base.model.parent)
        self.assertTrue((directory / "failed.json").exists())
        self.assertFalse((directory / "complete.json").exists())

    def test_late_journal_damage_retains_complete_and_failed_but_never_success(self):
        write = reconcile.backup.write_private

        def written(path, value):
            result = write(path, value)
            if path.name == "complete.json":
                (path.parent / "guard-result.json").write_bytes(b"{}")
            return result

        with mock.patch.object(reconcile.backup, "write_private", side_effect=written):
            with self.assertRaises(state.PersistenceError):
                reconcile.apply(self.raw, self.sha, self.base.model.guard_raw)
        directory = reconcile.claim_path(self.base.model.parent)
        self.assertTrue((directory / "complete.json").exists())
        self.assertTrue((directory / "failed.json").exists())
        with self.assertRaises(state.PersistenceError):
            reconcile.status(self.raw, self.sha)
        with self.assertRaises(state.PersistenceError):
            reconcile.apply(self.raw, self.sha, self.base.model.guard_raw)

    def test_missing_target_result_cannot_be_a_completed_status(self):
        reconcile.apply(self.raw, self.sha, self.base.model.guard_raw)
        directory = reconcile.claim_path(self.base.model.parent)
        (directory / "target-1-result.json").unlink()
        with self.assertRaises((state.PersistenceError, OSError)):
            reconcile.status(self.raw, self.sha)

    def test_changed_reconciliation_runtime_profile_refuses_completed_status(self):
        reconcile.apply(self.raw, self.sha, self.base.model.guard_raw)
        (reconcile.RUNTIME_ROOT / "profile.json").write_bytes(b"{}")
        with self.assertRaises(state.PersistenceError):
            reconcile.status(self.raw, self.sha)

    def test_runtime_profile_change_during_completion_cannot_succeed(self):
        write = reconcile.backup.write_private

        def written(path, value):
            result = write(path, value)
            if path.name == "complete.json":
                (reconcile.RUNTIME_ROOT / "profile.json").write_bytes(b"{}")
            return result

        with mock.patch.object(reconcile.backup, "write_private", side_effect=written):
            with self.assertRaises(state.PersistenceError):
                reconcile.apply(self.raw, self.sha, self.base.model.guard_raw)
        directory = reconcile.claim_path(self.base.model.parent)
        self.assertTrue((directory / "failed.json").exists())

    def test_guard_spawn_error_is_recorded_without_private_exception_text(self):
        import errno

        before = self.fixture.legacy.read_bytes()
        with mock.patch.object(
            reconcile,
            "run_guard",
            side_effect=lambda prepared: reconcile.execute_guard(["/usr/bin/python3"]),
        ), mock.patch.object(
            reconcile.subprocess,
            "run",
            side_effect=OSError(errno.EAGAIN, "PRIVATE_SENTINEL"),
        ):
            with self.assertRaises(state.PersistenceError):
                reconcile.apply(self.raw, self.sha, self.base.model.guard_raw)
        directory = reconcile.claim_path(self.base.model.parent)
        result = json.loads((directory / "guard-result.json").read_bytes())
        self.assertIsNone(result["exit_code"])
        self.assertEqual(result["payload"]["errno"], errno.EAGAIN)
        self.assertNotIn("PRIVATE_", json.dumps(result))
        self.assertEqual(self.fixture.legacy.read_bytes(), before)
        self.assertTrue((directory / "failed.json").exists())
