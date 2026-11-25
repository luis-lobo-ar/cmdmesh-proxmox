"""Forward work admits only the preserved pre-retirement guard-refusal stage."""

import copy
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
