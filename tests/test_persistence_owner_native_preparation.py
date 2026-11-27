"""Preparation is inert; actual local journals/locks with modeled current/source."""

import copy
import importlib
import os
import unittest
from unittest import mock

import test_persistence_owner_native_initialization as fixtures
from test_persistence_owner_phase_admission import admission_inputs


class NativePreparationBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.n = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils."
            "persistence_owner_native_executor"
        )

    def test_wrong_admission_refuses_before_any_lease(self):
        with mock.patch.object(
            self.n, "_leased", side_effect=AssertionError("lease IO")
        ):
            with self.assertRaises(ValueError):
                self.n.prepare(
                    admission=object(), kind="shutdown", accepted_head_sha256="0" * 64
                )
            with self.assertRaises(ValueError):
                self.n.inspect_transition(
                    admission=object(), prepared_raw=b"{}", prepared_sha256="0" * 64
                )

    def test_invalid_kind_mode_and_missing_resume_prior_refuse_before_evidence(self):
        codec = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils."
            "persistence_owner_native_admission"
        )
        sentinel = object.__new__(codec.NativeAdmission)
        with mock.patch.object(
            self.n, "_leased", side_effect=AssertionError("lease IO")
        ):
            for changes in (
                dict(kind="start"),
                dict(check_mode=0),
                dict(kind="resume"),
            ):
                arguments = dict(
                    admission=sentinel, kind="shutdown", accepted_head_sha256="0" * 64
                )
                arguments.update(changes)
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    self.n.prepare(**arguments)


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class NativePreparationTests(fixtures._InitializationFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.storage._initialize_journal(self.binding)
        self.store = dict(
            source="storage.invalid:/reference",
            target="/reference",
            fstype="nfs",
            options=["hard", "rw", "vers=3"],
        )
        self.enterContext(
            mock.patch.object(self.n.observe, "mount_facts", return_value=self.store)
        )

    def prepare(self, **changes):
        arguments = dict(
            admission=self.admission, kind="shutdown", accepted_head_sha256=self.genesis
        )
        arguments.update(changes)
        return self.n.prepare(**arguments)

    def test_prepare_and_reinspect_keep_journal_and_original_handoff_unchanged(self):
        before = self.native_files()
        prepared = self.prepare(check_mode=True)
        body = self.f.r.observe.decode(prepared.raw)
        self.assertTrue(body["candidate_only"])
        self.assertFalse(body["native_action_dispatched"])
        self.assertEqual(body["predecessor_sha256"], self.genesis)
        self.assertEqual(
            body["uptime_floor"],
            body["before_current"]["observation"]["guest"]["runtime"]["uptime"],
        )
        inspected = self.n.inspect_transition(
            admission=self.admission,
            prepared_raw=prepared.raw,
            prepared_sha256=prepared.sha256,
        )
        report = self.f.r.observe.decode(inspected.raw)
        self.assertEqual(report["prepared_sha256"], prepared.sha256)
        self.assertTrue(report["preconditions_observed"])
        self.assertFalse(report["native_action_dispatched"])
        self.assertEqual(self.native_files(), before)
        self.assertEqual(self.old_complete.read_bytes(), self.old_bytes)
        with mock.patch.object(
            self.n, "_leased", side_effect=AssertionError("lease IO")
        ):
            for fault in ("hash", "flag", "schema", "source", "floor"):
                bad = copy.deepcopy(body)
                if fault == "flag":
                    bad["native_action_dispatched"] = True
                elif fault == "schema":
                    bad["schema_version"] = True
                elif fault == "source":
                    bad["native_admission_sha256"] = "0" * 64
                elif fault == "floor":
                    bad["uptime_floor"] -= 1
                raw = self.f.r.state.canonical(bad)
                digest = "0" * 64 if fault == "hash" else self.f.r.state.sha256(raw)
                with self.subTest(fault=fault), self.assertRaises(ValueError):
                    self.n.inspect_transition(
                        admission=self.admission,
                        prepared_raw=raw,
                        prepared_sha256=digest,
                    )

    def test_resume_preparation_binds_stopped_phase_and_explicit_running_prior(self):
        evidence, entry, prior = admission_inputs(self.f.model.case.model, "stopped")
        for frame in (evidence["observation"], entry, prior):
            frame["host"].update(self.f.entry["host"])
        raw = self.f.r.state.canonical(prior)
        with mock.patch.object(self.f, "evidence", evidence), mock.patch.object(
            self.f, "entry", entry
        ):
            prepared = self.prepare(
                kind="resume",
                prior_runtime_raw=raw,
                prior_runtime_sha256=self.f.r.state.sha256(raw),
            )
        body = self.f.r.observe.decode(prepared.raw)
        self.assertEqual(body["kind"], "resume")
        self.assertEqual(body["before_current"]["phase"], "stopped")
        self.assertEqual(body["prior_runtime"], prior)
        self.assertIsNone(body["init_identity"])
        self.assertFalse(body["native_action_dispatched"])

    def test_pending_journal_refuses_without_advancing_or_posting(self):
        pending = self.n.journal._begin(
            self.binding, self.genesis, "shutdown", "a" * 64
        )
        before = self.native_files()
        with self.assertRaises(ValueError):
            self.prepare(accepted_head_sha256=pending.pending_head_sha256)
        self.assertEqual(self.native_files(), before)

    def test_late_native_head_write_prevents_preparation_export(self):
        original = self.f.executor._post_worker
        path = self.n.journal.RUNTIME_ROOT / self.binding.pair_key / "HEAD.json"
        mutations = []

        def late(*args):
            original(*args)
            if self.f.worker == 2:
                self.f.samebyte(path)
                mutations.append(str(path))

        with mock.patch.object(self.f.executor, "_post_worker", side_effect=late):
            with self.assertRaises(ValueError):
                self.prepare()
        self.assertEqual(len(mutations), 1)

    def test_final_current_failure_prevents_preparation_export(self):
        self.f.fault = "second-worker-exit"
        before = self.native_files()
        with self.assertRaisesRegex(ValueError, "modeled final worker failure"):
            self.prepare()
        self.assertEqual(self.native_files(), before)


if __name__ == "__main__":
    unittest.main()
