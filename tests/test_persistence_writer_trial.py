"""Prepare one claimed application test from the actual modeled boot journal."""

import copy
from contextlib import contextmanager
from contextlib import closing
import os
from pathlib import Path
import sys
import sqlite3
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_writer_trial as trial,
)
import test_persistence_retained_boot_execution as boot_fixture


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class WriterPreparationTests(unittest.TestCase):
    def setUp(self):
        self.parent = boot_fixture.BootExecutionTests("runTest")
        self.parent.setUp()
        self.addCleanup(self.parent.doCleanups)
        self.completed = self.parent.run_boot()
        self.request, self.profile = (
            self.parent.request,
            self.parent.base.fixture.profile,
        )
        self.fixture = self.parent.fixture
        self.root = self.fixture.root
        patch = mock.patch.object(
            trial, "RUNTIME_ROOT", self.root / "owner-history/writer-trial"
        )
        patch.start()
        self.addCleanup(patch.stop)
        self.nonce = "e" * 32
        self.complete_sha = self.completed["completion_sha256"]

    def prepare(self, **changes):
        self.fixture.events.clear()
        arguments = {
            "boot_raw": self.parent.raw,
            "boot_sha256": self.parent.sha,
            "boot_completion_sha256": self.complete_sha,
            "nonce": self.nonce,
        }
        arguments.update(changes)
        return trial.prepare(**arguments)

    def test_prepare_is_read_only_and_pure_decoder_does_not_run_native(self):
        before = {
            str(p): p.read_bytes()
            for p in (self.root / "owner-history").rglob("*")
            if p.is_file()
        }
        result = self.prepare()
        raw = trial.state.canonical(result)
        with mock.patch.object(
            trial.boot, "status", side_effect=AssertionError("pure load")
        ), mock.patch.object(
            trial.runtime.observe, "native", side_effect=AssertionError("pure load")
        ):
            self.assertEqual(
                trial.decode_prepared(raw, trial.state.sha256(raw)), result
            )
        self.assertFalse(trial.RUNTIME_ROOT.exists())
        self.assertEqual(
            before,
            {
                str(p): p.read_bytes()
                for p in (self.root / "owner-history").rglob("*")
                if p.is_file()
            },
        )
        self.assertEqual(result["runtime_identity"]["application"]["record_count"], 1)
        self.assertNotIn("uptime", result["runtime_identity"]["guest"]["runtime"])
        self.fixture.released()

    def test_prepared_bytes_stay_equal_when_only_uptime_increases(self):
        first = self.prepare()
        self.fixture.value["guest"]["runtime"]["uptime"] += 50
        self.assertEqual(self.prepare(), first)
        self.fixture.released()

    def test_wrong_boot_completion_or_nonce_refuses_without_claim(self):
        for change in (
            {"boot_completion_sha256": "0" * 64},
            {"nonce": True},
            {"nonce": "invalid"},
        ):
            with self.subTest(change=change), self.assertRaises(
                trial.state.PersistenceError
            ):
                self.prepare(**change)
        self.assertFalse(trial.RUNTIME_ROOT.exists())
        self.fixture.released()

    def test_old_boot_history_mutation_during_final_observation_refuses(self):
        original = trial._quiesced
        target = trial.boot.claim_path(self.request) / "guard-result.json"

        @contextmanager
        def mutate(*args):
            with original(*args) as result:
                yield result
                target.write_bytes(target.read_bytes() + b" ")

        with mock.patch.object(trial, "_quiesced", side_effect=mutate):
            with self.assertRaises(trial.state.PersistenceError):
                self.prepare()
        self.assertFalse(trial.RUNTIME_ROOT.exists())
        self.fixture.released()

    def test_application_exclusion_spans_closing_history_reads(self):
        original = trial._history
        calls = []

        def history(*args):
            calls.append(True)
            if len(calls) > 1:
                self.fixture.scopes(True)
            return original(*args)

        with mock.patch.object(trial, "_history", side_effect=history):
            self.prepare()
        self.assertGreaterEqual(len(calls), 2)
        self.fixture.released()

    def test_existing_or_unknown_trial_runtime_refuses_without_reuse(self):
        trial.RUNTIME_ROOT.mkdir(mode=0o700)
        (trial.RUNTIME_ROOT / "profile.json").write_bytes(b"{}")
        (trial.RUNTIME_ROOT / "profile.json").chmod(0o600)
        with self.assertRaises(trial.state.PersistenceError):
            self.prepare()

    def test_late_database_change_during_closing_history_refuses(self):
        original = trial._history
        calls = []

        def history(*args):
            value = original(*args)
            calls.append(True)
            if len(calls) == 2:
                with closing(
                    sqlite3.connect(self.fixture.database)
                ) as database, database:
                    database.execute(
                        "INSERT INTO entries VALUES (2,?,?)",
                        ("f" * 32, "late external write"),
                    )
            return value

        with mock.patch.object(trial, "_history", side_effect=history):
            with self.assertRaises(trial.state.PersistenceError):
                self.prepare()
        self.assertFalse(trial.RUNTIME_ROOT.exists())
        self.fixture.released()

    def test_dangling_runtime_path_is_not_an_unused_operation(self):
        trial.RUNTIME_ROOT.symlink_to(self.root / "nonexistent")
        with self.assertRaises((trial.state.PersistenceError, OSError)):
            self.prepare()

    def test_pure_decoder_requires_exact_parent_and_boot_history_membership(self):
        prepared = self.prepare()
        for fault in (
            "empty",
            "boot-profile",
            "boot-file",
            "extra",
            "profile-mismatch",
            "application",
        ):
            value = copy.deepcopy(prepared)
            history = value["history"]
            if fault == "empty":
                value["history"] = {"directories": {}, "files": {}}
            elif fault == "boot-profile":
                history["files"].pop(str(trial.boot.RUNTIME_ROOT / "profile.json"))
            elif fault == "boot-file":
                history["directories"][str(trial.boot.claim_path(self.request))][
                    "files"
                ].pop("guard-result.json")
            elif fault == "extra":
                history["files"]["/unexpected"] = copy.deepcopy(
                    next(iter(history["files"].values()))
                )
                history["files"]["/unexpected"]["path"] = "/unexpected"
            elif fault == "profile-mismatch":
                value["boot_runtime"]["file"]["sha256"] = "0" * 64
            else:
                value["runtime_identity"]["application"]["record_count"] += 1
            raw = trial.state.canonical(value)
            with self.subTest(fault=fault), self.assertRaises(
                trial.state.PersistenceError
            ):
                trial.decode_prepared(raw, trial.state.sha256(raw))


if __name__ == "__main__":
    unittest.main()
