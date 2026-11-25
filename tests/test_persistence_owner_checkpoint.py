"""An accepted historical checkpoint is not a current admission or permission."""

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
    persistence_owner_checkpoint as checkpoint,
    persistence_writer_execution as execution,
)
import test_persistence_writer_execution as lifecycle


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class OwnerCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.base = lifecycle.WriterExecutionTests("runTest")
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        patch = mock.patch.object(checkpoint, "ROOT_UID", os.geteuid())
        patch.start()
        self.addCleanup(patch.stop)
        frame = self.base.prepared["runtime_identity"]
        init = frame["kernel"]["init"]
        mapping = self.base.request["policy"]["mapping"]
        self.base.peer = {
            "pid": init["pid"] + 5,
            "birth": init["pstart"] + 1,
            "pid_namespace": init["pid_namespace_inode"],
            "mount_namespace": 9000,
            "uid": mapping["offset"] + mapping["uid"],
            "gid": mapping["offset"] + mapping["gid"],
            "nspid": [init["pid"] + 5, 321],
            "root": [os.makedev(*frame["kernel"]["rootfs"]["device"]), 2],
            "executable": [1, 555],
            "argv": list(execution.active.process.ARGV),
            "cgroup": frame["kernel"]["cgroup"]["path"].rsplit("/", 1)[0]
            + "/system.slice/reference-ledger.service\n",
        }
        result = self.base.run_trial()
        self.completed = {
            key: value for key, value in result.items() if key != "completion_sha256"
        }
        path = execution.trial.claim_path(self.base.request)
        self.records = {name: (path / name).read_bytes() for name in execution.NAMES}
        # Private temporary journals belong to the test user. Only this test
        # substitutes that UID for the public codec's fixed native root UID.
        self.seal()

    def test_rehashed_malformed_ancestor_metadata_is_not_portable_authority(self):
        for fault in ("boot-directory", "boot-profile", "history-directory"):
            previous, previous_records = copy.deepcopy(self.completed), dict(
                self.records
            )
            prepared = copy.deepcopy(self.base.prepared)
            if fault == "boot-directory":
                prepared["boot_runtime"]["directory"] = [0] * 5
            elif fault == "boot-profile":
                prepared["boot_runtime"]["file"]["identity"][2] |= 0o066
                path = prepared["boot_runtime"]["file"]["path"]
                prepared["history"]["files"][path]["identity"][2] |= 0o066
            else:
                path = str(execution.boot.claim_path(prepared["source_request"]))
                prepared["history"]["directories"][path]["identity"][2] |= 0o077
            raw = execution.state.canonical(prepared)
            checksum = execution.state.sha256(raw)
            self.completed["prepared_sha256"] = checksum
            intent = json.loads(self.records["intent.json"])
            intent["prepared_sha256"] = checksum
            self.records["intent.json"] = execution.state.canonical(intent)
            item = self.completed["journal_files"]["intent.json"]
            item["sha256"] = execution.state.sha256(self.records["intent.json"])
            item["identity"][6] = len(self.records["intent.json"])
            self.seal()
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.load(prepared_raw=raw, prepared_sha256=checksum)
            self.completed, self.records = previous, previous_records
            self.seal()

    def seal(self):
        self.completed["phase_journal_sha256"] = execution.state.sha256(
            execution.state.canonical(self.completed["journal_files"])
        )
        self.raw = execution.state.canonical(self.completed)
        self.sha = execution.state.sha256(self.raw)
        self.records["complete.json"] = self.raw

    def load(self, **changes):
        args = dict(
            prepared_raw=self.base.raw,
            prepared_sha256=self.base.sha,
            completion_raw=self.raw,
            completion_sha256=self.sha,
            records=self.records,
        )
        args.update(changes)
        return checkpoint.load_writer_checkpoint(**args)

    def test_accepts_exact_app2_without_current_access_or_mutating_inputs(self):
        before = copy.deepcopy((self.completed, self.records))
        with mock.patch.object(
            execution, "status", side_effect=AssertionError("current status")
        ), mock.patch.object(
            execution.runtime.observe, "native", side_effect=AssertionError("native")
        ), mock.patch.object(
            execution.backup, "read_private", side_effect=AssertionError("file read")
        ):
            result = self.load()
        self.assertEqual(
            result["completion"]["runtime"]["application"]["record_count"], 2
        )
        self.assertEqual(result["completion_sha256"], self.sha)
        self.assertEqual(before, (self.completed, self.records))
        self.assertEqual(self.base.actions, ["start", "stop"])

    def test_external_hashes_and_complete_raw_bytes_are_mandatory(self):
        for change in (
            {"prepared_sha256": "f" * 64},
            {"completion_sha256": "f" * 64},
            {"completion_raw": self.raw + b" "},
            {"completion_sha256": True},
        ):
            with self.subTest(change=list(change)), self.assertRaises(ValueError):
                self.load(**change)

    def test_missing_extra_or_changed_raw_record_is_not_a_checkpoint(self):
        for fault in ("missing", "extra", "changed", "nonbytes"):
            records = dict(self.records)
            if fault == "missing":
                records.pop("before-read.json")
            elif fault == "extra":
                records["failed.json"] = b"{}"
            elif fault == "changed":
                records["append-result.json"] = b"{}"
            else:
                records["append-result.json"] = "{}"
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.load(records=records)

    def test_rehashed_false_flags_or_changed_app2_refuse(self):
        for fault in ("flag", "credential", "count", "phase"):
            with self.subTest(fault=fault):
                previous = copy.deepcopy(self.completed)
                if fault == "flag":
                    self.completed["rebuild_verified"] = False
                elif fault == "credential":
                    self.completed["runtime"]["application"]["config_sha256"] = "f" * 64
                elif fault == "count":
                    self.completed["runtime"]["application"]["record_count"] = 1
                else:
                    self.completed["phase"] = "retained-os-quiesced"
                self.seal()
                with self.assertRaises(ValueError):
                    self.load()
                self.completed = previous
                self.seal()

    def test_rehashed_impossible_peer_cannot_be_made_valid_by_repeating_it(self):
        self.completed["peer"]["uid"] = 0
        for name in ("stop-admission.json", "stop-dispatch.json"):
            value = json.loads(self.records[name])
            value["peer"]["uid"] = 0
            self.records[name] = execution.state.canonical(value)
            item = self.completed["journal_files"][name]
            item["sha256"] = execution.state.sha256(self.records[name])
            item["identity"][6] = len(self.records[name])
        self.seal()
        with self.assertRaises(ValueError):
            self.load()

    def test_rehashed_boolean_or_permissive_native_metadata_refuses(self):
        for fault in ("bool", "mode", "directory", "profile"):
            previous = copy.deepcopy(self.completed)
            item = self.completed["journal_files"]["intent.json"]
            if fault == "bool":
                item["identity"][1] = True
            elif fault == "mode":
                item["identity"][2] |= 0o020
            elif fault == "directory":
                self.completed["claim_directory_identity"] = [0] * 5
            else:
                self.completed["runtime_profile"]["file"]["identity"][2] |= 0o020
            self.seal()
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.load()
            self.completed = previous
            self.seal()


if __name__ == "__main__":
    unittest.main()
