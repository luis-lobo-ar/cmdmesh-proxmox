"""Generating a new rootfs config does not permit a guest/application start."""

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
    persistence_blank_stage as stage,
    persistence_recipient as recipient,
    persistence_state as state,
)
import test_persistence_recipient as fixtures
import test_persistence_blank_guard as guard_fixtures


class BlankStageTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RecipientTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        policy, _ = guard_fixtures.model()
        self.fixture.after = {
            "vmid": 102,
            "config": policy["config"],
            "pending": [],
            "status": {"status": "stopped", "uptime": 0},
            "rootfs": {
                **policy["rootfs"],
                "volume": "local:102/vm-102-disk-0.raw",
                "identity": [*policy["rootfs"]["identity"], 1, 1],
            },
        }
        self.recipient_raw, self.recipient_sha = self.fixture.prepared()
        recipient.provision(self.recipient_raw, self.recipient_sha)
        self.units = self.root / "systemd"
        self.units.mkdir(mode=0o755)
        self.lxc = self.root / "lxc"
        self.lxc.mkdir(mode=0o700)
        self.generated = self.lxc / "102/config"
        self.generated.parent.mkdir(mode=0o700)
        self.calls = []
        for patch in (
            mock.patch.object(stage, "RUNTIME_ROOT", self.root / "managed/blank-stage"),
            mock.patch.object(stage, "UNIT_ROOT", self.units),
            mock.patch.object(stage, "LXC_ROOT", self.lxc),
            mock.patch.object(stage, "ROOT_UID", os.geteuid()),
            mock.patch.object(stage, "unit_facts", side_effect=self.unit_facts),
            mock.patch.object(stage, "native_generation", side_effect=self.generate),
            mock.patch.object(
                stage, "reload_units", side_effect=lambda: self.calls.append("reload")
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def unit_facts(self, request):
        result = {}
        for unit in stage.unit_names(request):
            file = stage.dropin_path(request, unit)
            result[unit] = {
                "LoadState": "loaded",
                "ActiveState": "inactive",
                "MainPID": "0",
                "DropInPaths": str(file) if file.exists() else "",
                "ExecStartPre": (
                    "{ path=/usr/bin/false ; argv[]=/usr/bin/false ; ignore_errors=no ; "
                    "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
                    if file.exists()
                    else ""
                ),
            }
        return result

    def generate(self, request, digest):
        self.assertTrue(self.fixture.inside_lock)
        self.assertTrue(any(stage.RUNTIME_ROOT.rglob("write-possible.json")))
        for unit in stage.unit_names(request):
            self.assertEqual(stage.dropin_path(request, unit).read_bytes(), stage.DENY)
        self.calls.append("generation")
        raw = (
            "lxc.rootfs.path = /var/lib/lxc/102/rootfs\n"
            "lxc.uts.name = reference-rebuilt\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cgroup2.cpu.max = 100000 100000\n"
            "lxc.cgroup2.cpuset.cpus = 0\n"
        ).encode()
        self.generated.write_bytes(raw)
        self.generated.chmod(0o600)
        return {"exit_code": 0, "stdout_sha256": state.sha256(b"null\n")}

    def prepared(self):
        value = stage.prepare(self.recipient_raw, self.recipient_sha)
        raw = state.canonical(value)
        return raw, state.sha256(raw)

    def test_prepare_is_readonly_and_binds_the_entire_stopped_recipient(self):
        raw, sha = self.prepared()
        prepared = stage.load_prepared(raw, sha)
        self.assertEqual(prepared["target"], self.fixture.after)
        self.assertFalse(stage.RUNTIME_ROOT.exists())
        self.assertFalse(self.generated.exists())
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.units.iterdir()), [])

    def test_stage_denies_both_units_before_generation_and_never_starts(self):
        raw, sha = self.prepared()
        with mock.patch.object(recipient, "post_guest_action") as post:
            result = stage.apply(raw, sha)
            observed = stage.status(raw, sha)
        post.assert_not_called()
        self.assertTrue(result["denied_generation_verified"])
        self.assertFalse(
            result["boot_verified"]
            or result["rebuild_verified"]
            or result["restore_verified"]
        )
        self.assertEqual(result["generated"], observed["generated"])
        self.assertEqual(
            state.sha256(result["generated"]["text"].encode()),
            result["generated"]["sha256"],
        )
        self.assertEqual(self.calls, ["reload", "generation"])
        self.assertTrue(any(stage.RUNTIME_ROOT.rglob("complete.json")))
        with self.assertRaises(state.PersistenceError):
            stage.apply(raw, sha)
        self.assertEqual(self.calls, ["reload", "generation"])

    def test_foreign_dropins_or_existing_generated_config_refuse_before_claim(self):
        for which in ("dropin", "generated"):
            if which == "dropin":
                path = stage.dropin_path(
                    self.fixture.request, stage.unit_names(self.fixture.request)[0]
                ).parent
                path.mkdir()
            else:
                path.rmdir()
                self.generated.write_bytes(b"foreign\n")
            with self.assertRaises(state.PersistenceError):
                self.prepared()
        self.assertFalse(stage.RUNTIME_ROOT.exists())
        self.assertEqual(self.calls, [])

    def test_target_drift_refuses_before_writes(self):
        raw, sha = self.prepared()
        self.fixture.after["config"]["description"] += " changed"
        with self.assertRaises(state.PersistenceError):
            stage.apply(raw, sha)
        self.assertFalse(stage.RUNTIME_ROOT.exists())
        self.assertEqual(self.calls, [])

    def test_generation_failure_leaves_denials_and_consumed_intent_no_retry(self):
        raw, sha = self.prepared()
        with mock.patch.object(
            stage, "native_generation", side_effect=OSError("failure")
        ):
            with self.assertRaises(OSError):
                stage.apply(raw, sha)
        self.assertTrue(any(stage.RUNTIME_ROOT.rglob("failed.json")))
        self.assertFalse(any(stage.RUNTIME_ROOT.rglob("complete.json")))
        for unit in stage.unit_names(self.fixture.request):
            self.assertEqual(
                stage.dropin_path(self.fixture.request, unit).read_bytes(), stage.DENY
            )
        with self.assertRaises(state.PersistenceError):
            stage.apply(raw, sha)

    def test_bad_generated_quota_never_becomes_verified(self):
        raw, sha = self.prepared()
        generate = self.generate

        def bad(request, digest):
            result = generate(request, digest)
            self.generated.write_bytes(
                self.generated.read_bytes().replace(b"100000 100000", b"max 100000")
            )
            return result

        with mock.patch.object(stage, "native_generation", side_effect=bad):
            with self.assertRaises(ValueError):
                stage.apply(raw, sha)
        self.assertFalse(any(stage.RUNTIME_ROOT.rglob("complete.json")))

    def test_status_rejects_changed_generated_bytes_and_never_rewrites_journal(self):
        raw, sha = self.prepared()
        stage.apply(raw, sha)
        before = {
            str(path): path.read_bytes() for path in stage.RUNTIME_ROOT.rglob("*.json")
        }
        stage.status(raw, sha)
        self.assertEqual(
            before,
            {
                str(path): path.read_bytes()
                for path in stage.RUNTIME_ROOT.rglob("*.json")
            },
        )
        with self.generated.open("ab") as stream:
            stream.write(b"lxc.apparmor.profile = unconfined\n")
        with self.assertRaises(state.PersistenceError):
            stage.status(raw, sha)
        self.assertEqual(
            before,
            {
                str(path): path.read_bytes()
                for path in stage.RUNTIME_ROOT.rglob("*.json")
            },
        )

    def test_closing_target_change_prevents_complete_record(self):
        raw, sha = self.prepared()
        original = recipient.observe.source_state
        from contextlib import contextmanager

        @contextmanager
        def changed(*args, **kwargs):
            with original(*args, **kwargs) as facts:
                yield facts
            if self.generated.exists():
                self.fixture.after["status"] = {
                    "status": "running",
                    "pid": 111,
                    "uptime": 1,
                }

        with mock.patch.object(recipient.observe, "source_state", side_effect=changed):
            with self.assertRaises(state.PersistenceError):
                stage.apply(raw, sha)
        self.assertFalse(any(stage.RUNTIME_ROOT.rglob("complete.json")))

    def test_incomplete_rehashed_preparation_is_not_authority(self):
        raw, sha = self.prepared()
        for key in ("target", "units"):
            value = json.loads(raw)
            value[key] = {}
            invalid = state.canonical(value)
            with self.assertRaises(state.PersistenceError):
                stage.load_prepared(invalid, state.sha256(invalid))


if __name__ == "__main__":
    unittest.main()
