"""One guarded blank OS start is distinct from application rebuild/recovery."""

from contextlib import contextmanager
import copy
import os
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_blank_boot as boot,
    persistence_blank_stage as stage,
    persistence_recipient as recipient,
    persistence_state as state,
)
import test_persistence_blank_stage as stage_fixture
import test_persistence_blank_runtime as runtime_fixture


class BlankBootTests(unittest.TestCase):
    def setUp(self):
        self.fixture = stage_fixture.BlankStageTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.stage_raw, self.stage_sha = self.fixture.prepared()
        self.completed = stage.apply(self.stage_raw, self.stage_sha)
        self.completion_sha = self.completed["completion_sha256"]
        self.running = False
        self.runtime = None
        self.posts = []
        self.reloaded = []
        self.executed_at = int(time.time())
        self.task = {
            **self.fixture.fixture.task,
            "upid": self.fixture.fixture.task["upid"].replace("vzcreate", "vzstart"),
            "type": "vzstart",
        }
        for patch in (
            mock.patch.object(
                boot, "RUNTIME_ROOT", self.fixture.root / "managed/blank-boot"
            ),
            mock.patch.object(boot, "ROOT_UID", os.geteuid()),
            mock.patch.object(boot, "cpu_available", return_value=[0, 1, 2, 3]),
            mock.patch.object(boot, "unit_facts", side_effect=self.units),
            mock.patch.object(
                boot, "reload_units", side_effect=lambda: self.reloaded.append(True)
            ),
            mock.patch.object(
                boot,
                "check_guard",
                side_effect=lambda prepared: boot.guard.validate_policy(
                    prepared["policy"]
                ),
            ),
            mock.patch.object(recipient, "post_guest_action", side_effect=self.post),
            mock.patch.object(recipient, "task_state", side_effect=self.task_state),
            mock.patch.object(
                boot.runtime,
                "collect",
                side_effect=lambda policy: copy.deepcopy(self.runtime),
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def prepared(self):
        value = boot.prepare(self.stage_raw, self.stage_sha, self.completion_sha)
        raw = state.canonical(value)
        self.runtime = runtime_fixture.model()[1]
        self.runtime.update(
            config=copy.deepcopy(value["policy"]["config"]),
            generated_config=self.completed["generated"]["text"],
        )
        self.runtime["rootfs"].update(copy.deepcopy(value["policy"]["rootfs"]))
        self.runtime["rootfs"]["backing_file"] = value["policy"]["rootfs"]["path"]
        self.runtime["rootfs"]["resolved_path"] = value["policy"]["rootfs"]["path"]
        self.runtime["guest"]["hostname"] = value["policy"]["config"]["hostname"]
        self.runtime["status"]["name"] = value["policy"]["config"]["hostname"]
        self.runtime["guest"]["machine_id_sha256"] = state.sha256(b"synthetic guest")
        boot.runtime.validate(value["policy"], self.runtime)
        return raw, state.sha256(raw)

    def units(self, prepared):
        request = prepared["stage_prepared"]["recipient_prepared"]["request"]
        values = {}
        for index, unit in enumerate(stage.unit_names(request)):
            old = stage.dropin_path(request, unit)
            new = boot.allowing_dropin(request, unit)
            paths, commands = [], []
            for path, argv in (
                (old, ["/usr/bin/false"]),
                (new, boot.guard_argv(prepared)),
            ):
                if not path.exists():
                    continue
                paths.append(str(path))
                executed = self.running and index == 0 and path == new
                commands.append(
                    {
                        "path": argv[0],
                        "argv": argv,
                        "ignore_errors": False,
                        "start_real_us": self.executed_at * 1000000 if executed else 0,
                        "stop_real_us": (
                            self.executed_at * 1000000 + 1 if executed else 0
                        ),
                        "start_monotonic_us": 1 if executed else 0,
                        "stop_monotonic_us": 2 if executed else 0,
                        "pid": 333 if executed else 0,
                        "code": 1 if executed else 0,
                        "status": 0,
                    }
                )
            values[unit] = {
                "LoadState": "loaded",
                "ActiveState": "active" if self.running and index == 0 else "inactive",
                "MainPID": 222 if self.running and index == 0 else 0,
                "DropInPaths": paths,
                "commands": commands,
            }
        return values

    def post(self, request, action):
        self.assertTrue(self.fixture.fixture.inside_lock)
        self.assertEqual(action, "start")
        self.assertTrue(any(boot.RUNTIME_ROOT.rglob("write-possible.json")))
        for unit in stage.unit_names(request):
            self.assertFalse(stage.dropin_path(request, unit).exists())
            self.assertTrue(boot.allowing_dropin(request, unit).exists())
        self.posts.append(copy.deepcopy(request))
        self.running = True
        self.executed_at = int(time.time())
        return {"upid": self.task["upid"], "tls_verified": True}

    def task_state(self, request, upid, *, kind="vzcreate"):
        task = self.task if kind == "vzstart" else self.fixture.fixture.task
        self.assertEqual(upid, task["upid"])
        return copy.deepcopy(task), [{"n": 1, "t": "TASK OK"}]

    def test_prepare_is_readonly_and_binds_qualified_stage_and_guard(self):
        raw, sha = self.prepared()
        value = boot.load_prepared(raw, sha)
        self.assertEqual(value["stage_sha256"], self.stage_sha)
        self.assertEqual(value["stage_completion_sha256"], self.completion_sha)
        self.assertFalse(boot.RUNTIME_ROOT.exists())
        self.assertFalse(self.posts or self.reloaded)
        with self.assertRaises(state.PersistenceError):
            boot.prepare(self.stage_raw, self.stage_sha, "f" * 64)

    def test_one_start_installs_guard_before_post_and_reports_os_only(self):
        raw, sha = self.prepared()
        result = boot.boot(raw, sha)
        self.assertTrue(result["boot_verified"])
        self.assertFalse(result["rebuild_verified"] or result["restore_verified"])
        self.assertEqual(len(self.posts), 1)
        self.assertEqual(len(self.reloaded), 2)
        self.assertTrue(any(boot.RUNTIME_ROOT.rglob("complete.json")))
        with mock.patch.object(
            recipient, "post_guest_action"
        ) as post, mock.patch.object(boot, "reload_units") as reload:
            status = boot.status(raw, sha)
        post.assert_not_called()
        reload.assert_not_called()
        self.assertTrue(status["boot_verified"])
        with self.assertRaises(state.PersistenceError):
            boot.boot(raw, sha)
        self.assertEqual(len(self.posts), 1)

    def test_unknown_post_stays_consumed_without_retry_or_false_boot(self):
        raw, sha = self.prepared()
        with mock.patch.object(
            recipient, "post_guest_action", side_effect=OSError("uncertain")
        ):
            with self.assertRaises(OSError):
                boot.boot(raw, sha)
        self.assertTrue(any(boot.RUNTIME_ROOT.rglob("failed.json")))
        self.assertFalse(any(boot.RUNTIME_ROOT.rglob("complete.json")))
        self.assertFalse(boot.status(raw, sha)["boot_verified"])
        with self.assertRaises(state.PersistenceError):
            boot.boot(raw, sha)

    def test_late_runtime_pid_change_during_source_context_exit_cannot_complete(self):
        raw, sha = self.prepared()
        original = recipient.observe.source_state

        @contextmanager
        def changed(*args, **kwargs):
            with original(*args, **kwargs) as facts:
                yield facts
            if self.running:
                self.runtime["init"]["pid"] += 1

        with mock.patch.object(recipient.observe, "source_state", side_effect=changed):
            with self.assertRaises(state.PersistenceError):
                boot.boot(raw, sha)
        self.assertFalse(any(boot.RUNTIME_ROOT.rglob("complete.json")))

    def test_rehashed_opaque_stage_proof_or_foreign_denial_owner_refuses(self):
        raw, sha = self.prepared()
        import json

        for fault in ("units", "generated", "denial-owner"):
            value = json.loads(raw)
            if fault == "units":
                value["stage_complete"]["units"] = {}
            elif fault == "generated":
                value["stage_complete"]["generated"]["identity"] = []
            else:
                unit = next(iter(value["denials"]))
                value["denials"][unit]["identity"][3] += 1
            value["stage_completion_sha256"] = state.sha256(
                state.canonical(value["stage_complete"])
            )
            invalid = state.canonical(value)
            with self.assertRaises(ValueError):
                boot.load_prepared(invalid, state.sha256(invalid))

    def test_failed_guard_check_keeps_both_denials_and_never_posts(self):
        raw, sha = self.prepared()
        with mock.patch.object(
            boot, "check_guard", side_effect=OSError("guard refusal")
        ):
            with self.assertRaises(OSError):
                boot.boot(raw, sha)
        self.assertFalse(self.posts)
        for unit in stage.unit_names(self.fixture.fixture.request):
            self.assertTrue(
                stage.dropin_path(self.fixture.fixture.request, unit).exists()
            )
        self.assertTrue(any(boot.RUNTIME_ROOT.rglob("failed.json")))

    def test_approved_cpu_rebalance_and_cleared_history_keep_verified_process_identity(
        self,
    ):
        raw, sha = self.prepared()
        boot.boot(raw, sha)
        self.runtime["cgroup"]["cpus"] = [2]
        self.runtime["guest"]["affinity"] = [2]
        units = self.units

        def cleared(prepared):
            values = units(prepared)
            for fields in values.values():
                for command in fields["commands"]:
                    for key in (
                        "pid",
                        "code",
                        "status",
                        "start_real_us",
                        "stop_real_us",
                        "start_monotonic_us",
                        "stop_monotonic_us",
                    ):
                        command[key] = 0
            return values

        with mock.patch.object(boot, "unit_facts", side_effect=cleared):
            observed = boot.status(raw, sha)
        self.assertTrue(observed["boot_verified"])
        self.assertEqual(observed["guard_execution_history"], "cleared-or-unobserved")
        self.assertEqual(len(self.posts), 1)

    def corrupt_guard(self):
        path = next(boot.RUNTIME_ROOT.rglob("guard.py"))
        with path.open("ab") as stream:
            stream.write(b"\n# changed outside the operation\n")

    def test_guard_change_during_last_runtime_collection_prevents_completion(self):
        raw, sha = self.prepared()
        calls = []

        def changed(policy):
            calls.append(True)
            if len(calls) == 2:
                self.corrupt_guard()
            return copy.deepcopy(self.runtime)

        with mock.patch.object(boot.runtime, "collect", side_effect=changed):
            with self.assertRaises(state.PersistenceError):
                boot.boot(raw, sha)
        self.assertFalse(any(boot.RUNTIME_ROOT.rglob("complete.json")))

    def test_guard_change_during_completion_write_cannot_return_success(self):
        raw, sha = self.prepared()
        backup_write = boot.backup.write_private

        def changed(path, value):
            result = backup_write(path, value)
            if path.name == "complete.json" and path.parent.parent == boot.RUNTIME_ROOT:
                self.corrupt_guard()
            return result

        with mock.patch.object(boot.backup, "write_private", side_effect=changed):
            with self.assertRaises(state.PersistenceError):
                boot.boot(raw, sha)
        self.assertTrue(any(boot.RUNTIME_ROOT.rglob("failed.json")))

    def test_status_closes_guard_after_last_runtime_collection(self):
        raw, sha = self.prepared()
        boot.boot(raw, sha)
        calls = []

        def changed(policy):
            calls.append(True)
            if len(calls) == 2:
                self.corrupt_guard()
            return copy.deepcopy(self.runtime)

        with mock.patch.object(boot.runtime, "collect", side_effect=changed):
            with self.assertRaises(state.PersistenceError):
                boot.status(raw, sha)

    def test_status_closes_guard_after_reading_completion_record(self):
        raw, sha = self.prepared()
        boot.boot(raw, sha)
        read = boot.backup.read_private

        def changed(path):
            result = read(path)
            if path.name == "complete.json" and path.parent.parent == boot.RUNTIME_ROOT:
                self.corrupt_guard()
            return result

        with mock.patch.object(boot.backup, "read_private", side_effect=changed):
            with self.assertRaises(state.PersistenceError):
                boot.status(raw, sha)


if __name__ == "__main__":
    unittest.main()
