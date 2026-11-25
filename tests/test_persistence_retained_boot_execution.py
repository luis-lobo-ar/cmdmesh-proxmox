"""A claimed OS start hands the native lock off while retaining writer exclusion."""

import copy
from contextlib import closing
import fcntl
import os
from pathlib import Path
import sys
import sqlite3
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_retained_boot as boot,
)
import test_persistence_retained_boot as preparation


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class BootExecutionTests(unittest.TestCase):
    def setUp(self):
        self.base = preparation.BootPreparationTests("runTest")
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.fixture, self.request = self.base.fixture, self.base.request
        self.policy = self.request["policy"]
        self.units = self.base.root / "systemd"
        self.units.mkdir(mode=0o700)
        self.target_units = boot.runtime.reference_units(self.request)
        attach = boot.reconcile.original.attach
        for vmid in self.fixture.vmids:
            for unit in attach.unit_names(vmid):
                directory = self.units / (unit + ".d")
                directory.mkdir(mode=0o700)
                files = {}
                for name, body in (
                    (
                        "50-cmdmesh-reference.conf",
                        boot.runtime.reference_body(self.request),
                    ),
                    (attach.DENIAL_NAME, attach.DENIAL),
                ):
                    path = directory / name
                    path.write_bytes(body)
                    path.chmod(0o600)
                    files[name] = boot._history_file(path)
                self.base.accepted["publication"]["controls"][unit] = {"files": files}
        self.started = False
        self.posts = 0
        self.polls = 0
        self.worker_calls = 0
        self.clock = 1000
        self.upid = (
            f"UPID:{self.policy['node']}:00000010:00000020:000003E8:"
            f"vzstart:{self.policy['vmid']}:root@pam:"
        )
        reference = self.fixture.value["reference"]
        for old in tuple(reference["files"]):
            path = Path(old)
            if path.name in {"guard.py", "policy.json"}:
                item = reference["files"].pop(old)
                name = str(self.base.guard_path.parent / path.name)
                reference["files"][name] = {**item, "path": name}
            else:
                reference["files"][old]["sha256"] = boot.state.sha256(
                    boot.runtime.reference_body(self.request)
                )
        for index, unit in enumerate(self.target_units):
            command = reference["units"][unit]["commands"][0]
            command["argv"] = boot.runtime.reference_argv(self.request)
            if index == 0:
                command["start_real_us"] = self.clock * 1000000
                command["stop_real_us"] = self.clock * 1000000 + 500000
        self.prepared = self.base.prepare()
        self.raw = boot.state.canonical(self.prepared)
        self.sha = boot.state.sha256(self.raw)
        self.before_old = self.old_files()
        self.native_worker = boot.runtime._collect_leased
        for target, name, callback in (
            (boot.api, "post_guest_action", self.post),
            (boot.api, "task_state", self.task),
            (boot.reconcile.original, "unit_state", self.unit_state),
            (boot.reconcile.original, "reload_units", lambda: None),
            (boot.reconcile, "execute_guard", self.direct_guard),
            (boot.runtime, "_collect_leased", self.worker),
            (boot.time, "time", lambda: self.clock),
        ):
            patch = mock.patch.object(target, name, side_effect=callback)
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(attach, "UNIT_ROOT", self.units)
        patch.start()
        self.addCleanup(patch.stop)

    def old_files(self):
        return {
            str(path): path.read_bytes()
            for unit in boot.reconcile.original.attach.unit_names(
                self.policy["retired_guest"]["vmid"]
            )
            for path in (self.units / (unit + ".d")).iterdir()
        }

    def handoff_scopes(self):
        retired = self.policy["retired_guest"]["vmid"]
        with self.assertRaises(boot.config_lock.ConfigLockError):
            boot.config_lock.require_write_available(retired)
        boot.config_lock.require_write_available(self.policy["vmid"])
        with self.assertRaises(boot.state.PersistenceError):
            with self.base.real_pair(self.policy["datasets"]):
                self.fail("pair EX must span the native task")
        with self.fixture.config.open("rb") as fd:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def post(self, binding, action):
        self.handoff_scopes()
        self.assertEqual((binding.vmid, action), (self.policy["vmid"], "start"))
        directory = boot.claim_path(self.request)
        self.assertTrue((directory / "intent.json").is_file())
        self.assertTrue((directory / "dispatch.json").is_file())
        for unit in self.target_units:
            self.assertFalse(
                (
                    self.units
                    / (unit + ".d")
                    / boot.reconcile.original.attach.DENIAL_NAME
                ).exists()
            )
        self.assertEqual(self.old_files(), self.before_old)
        self.posts += 1
        self.started = True
        return {"upid": self.upid, "tls_verified": True}

    def task(self, binding, upid, **kwargs):
        if self.worker_calls:
            self.base.scopes()
        else:
            self.handoff_scopes()
        self.polls += 1
        task = boot.api.parse_upid(binding, upid)
        return (
            {**task, "status": "stopped", "exitstatus": "WARNINGS: 1"},
            [{"n": 1, "t": boot.api.WARNING}, {"n": 2, "t": "TASK WARNINGS: 1"}],
        )

    def unit_state(self, unit):
        path = self.units / (unit + ".d")
        commands = []
        argv = boot.runtime.reference_argv(self.request)
        command = dict.fromkeys(boot.execution.FIELDS[3:], 0)
        command.update(path=argv[0], argv=argv, ignore_errors=False)
        commands.append(command)
        return {
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "MainPID": "0",
            "DropInPaths": sorted(str(item) for item in path.iterdir()),
            "commands": commands,
        }

    def direct_guard(self, argv):
        self.base.scopes()
        with self.fixture.config.open("rb") as fd:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return {
            "exit_code": 0,
            "payload": {"outcome": "qualified"},
            "stdout_sha256": boot.state.sha256(b'{"outcome":"qualified"}\n'),
            "stderr_bytes": 0,
            "stderr_sha256": boot.state.sha256(b""),
        }

    def worker(self, *args):
        self.worker_calls += 1
        self.assertTrue(self.started)
        self.base.scopes()
        return self.native_worker(*args)

    def run_boot(self):
        return boot.boot(self.raw, self.sha, timeout_seconds=10)

    def assert_failed_once(self):
        directory = boot.claim_path(self.request)
        self.assertTrue((directory / "failed.json").is_file())
        before = self.posts
        with self.assertRaises(ValueError):
            self.run_boot()
        self.assertEqual(self.posts, before)
        self.assertEqual(self.old_files(), self.before_old)
        self.fixture.released()

    def test_one_start_releases_only_target_lease_and_keeps_application_unchanged(self):
        result = self.run_boot()
        self.assertEqual((self.posts, self.polls, self.worker_calls), (1, 1, 2))
        self.assertTrue(result["boot_verified"] and result["application_quiesced"])
        self.assertFalse(result["rebuild_verified"] or result["restore_verified"])
        self.assertEqual(
            result["runtime"]["application"], self.base.source["application"]
        )
        self.assertEqual(self.old_files(), self.before_old)
        self.assertFalse((boot.claim_path(self.request) / "failed.json").exists())
        self.assertEqual(
            boot.state.sha256(boot.state.canonical(result["journal_files"])),
            result["phase_journal_sha256"],
        )
        for name, info in result["journal_files"].items():
            self.assertEqual(
                info["sha256"],
                boot.state.sha256((boot.claim_path(self.request) / name).read_bytes()),
            )
        for index in range(2):
            self.assertEqual(
                (
                    boot.claim_path(self.request) / f"target-denial-{index}.conf"
                ).read_bytes(),
                boot.reconcile.original.attach.DENIAL,
            )
        self.fixture.released()

    def test_lost_acknowledgement_consumes_claim_and_never_repeats_post(self):
        def lost(*args):
            self.post(*args)
            raise TimeoutError("private transport detail")

        with mock.patch.object(boot.api, "post_guest_action", side_effect=lost):
            with self.assertRaises(TimeoutError):
                self.run_boot()
        self.assertEqual((self.posts, self.polls, self.worker_calls), (1, 0, 0))
        self.assert_failed_once()
        self.assertNotIn(
            "private transport",
            (boot.claim_path(self.request) / "failed.json").read_text(),
        )

    def test_guard_refusal_keeps_denials_and_durable_result(self):
        result = self.direct_guard

        def refused(argv):
            value = result(argv)
            return {
                **value,
                "exit_code": 1,
                "payload": {"outcome": "refused", "reason": "test"},
            }

        with mock.patch.object(boot.reconcile, "execute_guard", side_effect=refused):
            with self.assertRaises(ValueError):
                self.run_boot()
        self.assertEqual(self.posts, 0)
        self.assertTrue((boot.claim_path(self.request) / "guard-result.json").exists())
        for unit in self.target_units:
            self.assertTrue(
                (
                    self.units
                    / (unit + ".d")
                    / boot.reconcile.original.attach.DENIAL_NAME
                ).exists()
            )
        self.assert_failed_once()

    def test_wrong_acknowledged_guest_refuses_before_task_poll(self):
        def wrong(*args):
            value = self.post(*args)
            return {
                **value,
                "upid": self.upid.replace(
                    f":vzstart:{self.policy['vmid']}:",
                    f":vzstart:{self.policy['vmid'] + 1}:",
                ),
            }

        with mock.patch.object(boot.api, "post_guest_action", side_effect=wrong):
            with self.assertRaises(ValueError):
                self.run_boot()
        self.assertEqual((self.posts, self.polls), (1, 0))
        self.assert_failed_once()

    def test_unknown_native_warning_cannot_report_runtime_success(self):
        def unqualified(binding, upid, **kwargs):
            task, log = self.task(binding, upid)
            log[0]["t"] = "WARN: unexpected native condition"
            return task, log

        with mock.patch.object(boot.api, "task_state", side_effect=unqualified):
            with self.assertRaises(ValueError):
                self.run_boot()
        self.assertEqual(self.worker_calls, 0)
        self.assert_failed_once()

    def test_parent_history_change_after_dispatch_refuses_completion(self):
        def changed(*args):
            value = self.post(*args)
            (self.base.publisher / "intent.json").write_bytes(b'{"after":"dispatch"}')
            return value

        with mock.patch.object(boot.api, "post_guest_action", side_effect=changed):
            with self.assertRaises(ValueError):
                self.run_boot()
        self.assertEqual(self.posts, 1)
        self.assert_failed_once()

    def test_runtime_refusal_keeps_claim_and_releases_locks(self):
        with mock.patch.object(
            boot.runtime,
            "_collect_leased",
            side_effect=ValueError("unqualified runtime"),
        ):
            with self.assertRaises(ValueError):
                self.run_boot()
        self.assert_failed_once()

    def test_completion_never_accepts_sql_cached_before_later_history_reads(self):
        original = boot._history_file
        changed = False

        def late(path, **kwargs):
            nonlocal changed
            value = original(path, **kwargs)
            if self.worker_calls and not changed:
                changed = True
                with closing(sqlite3.connect(self.fixture.database)) as db, db:
                    db.execute(
                        "INSERT INTO entries VALUES (2,?,?)",
                        ("2" * 32, "late unmanaged write"),
                    )
            return value

        with mock.patch.object(boot, "_history_file", side_effect=late):
            try:
                result = self.run_boot()
            except ValueError:
                self.assert_failed_once()
                return
        current = self.fixture.read_database(
            self.fixture.database, self.policy["application"]["instance_id"]
        )
        self.assertEqual(
            {key: result["runtime"]["application"][key] for key in current}, current
        )

    def test_status_is_read_only_and_never_calls_stopped_observers_or_post(self):
        initial = self.run_boot()
        before = self.base.files()
        self.fixture.value["guest"]["runtime"]["uptime"] += 30
        self.fixture.events.clear()
        with mock.patch.object(
            boot.reconcile,
            "status",
            side_effect=AssertionError("stopped reconciliation"),
        ), mock.patch.object(
            boot.observe, "source_state", side_effect=AssertionError("stopped source")
        ), mock.patch.object(
            boot.api, "post_guest_action", side_effect=AssertionError("repeated POST")
        ):
            result = boot.status(self.raw, self.sha)
        self.assertTrue(result["boot_verified"] and result["application_quiesced"])
        self.assertFalse(result["mutation_attempted"])
        self.assertEqual(result["completion_sha256"], initial["completion_sha256"])
        self.assertEqual(self.base.files(), before)
        self.assertEqual((self.posts, self.worker_calls), (1, 3))
        self.fixture.released()

    def test_status_refuses_extra_records_or_corrupt_completion_without_post(self):
        self.run_boot()
        self.fixture.events.clear()
        directory = boot.claim_path(self.request)
        path = directory / "unexpected.json"
        path.write_bytes(b"{}")
        path.chmod(0o600)
        with self.assertRaises(ValueError):
            boot.status(self.raw, self.sha)
        path.unlink()
        path = directory / "complete.json"
        value, _ = boot.backup.read_private(path)
        value["boot_verified"] = 1
        path.write_bytes(boot.state.canonical(value))
        with self.assertRaises(ValueError):
            boot.status(self.raw, self.sha)
        self.assertEqual(self.posts, 1)
        self.fixture.released()

    def test_status_cannot_qualify_a_consumed_lost_acknowledgement_claim(self):
        def lost(*args):
            self.post(*args)
            raise TimeoutError("lost")

        with mock.patch.object(boot.api, "post_guest_action", side_effect=lost):
            with self.assertRaises(TimeoutError):
                self.run_boot()
        before = self.base.files()
        with self.assertRaises(ValueError):
            boot.status(self.raw, self.sha)
        self.assertEqual(self.base.files(), before)
        self.assertEqual(self.posts, 1)

    def completion_fault(self, fault):
        original = boot.backup.write_private

        def write(path, value):
            checksum = original(path, value)
            if path.name == "complete.json":
                if fault == "database":
                    with closing(sqlite3.connect(self.fixture.database)) as db, db:
                        db.execute(
                            "INSERT INTO entries VALUES (2,?,?)",
                            ("2" * 32, "late write"),
                        )
                elif fault == "init":
                    self.fixture.mocks["init_state"].side_effect = lambda pid: (501, 20)
                else:
                    (boot.RUNTIME_ROOT / "profile.json").write_bytes(
                        b'{"foreign":true}'
                    )
            return checksum

        with mock.patch.object(boot.backup, "write_private", side_effect=write):
            with self.assertRaises(ValueError):
                self.run_boot()
        self.assertTrue((boot.claim_path(self.request) / "complete.json").exists())
        self.assert_failed_once()

    def test_database_changed_during_complete_write_refuses_stale_success(self):
        self.completion_fault("database")

    def test_init_replaced_during_complete_write_refuses_stale_success(self):
        self.completion_fault("init")

    def test_own_runtime_profile_changed_during_complete_write_refuses(self):
        self.completion_fault("profile")

    def test_native_task_timeout_keeps_one_consumed_dispatch(self):
        def running(binding, upid, **kwargs):
            task, _ = self.task(binding, upid)
            task.pop("exitstatus")
            task["status"] = "running"
            return task, []

        with mock.patch.object(
            boot.api, "task_state", side_effect=running
        ), mock.patch.object(boot.time, "monotonic", side_effect=[0, 11]):
            with self.assertRaisesRegex(ValueError, "native-task-timeout"):
                self.run_boot()
        self.assertEqual((self.posts, self.polls, self.worker_calls), (1, 1, 0))
        self.assert_failed_once()

    def test_old_task_acknowledgement_refuses_before_poll(self):
        def old(*args):
            value = self.post(*args)
            return {
                **value,
                "upid": self.upid.replace("000003E8:vzstart", "00000001:vzstart"),
            }

        with mock.patch.object(boot.api, "post_guest_action", side_effect=old):
            with self.assertRaisesRegex(ValueError, "task-clock"):
                self.run_boot()
        self.assertEqual((self.posts, self.polls), (1, 0))
        self.assert_failed_once()

    def test_old_guard_execution_cannot_qualify_the_new_start(self):
        command = self.fixture.value["reference"]["units"][self.target_units[0]][
            "commands"
        ][0]
        command.update(start_real_us=1000000, stop_real_us=1500000)
        with self.assertRaises(ValueError):
            self.run_boot()
        self.assert_failed_once()

    def test_status_closes_its_own_profile_after_runtime_work(self):
        self.run_boot()
        self.fixture.events.clear()
        original = self.native_worker

        def changed(*args):
            result = original(*args)
            (boot.RUNTIME_ROOT / "profile.json").write_bytes(b'{"foreign":true}')
            return result

        with mock.patch.object(boot.runtime, "_collect_leased", side_effect=changed):
            with self.assertRaises(ValueError):
                boot.status(self.raw, self.sha)
        self.assertEqual(self.posts, 1)
        self.fixture.released()

    def test_status_rejects_completion_replaced_after_its_initial_read(self):
        self.run_boot()
        self.fixture.events.clear()
        original = boot.backup.read_private

        def changed(path):
            value = original(path)
            if path.name == "task.json":
                completed = path.parent / "complete.json"
                saved, _ = original(completed)
                saved["phase"] = "foreign"
                completed.write_bytes(boot.state.canonical(saved))
            return value

        with mock.patch.object(boot.backup, "read_private", side_effect=changed):
            with self.assertRaises(ValueError):
                boot.status(self.raw, self.sha)
        self.assertEqual(self.posts, 1)

    def test_status_refuses_a_forged_journal_descriptor_with_a_matching_digest(self):
        self.run_boot()
        self.fixture.events.clear()
        path = boot.claim_path(self.request) / "complete.json"
        completed, _ = boot.backup.read_private(path)
        completed["journal_files"]["dispatch.json"]["identity"][1] += 1
        completed["phase_journal_sha256"] = boot.state.sha256(
            boot.state.canonical(completed["journal_files"])
        )
        path.write_bytes(boot.state.canonical(completed))
        with self.assertRaisesRegex(ValueError, "journal"):
            boot.status(self.raw, self.sha)
        self.assertEqual(self.posts, 1)


if __name__ == "__main__":
    unittest.main()
