"""Real journal ordering with modeled native workers, never a live guest trial."""

import copy
from contextlib import contextmanager
import importlib
import json
import os
import unittest
from unittest import mock

import test_persistence_owner_admission as admission
import test_persistence_owner_journal as journal_fixture


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class OwnerTransitionTests(unittest.TestCase):
    def setUp(self):
        self.sdk = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_transition"
        )
        self.model = admission.OwnerAdmissionTests("runTest")
        self.model.setUp()
        self.case = journal_fixture.OwnerJournalTests("runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.checkpoint = self.model.authority
        self.case.datasets = self.model.request["policy"]["datasets"]
        self.case.binding = self.sdk.binding(self.checkpoint)
        with self.sdk.runtime.pair_lock.locked_pair(
            self.case.datasets, initialize=True
        ):
            pass
        self.phase = "os_quiesced"
        self.events = []
        self.native_locks = set()
        self.app_held = False
        self.post_count = 0
        self.post_error = None
        self.terminal_error = False
        self.native_warning = False
        self.close_error = None
        self.history_error = False
        self.worker_override = None
        self.task_running = False
        self.native_clock = 1700000001
        self.entry = {
            "phase": self.phase,
            "host": copy.deepcopy(self.model.frame["host"]),
            "guest": copy.deepcopy(self.model.frame["guest"]),
            "reference": {},
            "root": {"bound": True},
            "ownership": {"bound": True},
            "stopped": None,
        }
        self.config = self.case.root / "application.json"
        self.config.write_bytes(b"synthetic-private-configuration")
        self.config.chmod(0o600)

        def patch(obj, name, **options):
            return self.enterContext(mock.patch.object(obj, name, **options))

        native_root = self.case.root / "native-locks"
        native_root.mkdir(mode=0o700)
        patch(self.sdk.runtime.config_lock, "LOCK_ROOT", new=native_root)
        patch(self.sdk.runtime.config_lock, "ROOT_UID", new=os.geteuid())
        native_reader = self.sdk.runtime.config_lock.read_guest
        self.native_writer = self.sdk.runtime.config_lock.require_write_available
        policy = self.model.request["policy"]
        for vmid in (policy["vmid"], policy["retired_guest"]["vmid"]):
            with native_reader(vmid, initialize=True):
                pass

        @contextmanager
        def native_lock(vmid):
            with native_reader(vmid):
                self.assertNotIn(vmid, self.native_locks)
                self.native_locks.add(vmid)
                self.events.append(("lock", vmid))
                try:
                    yield
                finally:
                    self.events.append(("unlock", vmid))
                    self.native_locks.remove(vmid)

        @contextmanager
        def app_lock(path, uid, gid):
            self.assertFalse(self.app_held)
            with self.sdk.observe.locked_config_original(
                self.config, os.geteuid(), os.getegid()
            ) as raw:
                self.app_held = True
                try:
                    yield raw
                finally:
                    self.app_held = False

        # Preserve a real application flock while routing the modeled policy path.
        patch(
            self.sdk.observe,
            "locked_config_original",
            new=self.sdk.observe.locked_config,
            create=True,
        )
        patch(self.sdk.observe, "locked_config", side_effect=app_lock)
        patch(self.sdk.runtime.config_lock, "read_guest", side_effect=native_lock)
        patch(
            self.sdk.runtime.config_lock,
            "require_write_available",
            side_effect=self.write_available,
        )
        patch(self.sdk.current, "_entry_leased", side_effect=self.collect_entry)
        patch(self.sdk.current, "_current_leased", side_effect=self.worker)
        patch(self.sdk, "_history", side_effect=self.history)
        patch(
            self.sdk,
            "_close_history",
            side_effect=lambda value: self.events.append("history-fast"),
        )
        patch(self.sdk.observe, "mount_facts", return_value={"native_nfs_mount": 42})
        patch(self.sdk.api, "post_guest_action", side_effect=self.post)
        patch(self.sdk.api, "task_state", side_effect=self.task_state)
        patch(self.sdk.time, "time", return_value=self.native_clock)

    def collect_entry(self, checkpoint, phase, prior_runtime=None):
        self.sdk.require(phase == self.phase, "modeled-guest-state")
        value = copy.deepcopy(self.entry)
        value["phase"] = phase
        value["guest"] = copy.deepcopy(
            self.model.evidence(phase)["observation"]["guest"]
        )
        return value

    def assert_outer_leases(self):
        policy = self.model.request["policy"]
        self.assertIn(policy["retired_guest"]["vmid"], self.native_locks)
        self.assertTrue(self.app_held)
        with self.assertRaises(ValueError):
            self.native_writer(policy["retired_guest"]["vmid"])
        with self.assertRaises(ValueError):
            with self.sdk.observe.locked_config_original(
                self.config, os.geteuid(), os.getegid()
            ):
                self.fail("application EX was released")
        # The real dataset-pair flock must still be owned by the caller.
        with self.assertRaises(ValueError):
            with self.sdk.runtime.pair_lock.locked_pair(policy["datasets"]):
                self.fail("pair EX was released")

    @contextmanager
    def worker(self, checkpoint, entry, raw, prior_runtime=None):
        self.assert_outer_leases()
        self.assertIn(self.model.request["policy"]["vmid"], self.native_locks)
        with self.assertRaises(ValueError):
            self.native_writer(self.model.request["policy"]["vmid"])
        self.events.append(("worker", self.phase))
        evidence = self.model.evidence(self.phase)
        if self.worker_override is not None:
            self.worker_override(evidence)
        self.sdk.current.validate_current(checkpoint, self.phase, evidence)
        yield evidence
        self.events.append(("worker-close", self.phase))
        if self.close_error == self.phase:
            raise ValueError("modeled late current proof refused")

    def history(self, checkpoint):
        self.events.append("history-slow")
        if self.history_error:
            raise ValueError("modeled changed history")
        return {"history": "closed"}

    def write_available(self, vmid):
        self.assertNotIn(vmid, self.native_locks)
        self.assert_outer_leases()
        self.native_writer(vmid)

    def post(self, binding, action):
        self.assert_outer_leases()
        self.assertNotIn(binding.vmid, self.native_locks)
        self.native_writer(binding.vmid)
        self.post_count += 1
        self.events.append(("POST", action))
        if self.post_error:
            raise self.post_error
        self.phase = "stopped" if action == "shutdown" else "os_quiesced"
        kind = "vzshutdown" if action == "shutdown" else "vzstart"
        return {
            "upid": f"UPID:{binding.node}:00000010:00000020:{self.native_clock:08X}:{kind}:{binding.vmid}:root@pam:",
            "tls_verified": True,
        }

    def task_state(self, binding, upid, *, kind):
        self.assert_outer_leases()
        self.assertNotIn(binding.vmid, self.native_locks)
        self.native_writer(binding.vmid)
        task = self.sdk.api.parse_upid(binding, upid, kind=kind)
        task["status"] = "running" if self.task_running else "stopped"
        if not self.task_running:
            task["exitstatus"] = "ERROR" if self.terminal_error else "OK"
        log = [
            {"n": 1, "t": "TASK ERROR: refused" if self.terminal_error else "TASK OK"}
        ]
        if self.native_warning:
            task["exitstatus"] = "WARNINGS: 1"
            log = [
                {"n": 1, "t": self.sdk.api.WARNING},
                {"n": 2, "t": "TASK WARNINGS: 1"},
            ]
        return task, log

    def initialize(self):
        head = self.sdk.genesis_sha256(self.checkpoint)
        result = self.sdk.initialize(self.checkpoint, head)
        self.assertEqual(result["head_sha256"], head)
        self.assertEqual(self.post_count, 0)
        return head

    def prepare(self, head, kind="shutdown"):
        return self.sdk.prepare(self.checkpoint, head, kind)

    def operate(self, prepared):
        raw = self.sdk.state.canonical(prepared)
        return self.sdk.operate(self.checkpoint, raw, self.sdk.state.sha256(raw))

    def test_preparation_is_read_only_and_a_complete_cycle_keeps_outer_leases(self):
        head = self.initialize()
        for kind in ("shutdown", "resume", "shutdown", "resume"):
            before = self.case.files()
            prepared = self.prepare(head, kind)
            self.assertEqual(before, self.case.files())
            result = self.operate(prepared)
            self.assertTrue(result["os_transition_verified"])
            self.assertTrue(result["application_quiesced"])
            self.assertFalse(result["application_write_verified"])
            self.assertFalse(result["restore_verified"])
            head = result["head_sha256"]
        self.assertEqual(self.post_count, 4)
        self.assertFalse(self.app_held)
        self.assertEqual(self.native_locks, set())

    def test_same_preparation_cannot_issue_a_second_post(self):
        prepared = self.prepare(self.initialize())
        self.operate(prepared)
        with self.assertRaises(ValueError):
            self.operate(prepared)
        self.assertEqual(self.post_count, 1)

    def test_changed_preparation_or_current_entry_refuses_before_dispatch(self):
        prepared = self.prepare(self.initialize())
        changed = copy.deepcopy(prepared)
        changed["entry"]["root"] = {"bound": False}
        with self.assertRaises(ValueError):
            self.operate(changed)
        self.assertEqual(self.post_count, 0)
        self.assertEqual(list(self.case.path().glob("[0-9]*")), [])

    def test_lost_ack_preserves_dispatch_and_blocks_redispatch(self):
        prepared = self.prepare(self.initialize())
        self.post_error = OSError("modeled lost response")
        with self.assertRaises(OSError):
            self.operate(prepared)
        self.assertEqual(self.post_count, 1)
        slot = self.case.path() / self.sdk.journal._slot(1)
        self.assertTrue((slot / "dispatch.json").is_file())
        self.assertFalse((slot / "ack.json").exists())
        self.assertEqual(
            json.loads((slot / "failure.json").read_bytes())["outcome"], "unknown"
        )
        self.post_error = None
        with self.assertRaises(ValueError):
            self.operate(prepared)
        self.assertEqual(self.post_count, 1)

    def test_rejected_terminal_never_publishes_success(self):
        prepared = self.prepare(self.initialize())
        self.terminal_error = True
        with self.assertRaises(ValueError):
            self.operate(prepared)
        slot = self.case.path() / self.sdk.journal._slot(1)
        self.assertTrue((slot / "terminal.json").exists())
        self.assertFalse((slot / "result.json").exists())
        self.assertEqual(self.post_count, 1)

    def test_failure_after_candidate_publication_keeps_candidate_and_barrier(self):
        prepared = self.prepare(self.initialize())
        self.close_error = "stopped"
        with self.assertRaises(ValueError):
            self.operate(prepared)
        slot = self.case.path() / self.sdk.journal._slot(1)
        self.assertTrue((slot / "result.json").exists())
        self.assertTrue((slot / "failure.json").exists())
        self.assertEqual(self.post_count, 1)
        with self.assertRaises(ValueError):
            self.prepare(self.sdk.genesis_sha256(self.checkpoint), "resume")

    def test_changed_history_refuses_before_begin_or_post(self):
        prepared = self.prepare(self.initialize())
        self.history_error = True
        with self.assertRaises(ValueError):
            self.operate(prepared)
        self.assertEqual(self.post_count, 0)

    def test_busy_native_lock_preserves_not_dispatched_barrier(self):
        prepared = self.prepare(self.initialize())
        with mock.patch.object(
            self.sdk.runtime.config_lock,
            "require_write_available",
            side_effect=ValueError("busy"),
        ):
            with self.assertRaises(ValueError):
                self.operate(prepared)
        self.assertEqual(self.post_count, 0)
        slot = self.case.path() / self.sdk.journal._slot(1)
        self.assertEqual(
            json.loads((slot / "failure.json").read_bytes())["outcome"],
            "not-dispatched",
        )

    def test_task_timeout_cannot_retry_the_request(self):
        prepared = self.prepare(self.initialize())
        self.task_running = True
        raw = self.sdk.state.canonical(prepared)
        with mock.patch.object(self.sdk.time, "monotonic", side_effect=[0, 2]):
            with self.assertRaises(ValueError):
                self.sdk.operate(
                    self.checkpoint, raw, self.sdk.state.sha256(raw), timeout_seconds=1
                )
        self.assertEqual(self.post_count, 1)
        slot = self.case.path() / self.sdk.journal._slot(1)
        self.assertTrue((slot / "ack.json").exists())
        self.assertFalse((slot / "terminal.json").exists())

    def test_foreign_ack_refuses_without_recording_it_or_retrying(self):
        prepared = self.prepare(self.initialize())
        post = self.post

        def foreign(binding, action):
            value = post(binding, action)
            value["upid"] = value["upid"].replace(":101:", ":103:")
            return value

        with mock.patch.object(self.sdk.api, "post_guest_action", side_effect=foreign):
            with self.assertRaises(ValueError):
                self.operate(prepared)
        self.assertEqual(self.post_count, 1)
        slot = self.case.path() / self.sdk.journal._slot(1)
        self.assertFalse((slot / "ack.json").exists())

    def test_late_real_native_lease_change_prevents_returning_candidate(self):
        prepared = self.prepare(self.initialize())
        complete = self.sdk.journal._complete

        def late(*args):
            candidate = complete(*args)
            vmid = self.model.request["policy"]["vmid"]
            path = self.sdk.runtime.config_lock.LOCK_ROOT / f"pve-config-{vmid}.lock"
            path.chmod(0o640)
            return candidate

        with mock.patch.object(self.sdk.journal, "_complete", side_effect=late):
            with self.assertRaises(ValueError):
                self.operate(prepared)
        slot = self.case.path() / self.sdk.journal._slot(1)
        self.assertTrue((slot / "result.json").exists())
        self.assertTrue((slot / "failure.json").exists())
        self.assertEqual(self.post_count, 1)

    def test_slow_work_precedes_each_final_worker(self):
        prepared = self.prepare(self.initialize())
        self.events.clear()
        self.operate(prepared)
        post_index = self.events.index(("POST", "shutdown"))
        pre_close = self.events.index(("worker-close", "os_quiesced"))
        final_close = self.events.index(("worker-close", "stopped"))
        self.assertLess(pre_close, post_index)
        self.assertNotIn("history-slow", self.events[pre_close:post_index])
        self.assertNotIn("history-slow", self.events[final_close:])

    def test_status_uses_accepted_head_and_never_writes_or_dispatches(self):
        prepared = self.prepare(self.initialize())
        completed = self.operate(prepared)
        before = self.case.files()
        raw = self.sdk.state.canonical(prepared)
        result = self.sdk.status(
            self.checkpoint, raw, self.sdk.state.sha256(raw), completed["head_sha256"]
        )
        self.assertTrue(result["os_transition_verified"])
        self.assertFalse(result["mutation_attempted"])
        self.assertEqual(before, self.case.files())
        self.assertEqual(self.post_count, 1)
        with self.assertRaises(ValueError):
            self.sdk.status(self.checkpoint, raw, self.sdk.state.sha256(raw), "f" * 64)
        self.assertEqual(before, self.case.files())

    def test_reused_api_pid_with_new_birth_refuses_before_begin(self):
        prepared = self.prepare(self.initialize())

        def replaced(evidence):
            if evidence["phase"] == "os_quiesced":
                evidence["observation"]["kernel"]["init"]["pstart"] += 100

        self.worker_override = replaced
        with self.assertRaises(ValueError):
            self.operate(prepared)
        self.assertEqual(self.post_count, 0)
        self.assertEqual(list(self.case.path().glob("[0-9]*")), [])

    def test_decreased_uptime_since_preparation_refuses_before_begin(self):
        prepared = self.prepare(self.initialize())
        self.assertGreater(prepared["uptime_floor"], 0)

        def decreased(evidence):
            evidence["observation"]["guest"]["runtime"]["uptime"] = (
                prepared["uptime_floor"] - 1
            )

        self.worker_override = decreased
        with self.assertRaises(ValueError):
            self.operate(prepared)
        self.assertEqual(self.post_count, 0)
        self.assertEqual(list(self.case.path().glob("[0-9]*")), [])

    def test_known_warning_still_requires_full_current_running_proof(self):
        stopped = self.operate(self.prepare(self.initialize()))
        prepared = self.prepare(stopped["head_sha256"], "resume")
        self.native_warning = True
        result = self.operate(prepared)
        self.assertEqual(
            result["native_outcome"],
            {"native_success": True, "accepted": True, "warning_count": 1},
        )
        self.assertTrue(result["current"]["guest_image_verified"])
        self.assertNotIn("synthetic-private-configuration", json.dumps(result))
        self.assertEqual(self.post_count, 2)

    def test_return_exports_exact_raw_records_and_has_a_pure_validator(self):
        prepared = self.prepare(self.initialize())
        result = self.operate(prepared)
        self.assertEqual(result["before"]["phase"], "os_quiesced")
        self.assertEqual(result["entry"]["phase"], "os_quiesced")
        slot = self.case.path() / self.sdk.journal._slot(1)
        for name, raw in result["operation_records"].items():
            path = self.case.path() / name if name == "HEAD.json" else slot / name
            self.assertEqual(path.read_bytes(), raw.encode())
        raw = self.sdk.state.canonical(prepared)
        before = copy.deepcopy(result)
        with mock.patch.object(
            self.sdk.observe, "read_regular", side_effect=AssertionError("pure IO")
        ), mock.patch.object(
            self.sdk.observe, "native", side_effect=AssertionError("pure native")
        ), mock.patch.object(
            self.sdk.api, "post_guest_action", side_effect=AssertionError("pure POST")
        ):
            self.sdk.validate_result(
                self.checkpoint, raw, self.sdk.state.sha256(raw), result
            )
            for fault in (
                "head_sha256",
                "phase_chain_sha256",
                "mutation_attempted",
                "operation_records",
                "entry",
            ):
                changed = copy.deepcopy(result)
                changed[fault] = (
                    1
                    if fault == "mutation_attempted"
                    else ({} if fault in {"operation_records", "entry"} else "f" * 64)
                )
                with self.subTest(fault=fault), self.assertRaises(ValueError):
                    self.sdk.validate_result(
                        self.checkpoint, raw, self.sdk.state.sha256(raw), changed
                    )
        self.assertEqual(before, result)


if __name__ == "__main__":
    unittest.main()
