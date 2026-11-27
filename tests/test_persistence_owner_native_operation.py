"""Real local leases/journals and SQL reads with modeled native/current providers."""

import copy
from contextlib import contextmanager
import importlib
import json
import os
import unittest
from unittest import mock

import test_persistence_owner_native_initialization as fixtures
from test_persistence_owner_phase_admission import admission_inputs


class NativeOperationBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.n = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_native_executor"
        )

    def test_mutation_requires_explicit_permission_and_normal_mode_before_io(self):
        with mock.patch.object(
            self.n, "_leased", side_effect=AssertionError("lease IO")
        ):
            for change in (
                {"allow_mutation": False},
                {"allow_mutation": 1},
                {"check_mode": True},
                {"check_mode": 0},
                {"timeout_seconds": 0},
                {"timeout_seconds": True},
            ):
                args = dict(
                    admission=object(),
                    prepared_raw=b"{}",
                    prepared_sha256="0" * 64,
                    allow_mutation=True,
                    check_mode=False,
                )
                args.update(change)
                with self.subTest(change=change), self.assertRaises(ValueError):
                    self.n.operate(**args)

    def test_invalid_admission_refuses_result_and_status_without_io(self):
        with mock.patch.object(
            self.n, "_leased", side_effect=AssertionError("lease IO")
        ):
            args = dict(
                admission=object(), prepared_raw=b"{}", prepared_sha256="0" * 64
            )
            with self.assertRaises(ValueError):
                self.n.validate_result(**args, result={})
            with self.assertRaises(ValueError):
                self.n.status(**args, accepted_head_sha256="0" * 64)

    def test_result_budget_precedes_encoding_or_evidence_reconstruction(self):
        leaf = "x" * 4096
        result = {"before": [leaf] * 8193}
        with mock.patch.object(
            self.n,
            "_decode_prepared",
            side_effect=AssertionError("evidence reconstruction"),
        ), mock.patch.object(
            self.n.state, "canonical", side_effect=AssertionError("unbounded encoding")
        ):
            with self.assertRaisesRegex(ValueError, "input-limit"):
                self.n.validate_result(
                    admission=object(),
                    prepared_raw=b"{}",
                    prepared_sha256="0" * 64,
                    result=result,
                )


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class NativeOperationTests(fixtures._InitializationFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.storage._initialize_journal(self.binding)
        for name in ("entry", "evidence"):
            self.enterContext(
                mock.patch.object(self.f, name, copy.deepcopy(getattr(self.f, name)))
            )
        self.store = dict(
            source="storage.invalid:/reference",
            target="/reference",
            fstype="nfs",
            options=["hard", "rw", "vers=3"],
        )
        self.enterContext(
            mock.patch.object(self.n.observe, "mount_facts", return_value=self.store)
        )
        self.clock = 1700000000
        self.posts = 0
        self.delay = False
        self.delayed = 0
        self.response_fault = None
        self.task = None
        self.enterContext(
            mock.patch.object(self.n.time, "time", side_effect=lambda: self.clock)
        )
        original = self.n.current._current_frames_leased

        @contextmanager
        def frames(*args):
            count = self.posts
            with original(*args) as value:
                yield value
            pair = self.n.journal.RUNTIME_ROOT / self.binding.pair_key
            if self.delay and self.posts == count and any(pair.glob("*/dispatch.json")):
                self.clock += 61
                self.delayed += 1
                self.delay = False

        self.enterContext(
            mock.patch.object(
                self.n.current, "_current_frames_leased", side_effect=frames
            )
        )
        self.enterContext(
            mock.patch.object(
                self.n.journal.api, "post_owner_guest_action", side_effect=self.post
            )
        )
        self.enterContext(
            mock.patch.object(
                self.n.journal.api, "task_state", side_effect=self.task_state
            )
        )

    def set_phase(self, phase):
        evidence, entry, prior = admission_inputs(self.f.model.case.model, phase)
        for frame in (
            evidence["observation"],
            entry,
            *([] if prior is None else [prior]),
        ):
            frame["host"].update(self.f.entry["host"])
        self.f.evidence, self.f.entry = evidence, entry

    def post(self, binding, action, dispatch_sha256, epoch):
        api, j = self.n.journal.api, self.n.journal
        self.posts += 1
        self.assertEqual(binding, self.binding.guest)
        self.assertTrue(self.f.model.case.app_held)
        self.n.runtime.config_lock.require_write_available(binding.vmid)
        with self.assertRaises(ValueError):
            with self.n.runtime.pair_lock.locked_pair(
                self.f.model.case.model.request["policy"]["datasets"]
            ):
                self.fail("pair lease released")
        pair = j.RUNTIME_ROOT / self.binding.pair_key
        head = self.n.observe.decode((pair / "HEAD.json").read_bytes())
        view = j._inspect(self.binding, j._digest(head))
        self.assertEqual(tuple(view.phases.records), ("dispatch.json",))
        self.assertEqual(
            j._digest(view.phases.records["dispatch.json"]), dispatch_sha256
        )
        kind = "vzshutdown" if action == "shutdown" else "vzstart"
        upid = f"UPID:{binding.node}:00000010:00000020:{self.clock:08X}:{kind}:{binding.vmid}:root@pam:"
        self.task = dict(
            **api.parse_upid(binding, upid, kind=kind),
            status="stopped",
            exitstatus="OK",
        )
        self.set_phase("stopped" if action == "shutdown" else "os_quiesced")
        if self.response_fault == "lost":
            raise OSError("modeled lost response")

        def clock(tick):
            return dict(
                epoch=copy.deepcopy(epoch),
                wall_ns=self.clock * 10**9 + tick,
                monotonic_before_ns=(self.clock - 1700000000) * 10**9 + tick,
                monotonic_after_ns=(self.clock - 1700000000) * 10**9 + tick + 1000,
            )

        return j.owner_ack.observe_response(
            binding,
            action,
            dispatch_sha256,
            clock(0),
            clock(200000000),
            tls_verified=True,
            tls_peer_sha256=binding.leaf_sha256,
            tls_version="TLSv1.3",
            http_status=401 if self.response_fault == "unauthorized" else 200,
            content_type="application/json",
            body=json.dumps({"data": upid}).encode(),
        )

    def task_state(self, binding, upid, *, kind):
        self.assertEqual(binding, self.binding.guest)
        self.assertEqual(
            self.n.journal.api.parse_upid(binding, upid, kind=kind)["upid"],
            self.task["upid"],
        )
        return copy.deepcopy(self.task), [{"n": 1, "t": "TASK OK"}]

    def prepare(self, head=None, kind="shutdown", prior=None):
        args = dict(
            admission=self.admission,
            kind=kind,
            accepted_head_sha256=head or self.genesis,
        )
        if prior is not None:
            raw = self.n.state.canonical(prior)
            args.update(
                prior_runtime_raw=raw, prior_runtime_sha256=self.n.state.sha256(raw)
            )
        return self.n.prepare(**args)

    def operate(self, prepared):
        return self.n.operate(
            admission=self.admission,
            prepared_raw=prepared.raw,
            prepared_sha256=prepared.sha256,
            allow_mutation=True,
        )

    def test_both_original_slow_pre_post_closures_then_status_and_no_replay(self):
        head, prior = self.genesis, None
        for kind in ("shutdown", "resume"):
            prepared = self.prepare(head, kind, prior)
            bad = self.n.observe.decode(prepared.raw)
            bad["prior_runtime"] = (
                bad["before_current"]["observation"] if kind == "shutdown" else None
            )
            bad_raw = self.n.state.canonical(bad)
            with mock.patch.object(
                self.n,
                "_leased",
                side_effect=AssertionError("invalid prior reached lease IO"),
            ):
                with self.assertRaises(ValueError):
                    self.n.operate(
                        admission=self.admission,
                        prepared_raw=bad_raw,
                        prepared_sha256=self.n.state.sha256(bad_raw),
                        allow_mutation=True,
                    )
            before_posts = self.posts
            self.delay = True
            result = self.operate(prepared)
            self.assertEqual(self.posts, before_posts + 1)
            self.assertTrue(result["os_transition_verified"])
            self.n.validate_result(
                admission=self.admission,
                prepared_raw=prepared.raw,
                prepared_sha256=prepared.sha256,
                result=result,
            )
            if kind == "shutdown":
                captured = copy.deepcopy(result)
                original = self.n._native_documents

                def changed(*args):
                    captured["mutation_attempted"] = False
                    return original(*args)

                with mock.patch.object(
                    self.n, "_native_documents", side_effect=changed
                ):
                    with self.assertRaisesRegex(ValueError, "result-input-changed"):
                        self.n.validate_result(
                            admission=self.admission,
                            prepared_raw=prepared.raw,
                            prepared_sha256=prepared.sha256,
                            result=captured,
                        )
            records = result["operation_records"]
            dispatch = self.n.observe.decode(records["dispatch.json"].encode())[
                "payload"
            ]
            ack = self.n.observe.decode(records["ack.json"].encode())["payload"]
            parsed = self.n.journal.api.parse_upid(
                self.binding.guest,
                ack["upid"],
                kind="vzshutdown" if kind == "shutdown" else "vzstart",
            )
            self.assertEqual(parsed["starttime"] - dispatch["clock"], 61)
            args = dict(
                admission=self.admission,
                prepared_raw=prepared.raw,
                prepared_sha256=prepared.sha256,
                accepted_head_sha256=result["head_sha256"],
            )
            if kind == "shutdown":
                raw = self.n.state.canonical(result["before"]["observation"])
                args.update(
                    prior_runtime_raw=raw, prior_runtime_sha256=self.n.state.sha256(raw)
                )
            files = self.native_files()
            status = self.n.status(**args)
            self.assertFalse(status["mutation_attempted"])
            self.assertEqual(self.native_files(), files)
            self.assertEqual(self.posts, before_posts + 1)
            with self.assertRaises(ValueError):
                self.operate(prepared)
            self.assertEqual(self.posts, before_posts + 1)
            head = result["head_sha256"]
            prior = result["before"]["observation"] if kind == "shutdown" else None
        self.assertEqual(self.delayed, 2)
        self.assertEqual(self.old_complete.read_bytes(), self.old_bytes)

    def test_lost_response_is_consumed_failed_and_never_replayed(self):
        prepared = self.prepare()
        self.response_fault = "lost"
        with self.assertRaisesRegex(OSError, "lost response"):
            self.operate(prepared)
        self.assertEqual(self.posts, 1)
        slot = (
            self.n.journal.RUNTIME_ROOT
            / self.binding.pair_key
            / self.n.journal._slot(1)
        )
        self.assertTrue((slot / "failure.json").exists())
        self.assertFalse((slot / "ack-observed.json").exists())
        with self.assertRaises(ValueError):
            self.operate(prepared)
        self.assertEqual(self.posts, 1)

    def test_unqualified_response_is_recorded_before_ack_refusal(self):
        prepared = self.prepare()
        self.response_fault = "unauthorized"
        with self.assertRaises(ValueError):
            self.operate(prepared)
        self.assertEqual(self.posts, 1)
        slot = (
            self.n.journal.RUNTIME_ROOT
            / self.binding.pair_key
            / self.n.journal._slot(1)
        )
        self.assertTrue((slot / "ack-observed.json").exists())
        self.assertTrue((slot / "failure.json").exists())
        self.assertFalse((slot / "ack.json").exists())

    def test_closing_worker_failure_consumes_slot_without_post(self):
        prepared = self.prepare()
        self.f.fault = "worker-exit"
        with self.assertRaisesRegex(ValueError, "final worker failure"):
            self.operate(prepared)
        self.assertEqual(self.posts, 0)
        slot = (
            self.n.journal.RUNTIME_ROOT
            / self.binding.pair_key
            / self.n.journal._slot(1)
        )
        self.assertTrue((slot / "dispatch.json").exists())
        self.assertTrue((slot / "failure.json").exists())

    def test_late_database_write_after_candidate_suppresses_return(self):
        prepared = self.prepare()
        original = self.n.journal._complete

        def changed(*args):
            result = original(*args)
            self.f.samebyte(self.f.db)
            return result

        with mock.patch.object(self.n.journal, "_complete", side_effect=changed):
            with self.assertRaises(ValueError):
                self.operate(prepared)
        self.assertEqual(self.posts, 1)
        slot = (
            self.n.journal.RUNTIME_ROOT
            / self.binding.pair_key
            / self.n.journal._slot(1)
        )
        self.assertTrue((slot / "result.json").exists())
        self.assertTrue((slot / "failure.json").exists())

    def test_native_timeout_records_unknown_and_never_replays(self):
        prepared = self.prepare()
        expired = False

        def running(binding, upid, *, kind):
            nonlocal expired
            task, log = self.task_state(binding, upid, kind=kind)
            task["status"] = "running"
            task.pop("exitstatus")
            expired = True
            return task, log

        with mock.patch.object(
            self.n.journal.api, "task_state", side_effect=running
        ), mock.patch.object(
            self.n.time, "monotonic", side_effect=lambda: 1000 if expired else 0
        ):
            with self.assertRaisesRegex(ValueError, "native-task-timeout"):
                self.operate(prepared)
        self.assertEqual(self.posts, 1)
        slot = (
            self.n.journal.RUNTIME_ROOT
            / self.binding.pair_key
            / self.n.journal._slot(1)
        )
        failure = self.n.observe.decode((slot / "failure.json").read_bytes())
        self.assertEqual(failure["outcome"], "unknown")
        self.assertTrue((slot / "ack-observed.json").exists())
        self.assertTrue((slot / "ack.json").exists())
        self.assertFalse((slot / "terminal.json").exists())
        self.assertFalse((slot / "result.json").exists())
        with self.assertRaises(ValueError):
            self.operate(prepared)
        self.assertEqual(self.posts, 1)
        self.assertEqual(self.old_complete.read_bytes(), self.old_bytes)

    def test_observed_publication_return_failure_blocks_without_another_post(self):
        prepared = self.prepare()
        original = self.n.journal._append_phase
        observation = None

        def failed(operation, stage, payload):
            nonlocal observation
            result = original(operation, stage, payload)
            if stage == "ack-observed":
                observation = copy.deepcopy(payload)
                raise OSError("modeled ack-observed return failure after publication")
            return result

        with mock.patch.object(self.n.journal, "_append_phase", side_effect=failed):
            with self.assertRaisesRegex(OSError, "ack-observed return failure"):
                self.operate(prepared)
        self.assertEqual(self.posts, 1)
        slot = (
            self.n.journal.RUNTIME_ROOT
            / self.binding.pair_key
            / self.n.journal._slot(1)
        )
        captured = self.n.observe.decode((slot / "ack-observed.json").read_bytes())
        self.assertEqual(captured["payload"], observation)
        self.assertTrue((slot / "failure.json").exists())
        self.assertFalse((slot / "ack.json").exists())
        self.assertFalse((slot / "result.json").exists())
        with self.assertRaises(ValueError):
            self.operate(prepared)
        self.assertEqual(self.posts, 1)
        self.assertEqual(self.old_complete.read_bytes(), self.old_bytes)


if __name__ == "__main__":
    unittest.main()
