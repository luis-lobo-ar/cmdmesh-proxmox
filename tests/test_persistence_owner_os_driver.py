"""Owner OS boundary: driver providers modeled, local SDK leases/files real."""

import copy, importlib, json, os, sys, unittest
from pathlib import Path
from unittest import mock

P = Path(__file__).resolve().parents[1]
W = P
sys.path[:0] = [str(P / "ansible"), str(W / "tests")]
importlib.import_module(
    "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_transition"
)
import test_persistence_owner_transition as native_fixture
import test_persistence_owner_checkpoint as codec_fixture

native_fixture.journal_fixture.ROOT = P
NAME = "ansible_collections.cmdmesh.proxmox.plugins.modules.lxc_persistence_owner_os"


def args(action="prepare"):
    values = dict(
        action=action,
        prepared_json="{}",
        prepared_sha256="a" * 64,
        completion_json="{}",
        completion_sha256="b" * 64,
        journal={},
    )
    from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
        persistence_writer_execution as w,
    )

    values["journal"] = {n: "{}" for n in w.NAMES | {"complete.json"}}
    if action in {"initialize", "prepare", "status"}:
        values["head_sha256"] = "c" * 64
    if action == "prepare":
        values["kind"] = "shutdown"
    if action in {"transition", "status"}:
        values.update(
            transition_prepared_json="{}", transition_prepared_sha256="d" * 64
        )
    return values


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.d = importlib.import_module(NAME)

    def codec(self):
        return mock.patch.object(
            self.d.sdk.current.checkpoint_codec,
            "load_writer_checkpoint",
            return_value={"accepted": True},
        )

    def test_permission_disabled_before_codec_for_normal_mutators(self):
        for action in ("initialize", "transition"):
            with self.codec() as codec, mock.patch.object(
                self.d.sdk, action if action == "initialize" else "operate"
            ) as change, self.assertRaises(ValueError):
                self.d.execute(**args(action))
            codec.assert_not_called()
            change.assert_not_called()

    def test_mutating_check_branches_use_readonly_real_preflight_helpers(self):
        for action, name in (
            ("initialize", "inspect_initialization"),
            ("transition", "inspect_transition"),
        ):
            for allow in (False, True):
                with self.codec(), mock.patch.object(
                    self.d.sdk, name, return_value={"would_change": True}
                ) as inspect, mock.patch.object(
                    self.d.sdk, "initialize"
                ) as init, mock.patch.object(
                    self.d.sdk, "operate"
                ) as operate:
                    v = self.d.execute(
                        **args(action), allow_mutation=allow, check_mode=True
                    )
                inspect.assert_called_once()
                init.assert_not_called()
                operate.assert_not_called()
                self.assertTrue(v["changed"])
                self.assertTrue(v["would_change"])
                self.assertFalse(v["mutation_attempted"])
                self.assertFalse(v["os_transition_verified"])
                self.assertFalse(v["metadata_initialized"])

    def test_readonly_actions_have_identical_mode_behavior(self):
        for action, name in (("prepare", "prepare"), ("status", "status")):
            for check in (False, True):
                value = (
                    {"safe": "e" * 64}
                    if action == "prepare"
                    else {
                        "mutation_attempted": False,
                        "os_transition_verified": True,
                        "phase": "stopped",
                    }
                )
                with self.codec(), mock.patch.object(
                    self.d.sdk, name, return_value=value
                ) as call:
                    v = self.d.execute(**args(action), check_mode=check)
                call.assert_called_once()
                self.assertFalse(v["changed"])
                self.assertFalse(v["mutation_attempted"])
                self.assertEqual(
                    v["assessment"], "prepared" if action == "prepare" else "observed"
                )

    def test_argument_scopes_types_bounds_before_codec(self):
        changes = [
            {"action": "resolve"},
            {"allow_mutation": 1},
            {"check_mode": 1},
            {"prepared_json": {}},
            {"journal": {}},
            {"prior_runtime": {"x": "y" * (4194304 + 1)}},
            {"kind": False},
            {"transition_prepared_json": "{}"},
            {"allow_mutation": True},
            {"head_sha256": None},
        ]
        for delta in changes:
            with self.subTest(
                fields=list(delta)
            ), self.codec() as codec, self.assertRaises(ValueError):
                self.d.execute(**dict(args(), **delta))
            codec.assert_not_called()
        for action, delta in (
            ("initialize", {"prior_runtime": {}}),
            ("transition", {"head_sha256": "a" * 64}),
            ("status", {"kind": "shutdown"}),
            ("transition", {"transition_prepared_sha256": None}),
        ):
            with self.codec() as codec, self.assertRaises(ValueError):
                self.d.execute(
                    **dict(
                        args(action),
                        allow_mutation=action in {"initialize", "transition"},
                        **delta
                    )
                )
            codec.assert_not_called()

    def test_normal_initialize_forwards_explicit_proposed_head_with_metadata_only_flags(
        self,
    ):
        with self.codec(), mock.patch.object(
            self.d.sdk,
            "initialize",
            return_value={"changed": True, "head_sha256": "c" * 64},
        ) as initialize:
            value = self.d.execute(**args("initialize"), allow_mutation=True)
        initialize.assert_called_once_with({"accepted": True}, "c" * 64)
        self.assertTrue(value["metadata_initialized"])
        self.assertTrue(value["mutation_attempted"])
        self.assertFalse(value["os_transition_verified"])
        self.assertEqual(value["command_outcome"], "not-dispatched")

    def test_normal_transition_passes_only_pinned_raw_and_produces_canonical_hash(self):
        with self.codec(), mock.patch.object(
            self.d.sdk,
            "operate",
            return_value={"os_transition_verified": True, "safe_hash": "e" * 64},
        ) as op:
            value = self.d.execute(**args("transition"), allow_mutation=True)
        op.assert_called_once_with({"accepted": True}, b"{}", "d" * 64)
        self.assertTrue(value["mutation_attempted"])
        self.assertTrue(value["os_transition_verified"])
        self.assertEqual(
            value["result_sha256"], self.d.state.sha256(value["result_json"].encode())
        )

    def test_initialization_failure_never_reports_native_dispatch(self):
        with self.codec(), mock.patch.object(
            self.d.sdk, "initialize", side_effect=RuntimeError("PRIVATE_INIT")
        ):
            with self.assertRaises(RuntimeError) as caught:
                self.d.execute(**args("initialize"), allow_mutation=True)
        value = self.d.failure(caught.exception)
        self.assertTrue(value["effects_may_exist"])
        self.assertEqual(value["command_outcome"], "not-dispatched")

    def test_static_failure_effects_and_privacy(self):
        with self.codec(), mock.patch.object(
            self.d.sdk, "operate", side_effect=RuntimeError("PRIVATE_SENTINEL")
        ):
            with self.assertRaises(RuntimeError) as caught:
                self.d.execute(**args("transition"), allow_mutation=True)
        failure = self.d.failure(caught.exception)
        self.assertTrue(failure["effects_may_exist"])
        self.assertTrue(failure["mutation_attempted"])
        self.assertFalse(failure["os_transition_verified"])
        self.assertNotIn("PRIVATE", json.dumps(failure))
        with mock.patch.object(
            self.d.sdk.current.checkpoint_codec,
            "load_writer_checkpoint",
            side_effect=RuntimeError("PRIVATE_CODEC"),
        ):
            with self.assertRaises(RuntimeError) as caught:
                self.d.execute(**args("transition"), allow_mutation=True)
        self.assertFalse(self.d.failure(caught.exception)["effects_may_exist"])

    @unittest.skipUnless(
        os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide reference guard"
    )
    def test_actual_codec_rejects_drift_before_sdk_preflight(self):
        case = codec_fixture.OwnerCheckpointTests("runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        values = dict(
            args(),
            prepared_json=case.base.raw.decode(),
            prepared_sha256=case.base.sha,
            completion_json=case.raw.decode(),
            completion_sha256=case.sha,
            journal={n: r.decode() for n, r in case.records.items()},
        )
        with mock.patch.object(
            self.d.sdk, "prepare", return_value={"safe": True}
        ) as prepare:
            self.d.execute(**values)
        prepare.assert_called_once()
        values["journal"]["before-read.json"] = "{}"
        with mock.patch.object(self.d.sdk, "prepare") as prepare, self.assertRaises(
            ValueError
        ):
            self.d.execute(**values)
        prepare.assert_not_called()

    @unittest.skipUnless(
        os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide reference guard"
    )
    def test_real_sdk_receipt_survives_the_module_wire_envelope(self):
        case = native_fixture.OwnerTransitionTests("runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        prepared = case.prepare(case.initialize())
        raw = case.sdk.state.canonical(prepared)
        sha = case.sdk.state.sha256(raw)
        values = dict(
            args("transition"),
            allow_mutation=True,
            transition_prepared_json=raw.decode(),
            transition_prepared_sha256=sha,
        )
        with mock.patch.object(
            self.d.sdk.current.checkpoint_codec,
            "load_writer_checkpoint",
            return_value=case.checkpoint,
        ):
            value = self.d.execute(**values)
        self.assertEqual(
            value["result_sha256"], self.d.state.sha256(value["result_json"].encode())
        )
        receipt = json.loads(value["result_json"])
        self.d.sdk.validate_result(case.checkpoint, raw, sha, receipt)
        self.assertEqual(value["head_sha256"], receipt["head_sha256"])
        self.assertNotEqual(value["result_sha256"], receipt["result_sha256"])
        self.assertTrue(value["application_quiesced"])
        self.assertTrue(value["os_transition_verified"])
        self.assertEqual(value["command_outcome"], "succeeded")
        self.assertEqual(case.post_count, 1)


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide reference guard"
)
class ReadonlyHelperTests(unittest.TestCase):
    def setUp(self):
        self.base = native_fixture.OwnerTransitionTests("runTest")
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.s = self.base.sdk

    def test_initialize_absence_and_existing_genesis_are_readonly(self):
        root = self.s.journal.RUNTIME_ROOT
        before = self.base.case.files()
        original = self.s.journal._initialize
        with mock.patch.object(
            self.s.journal, "_initialize", side_effect=AssertionError("write forbidden")
        ), mock.patch.object(
            self.s.api,
            "post_guest_action",
            side_effect=AssertionError("POST forbidden"),
        ):
            v = self.s.inspect_initialization(
                self.base.checkpoint, self.s.genesis_sha256(self.base.checkpoint)
            )
        self.assertTrue(v["would_change"])
        self.assertEqual(before, self.base.case.files())
        head = self.base.initialize()
        before = self.base.case.files()
        v = self.s.inspect_initialization(self.base.checkpoint, head)
        self.assertFalse(v["would_change"])
        self.assertEqual(before, self.base.case.files())

    def test_initialize_used_or_wrong_profile_refuses_no_repair(self):
        head = self.base.initialize()
        self.base.operate(self.base.prepare(head))
        before = self.base.case.files()
        with self.assertRaises(ValueError):
            self.s.inspect_initialization(self.base.checkpoint, head)
        self.assertEqual(before, self.base.case.files())

    def test_transition_preflight_fresh_init_uptime_and_no_claim_post(self):
        p = self.base.prepare(self.base.initialize())
        raw = self.s.state.canonical(p)
        sha = self.s.state.sha256(raw)
        before = self.base.case.files()
        with mock.patch.object(
            self.s.journal, "_begin", side_effect=AssertionError("claim forbidden")
        ), mock.patch.object(
            self.s.api,
            "post_guest_action",
            side_effect=AssertionError("POST forbidden"),
        ):
            v = self.s.inspect_transition(self.base.checkpoint, raw, sha)
        self.assertTrue(v["would_change"])
        self.assertEqual(before, self.base.case.files())

        def replaced(e):
            e["observation"]["kernel"]["init"]["pstart"] += 1

        self.base.worker_override = replaced
        with self.assertRaises(ValueError):
            self.s.inspect_transition(self.base.checkpoint, raw, sha)
        self.assertEqual(before, self.base.case.files())
        self.assertEqual(self.base.post_count, 0)

    def test_resume_preflight_is_readonly_for_stopped_target(self):
        stopped = self.base.operate(self.base.prepare(self.base.initialize()))
        prepared = self.base.prepare(stopped["head_sha256"], "resume")
        raw = self.s.state.canonical(prepared)
        before = self.base.case.files()
        with mock.patch.object(
            self.s.journal, "_begin", side_effect=AssertionError("claim forbidden")
        ), mock.patch.object(
            self.s.api,
            "post_guest_action",
            side_effect=AssertionError("POST forbidden"),
        ):
            result = self.s.inspect_transition(
                self.base.checkpoint, raw, self.s.state.sha256(raw)
            )
        self.assertTrue(result["would_change"])
        self.assertEqual(before, self.base.case.files())
        self.assertEqual(self.base.post_count, 1)

    def test_partial_and_schema_two_metadata_refuse_without_repair(self):
        root = self.s.journal.RUNTIME_ROOT
        root.mkdir(mode=0o700)
        before = self.base.case.files()
        with self.assertRaises(FileNotFoundError):
            self.s.inspect_initialization(
                self.base.checkpoint, self.s.genesis_sha256(self.base.checkpoint)
            )
        self.assertEqual(before, self.base.case.files())
        path = root / "runtime.json"
        path.write_bytes(
            self.s.state.canonical(dict(self.s.journal.RUNTIME, schema_version=2))
        )
        path.chmod(0o600)
        before = self.base.case.files()
        with self.assertRaises(ValueError):
            self.s.inspect_initialization(
                self.base.checkpoint, self.s.genesis_sha256(self.base.checkpoint)
            )
        self.assertEqual(before, self.base.case.files())

    def test_late_absent_metadata_creation_and_worker_failure_refuse(self):
        head = self.s.genesis_sha256(self.base.checkpoint)
        current = self.s.current._current_leased
        from contextlib import contextmanager

        @contextmanager
        def late(*a, **kw):
            with current(*a, **kw) as frame:
                yield frame
            self.s.journal.RUNTIME_ROOT.mkdir(mode=0o700)

        with mock.patch.object(
            self.s.current, "_current_leased", side_effect=late
        ), self.assertRaises(ValueError):
            self.s.inspect_initialization(self.base.checkpoint, head)


if __name__ == "__main__":
    unittest.main()
