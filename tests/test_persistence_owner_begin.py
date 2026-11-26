"""Clean-begin plans from actual disposable capture2, without execution."""

import copy
import importlib
import os
import unittest
from unittest import mock

import test_persistence_owner_continuation_v2 as fixture


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class BeginTests(unittest.TestCase):
    def setUp(self):
        self.module = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_begin"
        )
        self.fixture = fixture.ContinuationV2Tests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.case = self.fixture.case
        self.r = self.fixture.r

    def options(self):
        arguments = self.fixture.options("begin")
        del arguments["action"]
        return arguments

    def plan(self):
        args = self.options()
        result = self.module.prepare_begin(**args)
        return (
            args,
            result,
            self.module.load_begin(
                **args, plan_raw=result.raw, plan_sha256=result.sha256
            ),
        )

    def test_absent_runtime_plans_only_fixed_root_runtime_pair_and_h0(self):
        args, result, body = self.plan()
        root = self.r.RUNTIME_ROOT
        pair = root / self.case.owner.pair_key
        self.assertEqual(body["stage"], "unused")
        self.assertEqual(body["action"], "begin")
        self.assertEqual(body["schema_version"], 2)
        self.assertEqual(body["final_stage"], "h0-only")
        self.assertEqual(
            [item["path"] for item in body["operations"]],
            [
                str(root),
                str(root / "runtime.json"),
                str(pair),
                str(pair / "intent.json"),
            ],
        )
        self.assertEqual(
            [item["operation"] for item in body["operations"]],
            ["mkdir", "publish", "mkdir", "publish"],
        )
        self.assertEqual(body["operations"][0]["mode"], 0o700)
        self.assertEqual(body["operations"][2]["mode"], 0o700)
        self.assertEqual(body["operations"][-1]["payload_sha256"], self.case.h0sha)
        self.assertEqual(body["publication_contract_sha256"], self.case.contract.sha256)
        self.assertFalse(body["publication_authorized"])
        self.assertFalse(body["native_action_dispatched"])
        self.assertFalse(root.exists())
        self.assertEqual(result.sha256, self.r.state.sha256(result.raw))
        self.assertEqual(body["capture_sha256"], args["capture_sha256"])

    def test_current_shared_runtime_plans_only_own_pair_and_h0(self):
        root = self.r.RUNTIME_ROOT
        root.mkdir(mode=0o700)
        self.r.backup.write_private(root / "runtime.json", fixture.storage.RUNTIME)
        before = (root / "runtime.json").read_bytes()
        _, _, body = self.plan()
        self.assertEqual(
            [item["operation"] for item in body["operations"]], ["mkdir", "publish"]
        )
        self.assertEqual(body["operations"][0]["role"], "pair")
        self.assertIsNone(body["bootstrap_mutex"])
        self.assertEqual((root / "runtime.json").read_bytes(), before)
        self.assertFalse(self.case.old.path.exists())

    def test_partial_runtime_existing_pair_and_h0_are_not_clean_begin(self):
        root = self.r.RUNTIME_ROOT
        root.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.plan()
        self.r.backup.write_private(root / "runtime.json", fixture.storage.RUNTIME)
        self.case.old.path.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.plan()
        self.r.backup.write_private(
            self.case.old.path / "intent.json", self.r.observe.decode(self.case.h0)
        )
        with self.assertRaises(ValueError):
            self.plan()

    def test_plan_cannot_be_changed_into_an_unselected_path_or_permission(self):
        args, result, body = self.plan()
        changes = (
            ("schema_version", True),
            ("publication_authorized", True),
            ("final_stage", "complete-candidate"),
            ("action", "publish-marker"),
            ("publication_contract_sha256", "0" * 64),
            ("unexpected", False),
        )
        for key, value in changes:
            changed = copy.deepcopy(body)
            changed[key] = value
            raw = self.r.state.canonical(changed)
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.module.load_begin(
                    **args, plan_raw=raw, plan_sha256=self.r.state.sha256(raw)
                )
        changed = copy.deepcopy(body)
        changed["operations"][0]["path"] = "/unselected"
        raw = self.r.state.canonical(changed)
        with self.assertRaises(ValueError):
            self.module.load_begin(
                **args, plan_raw=raw, plan_sha256=self.r.state.sha256(raw)
            )

    def test_selection_capture_and_legacy_schema_refuse_without_io(self):
        args = self.options()
        legacy = self.fixture.legacy_capture()
        cases = [
            {**args, key: "0" * 64}
            for key in (
                "checkpoint_sha256",
                "intent_sha256",
                "contract_sha256",
                "capture_sha256",
            )
        ]
        cases.append(
            {
                **args,
                "capture_raw": legacy,
                "capture_sha256": self.r.state.sha256(legacy),
            }
        )
        with mock.patch.object(
            self.r.os, "open", side_effect=AssertionError("plan IO")
        ):
            for changed in cases:
                with self.subTest(keys=tuple(changed)), self.assertRaises(ValueError):
                    self.module.prepare_begin(**changed)

    def test_pure_reconstruction_preserves_selected_input_bytes(self):
        args = self.options()
        before = copy.deepcopy(args)
        with mock.patch.object(
            self.r.os, "open", side_effect=AssertionError("plan IO")
        ):
            result = self.module.prepare_begin(**args)
            body = self.module.load_begin(
                **args, plan_raw=result.raw, plan_sha256=result.sha256
            )
        self.assertEqual(args, before)
        self.assertEqual(body["completion_schema_version"], 2)
        self.assertEqual(
            body["phase_admission_policy"],
            self.r.observe.decode(self.case.contract.raw)["phase_policy"],
        )
