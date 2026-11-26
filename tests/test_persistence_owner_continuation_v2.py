"""Version2 plans select fresh admission without executing any publication."""

import copy
import importlib
import os
import unittest
from unittest import mock

import test_persistence_owner_completion as fixture
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_attempt as attempt,
    persistence_owner_continuation as previous,
    persistence_owner_storage_profile as storage,
)


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class ContinuationV2Tests(unittest.TestCase):
    def setUp(self):
        self.codec = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_continuation_v2"
        )
        self.case = fixture.CompletionTests("runTest")
        self.case.prepare_old_completion = False
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.r = self.case.old.r
        self.enterContext(
            mock.patch.object(attempt, "_WALK_ROOT", self.case.old.base.root.parent)
        )

    def capture(self):
        with attempt.inspect_attempt(
            self.case.owner, self.case.h0, self.case.h0sha
        ) as view:
            return view.raw

    def options(self, action, capture=None):
        raw = self.capture() if capture is None else capture
        return dict(
            **self.case.arguments(),
            capture_raw=raw,
            capture_sha256=self.r.state.sha256(raw),
            action=action
        )

    def test_four_missing_only_plans_require_semantic2_and_fresh_phase_policy(self):
        self.r.RUNTIME_ROOT.mkdir(mode=0o700)
        for step, action in enumerate(
            ("finish-runtime", "record-intent", "publish-marker", "record-completion")
        ):
            if step == 1:
                self.r.backup.write_private(
                    self.r.RUNTIME_ROOT / "runtime.json", storage.RUNTIME
                )
                self.case.old.path.mkdir(mode=0o700)
            elif step == 2:
                self.r.backup.write_private(
                    self.case.old.path / "intent.json",
                    self.r.observe.decode(self.case.h0),
                )
            elif step == 3:
                self.r.backup.write_private(
                    self.case.old.base.path() / self.r.MARKER,
                    self.r._marker(self.case.owner, self.case.h0sha),
                )
            args = self.options(action)
            before = copy.deepcopy(args)
            with mock.patch.object(
                self.r.os, "open", side_effect=AssertionError("plan IO")
            ):
                plan = self.codec.prepare_continuation(**args)
                body = self.codec.load_continuation(
                    **args, plan_raw=plan.raw, plan_sha256=plan.sha256
                )
            with self.subTest(action=action):
                self.assertEqual(body["schema_version"], 2)
                self.assertEqual(body["completion_schema_version"], 2)
                self.assertEqual(
                    body["publication_contract_sha256"], self.case.contract.sha256
                )
                self.assertEqual(
                    body["phase_admission_policy"]["phases"], ["os_quiesced", "stopped"]
                )
                self.assertNotIn("required_host_epoch", body)
                self.assertNotIn("required_current_phase", body)
                self.assertNotIn("required_worker_fence_sha256", body)
                self.assertEqual(
                    body["historical_worker_fence_sha256"],
                    self.case.old.evidence["worker_fence_sha256"],
                )
                self.assertFalse(body["publication_authorized"])
                self.assertFalse(body["successor_native_admission_authorized"])
                self.assertTrue(body["destination_must_remain_absent"])
                self.assertEqual(args, before)

    def test_old_plan_one_cannot_pass_new_loader(self):
        self.r.RUNTIME_ROOT.mkdir(mode=0o700)
        args = self.options("finish-runtime")
        old = previous.prepare_continuation(
            self.case.owner,
            self.case.h0,
            self.case.h0sha,
            args["capture_raw"],
            args["capture_sha256"],
            args["action"],
        )
        with self.assertRaises(ValueError):
            self.codec.load_continuation(
                **args, plan_raw=old.raw, plan_sha256=old.sha256
            )

    def test_contract_capture_action_and_fresh_policy_changes_refuse(self):
        self.r.RUNTIME_ROOT.mkdir(mode=0o700)
        args = self.options("finish-runtime")
        plan = self.codec.prepare_continuation(**args)
        original = self.r.observe.decode(plan.raw)
        for field, value in (
            ("schema_version", True),
            ("completion_schema_version", 1),
            ("publication_contract_sha256", "0" * 64),
            ("phase_admission_policy", {}),
            ("required_host_epoch", self.case.old.evidence["host_epoch"]),
            ("publication_authorized", True),
            ("destination", "/tmp/other"),
        ):
            changed = copy.deepcopy(original)
            changed[field] = value
            raw = self.r.state.canonical(changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.codec.load_continuation(
                    **args, plan_raw=raw, plan_sha256=self.r.state.sha256(raw)
                )
        for field in ("contract_sha256", "capture_sha256", "checkpoint_sha256"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.codec.prepare_continuation(**{**args, field: "0" * 64})
        with self.assertRaises(ValueError):
            self.codec.prepare_continuation(**{**args, "action": "record-completion"})

    def test_unused_and_complete_candidates_never_select_a_publication(self):
        for action in (
            "finish-runtime",
            "record-intent",
            "publish-marker",
            "record-completion",
        ):
            with self.subTest(stage="unused", action=action), self.assertRaises(
                ValueError
            ):
                self.codec.prepare_continuation(**self.options(action))
        self.case.old.complete()
        (self.r.RUNTIME_ROOT / "runtime.json").write_bytes(
            self.r.state.canonical(storage.RUNTIME)
        )
        for action in (
            "finish-runtime",
            "record-intent",
            "publish-marker",
            "record-completion",
        ):
            with self.subTest(stage="complete", action=action), self.assertRaises(
                ValueError
            ):
                self.codec.prepare_continuation(**self.options(action))

    def test_loader_recloses_decoded_plan_after_reconstruction(self):
        self.r.RUNTIME_ROOT.mkdir(mode=0o700)
        args = self.options("finish-runtime")
        plan = self.codec.prepare_continuation(**args)
        decode, canonical = self.r._decode, self.r.state.canonical
        selected = []

        def track(raw, sha, *limits):
            value = decode(raw, sha, *limits)
            if raw == plan.raw:
                selected.append(value)
            return value

        def mutate(value):
            raw = canonical(value)
            if (
                selected
                and type(value) is dict
                and value.get("schema_version") == 2
                and value.get("document_type", "").endswith(".continuation-plan")
            ):
                selected[0]["publication_authorized"] = True
            return raw

        with mock.patch.object(self.r, "_decode", side_effect=track), mock.patch.object(
            self.r.state, "canonical", side_effect=mutate
        ), self.assertRaises(ValueError):
            self.codec.load_continuation(
                **args, plan_raw=plan.raw, plan_sha256=plan.sha256
            )
