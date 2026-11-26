"""Finite metadata continuation plans do not execute or authorize their actions."""

import copy
from contextlib import ExitStack
import json
import unittest
from unittest import mock

import test_persistence_owner_attempt_codec as fixture
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_continuation as continuation,
    persistence_owner_storage_profile as profile,
)


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.AttemptCodecTests("runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.attempt_fixture = self.case.case
        self.retirement_fixture = self.attempt_fixture.case
        self.r = self.case.r
        self.owner = self.retirement_fixture.owner
        self.h0, self.h0_sha = self.attempt_fixture.h0, self.attempt_fixture.sha

    def prepare(self, action, raw=None):
        raw = self.case.capture() if raw is None else raw

        def forbidden(*args, **kwargs):
            raise AssertionError("plan performed IO")

        with ExitStack() as stack:
            for name in (
                "os.open",
                "os.stat",
                "os.fstat",
                "os.scandir",
                "pathlib.Path.read_bytes",
                "pathlib.Path.resolve",
                "subprocess.Popen",
                "socket.socket",
                "sqlite3.connect",
            ):
                stack.enter_context(mock.patch(name, side_effect=forbidden))
            return continuation.prepare_continuation(
                self.owner, self.h0, self.h0_sha, raw, self.r.state.sha256(raw), action
            )

    def bootstrap(self):
        self.r.RUNTIME_ROOT.mkdir(mode=0o700)

    def empty_claim(self):
        self.attempt_fixture.version_two()
        self.retirement_fixture.path.mkdir(mode=0o700)

    def h0_only(self):
        self.attempt_fixture.claim()

    def h0_marker(self):
        self.h0_only()
        self.r.backup.write_private(
            self.retirement_fixture.base.path() / self.r.MARKER,
            self.r._marker(self.owner, self.h0_sha),
        )

    def test_four_exact_edges_return_bounded_frozen_plans(self):
        cases = [
            ("bootstrap-incomplete", "finish-runtime"),
            ("empty-claim", "record-intent"),
            ("h0-only", "publish-marker"),
            ("h0-marker", "record-completion"),
        ]
        self.bootstrap()
        for index, (stage, action) in enumerate(cases):
            if index == 1:
                self.r.backup.write_private(
                    self.r.RUNTIME_ROOT / "runtime.json",
                    profile.RUNTIME,
                )
                self.retirement_fixture.path.mkdir(mode=0o700)
            elif index == 2:
                self.r.backup.write_private(
                    self.retirement_fixture.path / "intent.json", json.loads(self.h0)
                )
            elif index == 3:
                self.r.backup.write_private(
                    self.retirement_fixture.base.path() / self.r.MARKER,
                    self.r._marker(self.owner, self.h0_sha),
                )
            plan = self.prepare(action)
            body = json.loads(plan.raw)
            with self.subTest(stage=stage):
                self.assertEqual(body["stage"], stage)
                self.assertEqual(body["action"], action)
                self.assertEqual(plan.sha256, self.r.state.sha256(plan.raw))
                self.assertTrue(body["candidate_only"])
                for flag in (
                    "producer_authenticated",
                    "current_admitted",
                    "publication_authorized",
                    "native_action_dispatched",
                    "successor_native_admission_authorized",
                ):
                    self.assertIs(body[flag], False)
                with self.assertRaises(AttributeError):
                    plan.raw = b"changed"

    def test_wrong_actions_aliases_and_non_strings_refuse(self):
        self.bootstrap()
        for action in (
            "record-intent",
            "publish-marker",
            "record-completion",
            "resume",
            "",
            True,
            [],
            {},
            None,
        ):
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.prepare(action)

    def test_unused_and_complete_candidates_have_separate_paths(self):
        with self.assertRaises(ValueError):
            self.prepare("finish-runtime")
        self.retirement_fixture.complete()
        (self.r.RUNTIME_ROOT / "runtime.json").write_bytes(
            self.r.state.canonical(profile.RUNTIME)
        )
        for action in (
            "finish-runtime",
            "record-intent",
            "publish-marker",
            "record-completion",
        ):
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.prepare(action)

    def test_payloads_and_destinations_are_source_derived(self):
        self.h0_only()
        value = json.loads(self.prepare("publish-marker").raw)
        expected = self.r.state.canonical(self.r._marker(self.owner, self.h0_sha))
        self.assertEqual(
            value["destination"],
            str(self.retirement_fixture.base.path() / self.r.MARKER),
        )
        self.assertEqual(value["payload_sha256"], self.r.state.sha256(expected))
        self.assertEqual(value["payload_size"], len(expected))
        self.assertTrue(value["destination_must_remain_absent"])

    def test_completion_never_invents_closing_evidence(self):
        self.h0_marker()
        value = json.loads(self.prepare("record-completion").raw)
        self.assertIsNone(value["payload_sha256"])
        self.assertIsNone(value["payload_size"])
        self.assertEqual(value["payload_source"], "fresh-closing-evidence")
        self.assertEqual(value["required_current_phase"], "os_quiesced")
        self.assertEqual(
            value["unsupported_phase_or_epoch"], "phase-aware-reconciliation-required"
        )
        self.assertNotIn("closing_evidence", value)

    def test_shared_churn_changes_capture_but_not_required_projection(self):
        self.empty_claim()
        raw = self.case.capture()
        body = json.loads(raw)
        original = json.loads(self.prepare("record-intent", raw).raw)
        for path, fields in body["directory_closure_fields"].items():
            if fields == 5:
                body["directories"][path][5] += 1
                body["directories"][path][6] += 100
                body["directories"][path][7] += 100
                body["directories"][path][8] += 100
        changed = self.r.state.canonical(body)
        current = json.loads(self.prepare("record-intent", changed).raw)
        self.assertNotEqual(original["capture_sha256"], current["capture_sha256"])
        self.assertEqual(
            original["expected_fresh_projection_sha256"],
            current["expected_fresh_projection_sha256"],
        )
        owned = next(p for p, n in body["directory_closure_fields"].items() if n == 9)
        body["directories"][owned][7] += 1
        other = json.loads(
            self.prepare("record-intent", self.r.state.canonical(body)).raw
        )
        self.assertNotEqual(
            current["expected_fresh_projection_sha256"],
            other["expected_fresh_projection_sha256"],
        )

    def test_rehashed_fake_capture_and_profile_drift_refuse(self):
        self.bootstrap()
        raw = self.case.capture()
        body = json.loads(raw)
        body["status"] = "h0-only"
        with self.assertRaises(ValueError):
            self.prepare("publish-marker", self.r.state.canonical(body))
        original = continuation.codec.validate_capture

        def drift(*args):
            value = original(*args)
            continuation.COMPARISON_POLICY["files"] = "ignore"
            return value

        with mock.patch.object(
            continuation,
            "COMPARISON_POLICY",
            copy.deepcopy(continuation.COMPARISON_POLICY),
        ), mock.patch.object(continuation.codec, "validate_capture", side_effect=drift):
            with self.assertRaises(ValueError):
                self.prepare("finish-runtime", raw)


if __name__ == "__main__":
    unittest.main()
