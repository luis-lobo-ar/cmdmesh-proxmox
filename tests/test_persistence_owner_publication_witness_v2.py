"""Semantic2 with actual disposable publication events, no managed authority."""

import os
from contextlib import ExitStack
import unittest
from unittest import mock

import test_persistence_owner_completion as fixture
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_publication_witness as witness,
)


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class PublicationWitnessV2Tests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.CompletionTests("runTest")
        self.case.prepare_old_completion = False
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.r = self.case.old.r
        self.enterContext(
            mock.patch.object(
                witness.attempt, "_WALK_ROOT", self.case.old.base.root.parent
            )
        )

    def descriptor(self, path):
        return dict(
            path=str(path),
            sha256=self.r.state.sha256(path.read_bytes()),
            identity=list(self.r.observe.stable(path.stat())),
        )

    def prepare(self, action, phase="os_quiesced", new_epoch=False):
        root, pair = self.r.RUNTIME_ROOT, self.case.old.path
        root.mkdir(mode=0o700)
        if action == "finish-runtime":
            return (
                None,
                None,
                root / "runtime.json",
                self.r.state.canonical(witness.profile.RUNTIME),
            )
        self.r.backup.write_private(root / "runtime.json", witness.profile.RUNTIME)
        pair.mkdir(mode=0o700)
        if action == "record-intent":
            return None, None, pair / "intent.json", self.case.h0
        self.r.backup.write_private(
            pair / "intent.json", self.r.observe.decode(self.case.h0)
        )
        marker_path = self.case.old.base.path() / self.r.MARKER
        marker = self.r._marker(self.case.owner, self.case.h0sha)
        if action == "publish-marker":
            return None, None, marker_path, self.r.state.canonical(marker)
        self.r.backup.write_private(marker_path, marker)
        result = self.case.codec.prepare_completion(
            **self.case.arguments(),
            intent_file=self.descriptor(pair / "intent.json"),
            marker_file=self.descriptor(marker_path),
            closing=self.case.closing(phase, new_epoch)
        )
        return result.raw, result.sha256, pair / "complete.json", result.raw

    def scope(self, action, raw=None, sha=None, **changes):
        args = {
            **self.case.arguments(),
            "action": action,
            "event_profile": witness.EVENT_PROFILE,
            "complete_raw": raw,
            "complete_sha256": sha,
        }
        args.update(changes)
        return witness.observe_control_publication_v2(**args)

    def successful(self, action, phase="os_quiesced", new_epoch=False):
        raw, sha, path, expected = self.prepare(action, phase, new_epoch)
        old = self.case.old.originals()
        with self.scope(action, raw, sha) as publication:
            receipt = publication.publish()
            self.assertIs(publication.receipt, receipt)
        self.assertTrue(publication.closed)
        self.assertEqual(path.read_bytes(), expected)
        self.assertEqual(receipt.payload_sha256, self.r.state.sha256(expected))
        self.case.old.assert_preserved(old)

    def test_runtime_remains_identical_storage2(self):
        self.successful("finish-runtime")

    def test_intent_is_exact_accepted_h0(self):
        self.successful("record-intent")

    def test_marker_is_exact_derived_marker(self):
        self.successful("publish-marker")

    def test_running_completion_uses_semantic2(self):
        self.successful("record-completion")

    def test_stopped_completion_uses_real_stopped_schema(self):
        self.successful("record-completion", "stopped")

    def test_new_boot_completion_keeps_historical_evidence(self):
        self.successful("record-completion", "stopped", True)

    def test_all_actions_require_decoded_checkpoint_and_contract_before_observer_io(
        self,
    ):
        for action in (
            "finish-runtime",
            "record-intent",
            "publish-marker",
            "record-completion",
        ):
            for change in (
                {"checkpoint": None},
                {"checkpoint_sha256": "0" * 64},
                {"contract_sha256": "0" * 64},
                {"contract_raw": b"{}"},
            ):
                with self.subTest(
                    action=action, change=tuple(change)
                ), mock.patch.object(
                    witness.attempt,
                    "_Reader",
                    side_effect=AssertionError("observer IO before selection"),
                ), self.assertRaises(
                    ValueError
                ):
                    with self.scope(action, **change):
                        pass

    def test_legacy_completion_is_never_written_by_v2(self):
        raw, sha, path, _ = self.prepare("record-completion")
        value = self.r.observe.decode(raw)
        legacy = self.r._completion(
            self.case.owner,
            self.case.h0sha,
            value["intent_file"],
            self.r.state.canonical(value["marker"]),
            value["marker_file"],
            self.case.old.intent["basis"],
            self.case.old.evidence,
        )
        raw = self.r.state.canonical(legacy)
        sha = self.r.state.sha256(raw)
        self.r.validate_handoff(
            self.case.owner, self.case.h0, self.case.h0sha, raw, sha
        )
        with mock.patch.object(
            witness.attempt, "_Reader", side_effect=AssertionError("observer IO")
        ), self.assertRaises(ValueError):
            with self.scope("record-completion", raw, sha):
                pass
        self.assertFalse(path.exists())

    def test_completion_descriptors_must_match_actual_held_dependencies(self):
        raw, sha, path, _ = self.prepare("record-completion")
        value = self.r.observe.decode(raw)
        value["intent_file"]["identity"][1] += 1
        raw = self.r.state.canonical(value)
        sha = self.r.state.sha256(raw)
        self.case.codec.validate_completion(
            **self.case.arguments(), complete_raw=raw, complete_sha256=sha
        )
        with self.assertRaises(ValueError):
            with self.scope("record-completion", raw, sha) as publication:
                publication.publish()
        self.assertFalse(path.exists())

    def test_checkpoint_drift_in_last_prewrite_event_read_refuses_without_write(self):
        _, _, path, _ = self.prepare("record-intent")
        original = witness.attempt._Reader.check_events
        armed = False

        def mutate(reader):
            original(reader)
            if armed:
                self.case.cp["completion"]["runtime"]["application"][
                    "record_count"
                ] += 1

        with mock.patch.object(
            witness.attempt._Reader, "check_events", side_effect=mutate, autospec=True
        ), self.assertRaises(ValueError):
            with self.scope("record-intent") as publication:
                armed = True
                publication.publish()
        self.assertFalse(path.exists())

    def test_postpublication_checkpoint_drift_leaves_unaccepted_candidate(self):
        _, _, path, _ = self.prepare("record-intent")
        with self.assertRaises(ValueError):
            with self.scope("record-intent") as publication:
                publication.publish()
                self.case.cp["completion"]["runtime"]["application"][
                    "record_count"
                ] += 1
        self.assertTrue(path.exists())

    def test_selection_cannot_be_removed_to_bypass_prewrite_checks(self):
        _, _, path, _ = self.prepare("record-intent")
        with self.assertRaises(ValueError):
            with self.scope("record-intent") as publication:
                publication._selection = None
                publication.publish()
        self.assertFalse(path.exists())

    def test_selection_change_during_last_prewrite_validation_refuses_before_write(
        self,
    ):
        _, _, path, _ = self.prepare("record-intent")
        original_events = witness.attempt._Reader.check_events
        original_validate = witness.semantics.Selection.validate
        selected = None
        armed = False

        def events(reader):
            nonlocal armed
            original_events(reader)
            if (
                selected is not None
                and reader is selected._parent
                and selected._attempted
            ):
                armed = True

        def validate(selection):
            original_validate(selection)
            if armed:
                selected._selection = None

        with mock.patch.object(
            witness.attempt._Reader, "check_events", autospec=True, side_effect=events
        ), mock.patch.object(
            witness.semantics.Selection, "validate", autospec=True, side_effect=validate
        ), self.assertRaises(
            ValueError
        ):
            with self.scope("record-intent") as publication:
                selected = publication
                publication.publish()
        self.assertFalse(path.exists())

    def test_same_byte_dependency_write_is_not_hidden_by_semantic_validation(self):
        raw, sha, path, _ = self.prepare("record-completion")
        h0 = self.case.old.path / "intent.json"
        with self.assertRaises(ValueError):
            with self.scope("record-completion", raw, sha) as publication:
                h0.write_bytes(h0.read_bytes())
                publication.publish()
        self.assertFalse(path.exists())

    def test_private_checkpoint_change_after_last_validator_refuses_before_write(self):
        _, _, path, _ = self.prepare("record-intent")
        events = witness.attempt._Reader.check_events
        validate = witness.semantics.Selection.validate
        publication = None
        armed = False

        def observed(reader):
            nonlocal armed
            events(reader)
            if (
                publication is not None
                and reader is publication._parent
                and publication._attempted
            ):
                armed = True

        def changed(selection):
            validate(selection)
            if armed:
                selection._private_checkpoint["completion"]["runtime"]["application"][
                    "record_count"
                ] += 1

        with mock.patch.object(
            witness.attempt._Reader, "check_events", autospec=True, side_effect=observed
        ), mock.patch.object(
            witness.semantics.Selection, "validate", autospec=True, side_effect=changed
        ), self.assertRaises(
            ValueError
        ):
            with self.scope("record-intent") as current:
                publication = current
                current.publish()
        self.assertFalse(path.exists())

    def test_caught_failure_is_still_poisoned(self):
        self.prepare("record-intent")
        with self.assertRaises(ValueError):
            with self.scope("record-intent") as publication:
                publication.publish()
                with self.assertRaises(ValueError):
                    publication.publish()

    def test_planned_witness_overlaps_inspector_then_intent_can_publish(self):
        _, _, path, expected = self.prepare("record-intent")
        with ExitStack() as stack:
            with witness.attempt.inspect_attempt_v2(
                **self.case.arguments()
            ) as observation:
                publication = stack.enter_context(self.scope("record-intent"))
                self.assertEqual(
                    self.r.observe.decode(observation.raw)["status"], "empty-claim"
                )
            self.assertTrue(observation.seal.closed)
            publication.publish()
        self.assertTrue(publication.closed)
        self.assertEqual(path.read_bytes(), expected)

    def test_overlapping_witness_does_not_hide_old_file_write_from_inspector(self):
        _, _, path, _ = self.prepare("record-intent")
        old = self.case.old.base.path() / "HEAD.json"
        with self.assertRaises(ValueError):
            with ExitStack() as stack:
                with self.assertRaises(ValueError):
                    with witness.attempt.inspect_attempt_v2(**self.case.arguments()):
                        stack.enter_context(self.scope("record-intent"))
                        old.write_bytes(old.read_bytes())
        self.assertFalse(path.exists())

    def test_release_failure_suppresses_success_after_complete_file(self):
        raw, sha, path, _ = self.prepare("record-completion")
        release = witness.attempt._Reader.release

        def fail(reader):
            release(reader)
            raise ValueError("synthetic release error")

        with mock.patch.object(
            witness.attempt._Reader, "release", side_effect=fail, autospec=True
        ), self.assertRaises(ValueError):
            with self.scope("record-completion", raw, sha) as publication:
                publication.publish()
        self.assertTrue(path.exists())
