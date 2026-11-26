"""Finite selection and local forensic capture; no producer or native authority."""

import base64
import copy
import importlib
import os
import unittest
from unittest import mock

import test_persistence_owner_completion as fixtures
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_attempt as attempt,
    persistence_owner_attempt_codec as codec,
    persistence_owner_storage_profile as storage,
)


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class SemanticSelectionTests(unittest.TestCase):
    def setUp(self):
        self.case = fixtures.CompletionTests("runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.semantics = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_semantics"
        )
        self.r = self.case.old.r
        self.enterContext(
            mock.patch.object(attempt, "_WALK_ROOT", self.case.old.base.root.parent)
        )
        self.runtime_file = self.r.RUNTIME_ROOT / "runtime.json"
        self.runtime_file.write_bytes(self.r.state.canonical(storage.RUNTIME))

    def selected(self, **changes):
        return self.semantics.select(**{**self.case.arguments(), **changes})

    def capture(self):
        with attempt.inspect_attempt_v2(**self.case.arguments()) as observation:
            raw, sha = observation.raw, observation.sha256
        self.assertTrue(observation.seal.closed)
        return self.r.observe.decode(raw), raw, sha

    def replay(self, raw, sha):
        return codec.validate_capture_v2(
            **self.case.arguments(), capture_raw=raw, capture_sha256=sha
        )

    def test_selection_and_semantic_two_completion_are_pure(self):
        document = self.case.candidate(closing=self.case.closing("stopped", True))
        before = copy.deepcopy(self.case.cp)
        with mock.patch.object(
            self.r.os, "open", side_effect=AssertionError("selection IO")
        ):
            selected = self.selected()
            self.assertIsNone(selected.validate())
            body = selected.completion(document.raw, document.sha256)
        self.assertEqual(body["schema_version"], 2)
        self.assertEqual(selected.checkpoint_sha256, self.case.cp_sha)
        self.assertEqual(selected.contract_sha256, self.case.contract.sha256)
        self.assertEqual(self.case.cp, before)

    def test_schema_one_requires_explicit_forensic_flag(self):
        selected = self.selected()
        old = self.case.complete_v1
        with self.assertRaises(ValueError):
            selected.completion(old.raw, old.sha256)
        self.assertEqual(
            selected.completion(old.raw, old.sha256, allow_historical=True)[
                "schema_version"
            ],
            1,
        )
        with self.assertRaises(ValueError):
            selected.completion(old.raw, old.sha256, allow_historical=1)

    def test_original_and_private_checkpoint_and_pin_mutations_refuse(self):
        for subject in ("original", "private", "pin"):
            original = copy.deepcopy(self.case.cp)
            selected = self.selected()
            if subject == "original":
                self.case.cp["completion"]["runtime"]["application"][
                    "record_count"
                ] += 1
            elif subject == "private":
                selected._private_checkpoint["completion"]["runtime"]["application"][
                    "record_count"
                ] += 1
            else:
                object.__setattr__(selected, "checkpoint_sha256", "f" * 64)
            with self.subTest(subject=subject), self.assertRaises(ValueError):
                selected.validate()
            self.case.cp.clear()
            self.case.cp.update(original)

    def test_wrong_pins_and_opaque_checkpoint_refuse_before_observer(self):
        for changes in (
            {"checkpoint_sha256": "0" * 64},
            {"contract_sha256": "0" * 64},
            {"checkpoint": self.case.cp_sha},
        ):
            with self.subTest(changes=changes), mock.patch.object(
                attempt,
                "_Reader",
                side_effect=AssertionError("observer before selection"),
            ), self.assertRaises(ValueError):
                with attempt.inspect_attempt_v2(**{**self.case.arguments(), **changes}):
                    pass

    def test_historical_candidate_replays_without_authority(self):
        body, raw, sha = self.capture()
        self.assertEqual(body["schema_version"], 2)
        self.assertEqual(body["status"], "complete-candidate")
        self.assertEqual(body["completion_schema_version"], 1)
        self.assertEqual(
            body["completion_disposition"], "historical-requalification-required"
        )
        self.assertEqual(self.replay(raw, sha), body)
        for flag in (
            "publication_authorized",
            "metadata_resolution_recorded",
            "native_action_dispatched",
            "original_request_fenced",
            "successor_native_admission_authorized",
        ):
            self.assertIs(body[flag], False)

    def test_semantic_two_candidate_replays_and_legacy_api_remains_one(self):
        document = self.case.candidate(closing=self.case.closing("stopped", True))
        # Setup only: this is not evidence that a publisher or executor works.
        path = self.case.old.path / "complete.json"
        path.write_bytes(document.raw)
        body, raw, sha = self.capture()
        self.assertEqual(body["completion_schema_version"], 2)
        self.assertEqual(body["completion_disposition"], "semantic2-candidate")
        self.assertEqual(self.replay(raw, sha), body)
        with attempt.inspect_attempt(
            self.case.owner, self.case.h0, self.case.h0sha
        ) as old:
            legacy = self.r.observe.decode(old.raw)
        self.assertEqual(legacy["schema_version"], 1)
        self.assertEqual(legacy["status"], "blocked")
        self.assertNotIn("completion_disposition", legacy)

    def test_absent_completion_and_partial_completion_are_distinct(self):
        path = self.case.old.path / "complete.json"
        path.unlink()
        body, raw, sha = self.capture()
        self.assertEqual(body["status"], "h0-marker")
        self.assertIsNone(body["completion_schema_version"])
        self.assertEqual(body["completion_disposition"], "absent")
        self.assertEqual(self.replay(raw, sha), body)
        for data in (b"", b'{"partial":', b'{"schema_version":true}'):
            path.write_bytes(data)
            path.chmod(0o600)
            body, raw, sha = self.capture()
            self.assertEqual(body["status"], "blocked")
            self.assertEqual(body["completion_disposition"], "invalid")
            self.assertEqual(
                base64.b64decode(body["files"][str(path)]["raw_base64"]), data
            )
            with self.assertRaises(ValueError):
                self.replay(raw, sha)

    def test_capture_external_pins_schema_and_fact_omissions_refuse(self):
        body, _, _ = self.capture()
        for field, value in (
            ("schema_version", 1),
            ("checkpoint_sha256", "0" * 64),
            ("publication_contract_sha256", "0" * 64),
            ("completion_schema_version", True),
            ("completion_disposition", "semantic2-candidate"),
        ):
            changed = copy.deepcopy(body)
            changed[field] = value
            raw = self.r.state.canonical(changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.replay(raw, self.r.state.sha256(raw))
        changed = copy.deepcopy(body)
        del changed["files"][str(self.case.old.path / "intent.json")]
        raw = self.r.state.canonical(changed)
        with self.assertRaises(ValueError):
            self.replay(raw, self.r.state.sha256(raw))

    def test_actual_marker_descriptor_drift_blocks_valid_completion(self):
        marker = self.case.old.base.path() / self.r.MARKER
        marker.write_bytes(marker.read_bytes())
        body, raw, sha = self.capture()
        self.assertEqual(body["status"], "blocked")
        with self.assertRaises(ValueError):
            self.replay(raw, sha)

    def test_selected_checkpoint_drift_at_resource_exit_prevents_return(self):
        release = attempt._Reader.release
        original = copy.deepcopy(self.case.cp)

        def late(reader):
            release(reader)
            self.case.cp["completion"]["runtime"]["application"]["record_count"] += 1

        try:
            with mock.patch.object(
                attempt._Reader, "release", side_effect=late, autospec=True
            ), self.assertRaises(ValueError):
                self.capture()
        finally:
            self.case.cp.clear()
            self.case.cp.update(original)

    def test_completion_decoded_view_recloses_after_selection_validation(self):
        selected = self.selected()
        document = self.case.candidate()
        decode, validate = self.r._decode, selected.validate
        decoded = []

        def track(raw, sha, *args):
            body = decode(raw, sha, *args)
            if raw == document.raw:
                decoded.append(body)
            return body

        def late():
            validate()
            if decoded:
                decoded[-1]["native_action_dispatched"] = True

        with mock.patch.object(self.r, "_decode", side_effect=track), mock.patch.object(
            self.semantics.Selection, "validate", side_effect=late
        ), self.assertRaises(ValueError):
            selected.completion(document.raw, document.sha256)

    def test_shared_sibling_churn_allowed_but_late_old_file_write_refuses(self):
        other = ("a" if self.case.owner.pair_key[0] != "a" else "b") * 64
        with attempt.inspect_attempt_v2(**self.case.arguments()):
            sibling = self.r.RUNTIME_ROOT / other
            sibling.mkdir(mode=0o700)
            sibling.rmdir()
        head = self.case.old.base.path() / "HEAD.json"
        with self.assertRaises(ValueError):
            with attempt.inspect_attempt_v2(**self.case.arguments()) as view:
                scan = view.seal._scan
                calls = 0

                def late(*args, **kwargs):
                    nonlocal calls
                    result = scan(*args, **kwargs)
                    calls += 1
                    if calls == len(view.seal.members):
                        head.write_bytes(head.read_bytes())
                    return result

                with mock.patch.object(view.seal, "_scan", side_effect=late):
                    view.seal.check_memberships()

    def test_selection_raw_snapshots_cannot_be_mutable_equal_aliases(self):
        for field in (
            "_checkpoint_raw",
            "_binding_raw",
            "_intent_raw",
            "_contract_raw",
            "_profile_raw",
        ):
            selected = self.selected()
            object.__setattr__(selected, field, bytearray(getattr(selected, field)))
            with self.subTest(field=field), self.assertRaises(ValueError):
                selected.validate()

    def test_checkpoint_snapshot_references_cannot_be_rebased(self):
        for field in ("_original_checkpoint", "_private_checkpoint"):
            selected = self.selected()
            object.__setattr__(selected, field, copy.deepcopy(getattr(selected, field)))
            with self.subTest(field=field), self.assertRaises(ValueError):
                selected.validate()

    def test_selection_closes_private_checkpoint_after_last_contract_encoding(self):
        selected = self.selected()
        load = self.semantics.codec.load_publication_contract
        canonical = self.r.state.canonical
        returned = []

        def loaded(**kwargs):
            result = load(**kwargs)
            returned.append(result)
            return result

        def late(value):
            raw = canonical(value)
            if returned and value is returned[-1]:
                selected._private_checkpoint["completion"]["runtime"]["application"][
                    "record_count"
                ] += 1
            return raw

        with mock.patch.object(
            self.semantics.codec, "load_publication_contract", side_effect=loaded
        ), mock.patch.object(
            self.r.state, "canonical", side_effect=late
        ), self.assertRaises(
            ValueError
        ):
            selected.validate()

    def test_inspector_recloses_view_after_last_selection_validator(self):
        validate = self.semantics.Selection.validate
        held = []

        def late(selected):
            validate(selected)
            if held and held[0].seal.closed:
                body = self.r.observe.decode(held[0].raw)
                body["status"] = "unused"
                raw = self.r.state.canonical(body)
                object.__setattr__(held[0], "raw", raw)
                object.__setattr__(held[0], "sha256", self.r.state.sha256(raw))

        with mock.patch.object(
            self.semantics.Selection, "validate", side_effect=late, autospec=True
        ), self.assertRaises(ValueError):
            with attempt.inspect_attempt_v2(**self.case.arguments()) as view:
                held.append(view)


if __name__ == "__main__":
    unittest.main()
