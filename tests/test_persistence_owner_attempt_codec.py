"""Pure capture validation uses actual disposable inspector output as fixtures."""

import base64
import copy
from contextlib import ExitStack
import json
from pathlib import Path
import unittest
from unittest import mock

import test_persistence_owner_attempt as fixture
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_attempt_codec as codec,
)


class AttemptCodecTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.AttemptTests("runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.r = self.case.r
        # Include one real private ancestor in the disposable anchor projection.
        self.enterContext(
            mock.patch.object(
                fixture.attempt, "_WALK_ROOT", self.case.case.base.root.parent
            )
        )

    def capture(self):
        with self.case.inspect() as view:
            raw = view.raw
        return raw

    def validate(self, raw):
        def forbidden(*args, **kwargs):
            raise AssertionError("unexpected IO in pure attempt codec")

        with ExitStack() as stack:
            for target in (
                "os.open",
                "os.stat",
                "os.lstat",
                "os.fstat",
                "os.scandir",
                "os.listdir",
                "pathlib.Path.read_bytes",
                "pathlib.Path.resolve",
                "subprocess.Popen",
                "socket.socket",
                "sqlite3.connect",
            ):
                stack.enter_context(mock.patch(target, side_effect=forbidden))
            for module, name in (
                (codec.attempt, "_Reader"),
                (codec.r, "_capture"),
                (codec.r, "_runtime"),
                (codec.r.backup, "write_private"),
            ):
                stack.enter_context(
                    mock.patch.object(module, name, side_effect=forbidden)
                )
            return codec.validate_capture(
                self.case.case.owner,
                self.case.h0,
                self.case.sha,
                raw,
                self.r.state.sha256(raw),
            )

    def changed(self, body):
        return self.r.state.canonical(body)

    def test_all_admissible_prefixes_reconstruct_exactly(self):
        for stage in (
            "unused",
            "bootstrap-incomplete",
            "empty-claim",
            "h0-only",
            "h0-marker",
        ):
            if stage == "bootstrap-incomplete":
                self.r.RUNTIME_ROOT.mkdir(mode=0o700)
            elif stage == "empty-claim":
                self.r.backup.write_private(
                    self.r.RUNTIME_ROOT / "runtime.json", fixture.profile.RUNTIME
                )
                self.case.case.path.mkdir(mode=0o700)
            elif stage == "h0-only":
                self.r.backup.write_private(
                    self.case.case.path / "intent.json", json.loads(self.case.h0)
                )
            elif stage == "h0-marker":
                self.r.backup.write_private(
                    self.case.case.base.path() / self.r.MARKER,
                    self.r._marker(self.case.case.owner, self.case.sha),
                )
            raw = self.capture()
            with self.subTest(stage=stage):
                value = self.validate(raw)
                self.assertEqual(value["status"], stage)
                self.assertEqual(self.changed(value), raw)

    def test_valid_complete_candidate_stays_forensic(self):
        self.case.case.complete()
        (self.r.RUNTIME_ROOT / "runtime.json").write_bytes(
            self.r.state.canonical(fixture.profile.RUNTIME)
        )
        value = self.validate(self.capture())
        self.assertEqual(value["status"], "complete-candidate")
        self.assertFalse(value["publication_authorized"])

    def test_codec_performs_no_filesystem_process_or_network_operations(self):
        raw = self.capture()

        def forbidden(*args, **kwargs):
            raise AssertionError("unexpected IO in pure attempt codec")

        with mock.patch.object(
            codec.r.os, "open", side_effect=forbidden
        ), mock.patch.object(
            codec.r.os, "stat", side_effect=forbidden
        ), mock.patch.object(
            codec.r.os, "fstat", side_effect=forbidden
        ), mock.patch.object(
            Path, "lstat", side_effect=forbidden
        ), mock.patch.object(
            Path, "read_bytes", side_effect=forbidden
        ), mock.patch(
            "subprocess.Popen", side_effect=forbidden
        ), mock.patch(
            "socket.socket", side_effect=forbidden
        ):
            value = self.validate(raw)
        self.assertEqual(value["status"], "unused")

    def test_rehashed_flags_status_binding_and_h0_refuse(self):
        baseline = json.loads(self.capture())
        changes = [
            ("status", "complete-candidate"),
            ("publication_authorized", True),
            ("readonly", False),
            ("accepted_intent_sha256", "a" * 64),
            ("expected_publication_protocol", "direct-write"),
            ("schema_version", True),
        ]
        for key, value in changes:
            body = copy.deepcopy(baseline)
            body[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(self.changed(body))
        body = copy.deepcopy(baseline)
        body["binding"]["authority_sha256"] = self.r.state.sha256(
            b"wrong selected binding"
        )
        with self.assertRaises(ValueError):
            self.validate(self.changed(body))

    def test_omitted_or_added_derived_proofs_refuse(self):
        baseline = json.loads(self.capture())
        for section in (
            "files",
            "directories",
            "ancestors",
            "memberships",
            "membership_policy",
            "directory_closure_fields",
        ):
            body = copy.deepcopy(baseline)
            body[section].pop(next(iter(body[section])))
            with self.subTest(section=section), self.assertRaises(ValueError):
                self.validate(self.changed(body))
        for section in ("absent",):
            body = copy.deepcopy(baseline)
            body[section].pop()
            with self.assertRaises(ValueError):
                self.validate(self.changed(body))
        body = copy.deepcopy(baseline)
        body["absent"].append(str(self.r.RUNTIME_ROOT / "extra"))
        with self.assertRaises(ValueError):
            self.validate(self.changed(body))

    def test_rehashed_raw_hash_size_and_membership_mutations_refuse(self):
        baseline = json.loads(self.capture())
        path = next(iter(baseline["files"]))
        changes = [
            lambda b: b["files"][path].__setitem__(
                "raw_base64", base64.b64encode(b"bad").decode()
            ),
            lambda b: b["files"][path].__setitem__("sha256", "c" * 64),
            lambda b: b["files"][path]["identity"].__setitem__(6, 1),
            lambda b: b["memberships"][next(iter(b["memberships"]))].append(
                "unexpected"
            ),
            lambda b: b["ancestors"][next(iter(b["ancestors"]))].__setitem__(
                2, 0o40777
            ),
        ]
        for index, change in enumerate(changes):
            body = copy.deepcopy(baseline)
            change(body)
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.validate(self.changed(body))

    def test_blocked_legacy_and_partial_records_cannot_make_plans(self):
        self.r.RUNTIME_ROOT.mkdir(mode=0o700)
        path = self.r.RUNTIME_ROOT / "runtime.json"
        self.r.backup.write_private(path, self.r.RUNTIME)
        with self.assertRaises(ValueError):
            self.validate(self.capture())
        path.write_bytes(self.r.state.canonical(fixture.profile.RUNTIME))
        self.case.case.path.mkdir(mode=0o700)
        (self.case.case.path / "intent.json").write_bytes(b"")
        (self.case.case.path / "intent.json").chmod(0o600)
        with self.assertRaises(ValueError):
            self.validate(self.capture())

    def test_wrong_hash_noncanonical_unknown_fields_and_input_budget_refuse(self):
        raw = self.capture()
        with self.assertRaises(ValueError):
            codec.validate_capture(
                self.case.case.owner, self.case.h0, self.case.sha, raw, "d" * 64
            )
        with self.assertRaises(ValueError):
            self.validate(raw + b"\n")
        body = json.loads(raw)
        body["extra"] = False
        with self.assertRaises(ValueError):
            self.validate(self.changed(body))
        with mock.patch.object(codec.attempt, "OUTPUT_LIMIT", len(raw) - 1):
            with self.assertRaises(ValueError):
                self.validate(raw)

    def test_boolean_metadata_and_downgraded_directory_policy_refuse(self):
        baseline = json.loads(self.capture())
        for section in ("files", "directories", "ancestors"):
            body = copy.deepcopy(baseline)
            value = body[section][next(iter(body[section]))]
            metadata = value["identity"] if section == "files" else value
            metadata[0] = True
            with self.subTest(section=section), self.assertRaises(ValueError):
                self.validate(self.changed(body))
        body = copy.deepcopy(baseline)
        owned = next(p for p, n in body["directory_closure_fields"].items() if n == 9)
        body["directory_closure_fields"][owned] = 5
        with self.assertRaises(ValueError):
            self.validate(self.changed(body))

    def test_aggregate_budget_refuses_before_any_base64_decode(self):
        raw = self.capture()
        with mock.patch.object(codec.attempt, "AGGREGATE_LIMIT", 0), mock.patch.object(
            codec.base64,
            "b64decode",
            side_effect=AssertionError("decode exceeded budget"),
        ):
            with self.assertRaises(ValueError):
                self.validate(raw)

    def test_present_files_cannot_be_omitted_from_directory_membership(self):
        self.case.claim()
        baseline = json.loads(self.capture())
        paths = (
            self.case.case.base.path() / "HEAD.json",
            self.case.case.path / "intent.json",
        )
        for path in paths:
            self.assertIn(str(path), baseline["files"])
            body = copy.deepcopy(baseline)
            body["memberships"][str(path.parent)].remove(path.name)
            with self.subTest(name=path.name), self.assertRaises(ValueError):
                self.validate(self.changed(body))

    def test_internal_decoded_memory_and_profile_drift_refuse(self):
        raw = self.capture()
        original = codec.attempt._collect
        for subject in ("intent", "capture"):

            def changed(reader, owner, intent, intent_raw, intent_sha):
                result = original(reader, owner, intent, intent_raw, intent_sha)
                if subject == "intent":
                    intent["caller_evidence"]["current_sha256"] = "f" * 64
                else:
                    reader.body["status"] = "blocked"
                return result

            with self.subTest(subject=subject), mock.patch.object(
                codec.attempt, "_collect", side_effect=changed
            ):
                with self.assertRaises(ValueError):
                    self.validate(raw)
        closer = codec.r._close_binding

        def drift(*args):
            closer(*args)
            codec.profile.RUNTIME["target_schema"] = 999

        with mock.patch.object(
            codec.profile, "RUNTIME", copy.deepcopy(codec.profile.RUNTIME)
        ), mock.patch.object(codec.r, "_close_binding", side_effect=drift):
            with self.assertRaises(ValueError):
                self.validate(raw)


if __name__ == "__main__":
    unittest.main()
