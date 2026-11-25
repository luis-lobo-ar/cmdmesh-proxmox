"""Real private filesystem/leases; current/fence proofs are opaque caller hashes."""

import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock
import test_persistence_owner_journal as fixture

j, pair, api = fixture.journal, fixture.pair, fixture.api


class ResolutionTests(unittest.TestCase):
    def setUp(self):
        self.base = fixture.OwnerJournalTests("runTest")
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.head = self.base.initialize()["head_sha256"]
        self.anchor = (self.base.path() / "HEAD.json").read_bytes()
        self.proof = {
            "phase": "stopped",
            "current_sha256": "c" * 64,
            "worker_fence_sha256": "d" * 64,
        }
        self.no_post = self.enterContext(
            mock.patch.object(
                api, "post_guest_action", side_effect=AssertionError("POST forbidden")
            )
        )
        self.no_get = self.enterContext(
            mock.patch.object(
                api, "get", side_effect=AssertionError("native GET forbidden")
            )
        )

    def originals(self):
        return {
            p: (raw, identity)
            for p, (raw, identity) in self.base.files().items()
            if p != str(self.base.path() / "HEAD.json")
        }

    def preserved(self, files):
        current = self.base.files()
        self.assertEqual(files, {name: current[name] for name in files})

    def phases(self, op, rejected=False):
        payloads = fixture.phase_payloads(op)
        if rejected:
            payloads["terminal"]["task"]["exitstatus"] = "error"
            payloads["terminal"]["log"] = [{"n": 1, "t": "TASK ERROR: refused"}]
            payloads["terminal"]["native_outcome"] = api.native_outcome(
                payloads["terminal"]["task"], payloads["terminal"]["log"]
            )
        with pair.locked_pair(self.base.datasets):
            for stage, payload in payloads.items():
                op = j._append_phase(op, stage, payload)
        return op

    def prepare(self, anchor=None, checksum=None):
        with pair.locked_pair(self.base.datasets):
            return j.prepare_resolution(
                self.base.binding,
                self.anchor if anchor is None else anchor,
                self.head if checksum is None else checksum,
                j._digest(j.capture_basis(self.base.binding)),
                self.proof,
            )

    def begin(self, prepared):
        raw = j.state.canonical(prepared)
        with pair.locked_pair(self.base.datasets):
            return j.begin_resolution(self.base.binding, raw, j.state.sha256(raw))

    def complete(self, op):
        with pair.locked_pair(self.base.datasets):
            return j.complete_resolution(op)

    def resolve(self, anchor=None, checksum=None):
        before = self.originals()
        prepared = self.prepare(anchor, checksum)
        op = self.begin(prepared)
        candidate = self.complete(op)
        self.preserved(before)
        self.assertTrue(candidate.metadata_resolution_recorded)
        self.assertFalse(candidate.native_action_dispatched)
        with pair.locked_pair(self.base.datasets):
            view = j._inspect(self.base.binding, candidate.head_sha256)
        self.assertEqual(view.intent["kind"], "resolve")
        self.no_post.assert_not_called()
        self.no_get.assert_not_called()
        return candidate

    def test_intent_only_resolution_preserves_raw_and_new_native_can_follow(self):
        op = self.base.begin(self.head)
        with pair.locked_pair(self.base.datasets):
            j._fail(op, "no-dispatch", "not-dispatched")
        candidate = self.resolve()
        next_op = self.base.begin(candidate.head_sha256, "resume")
        complete = self.base.complete(next_op)
        self.assertEqual(complete.sequence, 3)
        result = json.loads(
            (self.base.path() / j._slot(2) / "result.json").read_bytes()
        )
        self.assertFalse(result["native_action_dispatched"])
        self.assertNotIn("native_success", result)

    def test_empty_or_zero_intent_orphans_resolve_without_adoption(self):
        for kind in ("empty", "zero"):
            child = type(self)("runTest")
            child.setUp()
            try:
                slot = child.base.path() / j._slot(1)
                slot.mkdir(mode=0o700)
                if kind == "zero":
                    (slot / "intent.json").write_bytes(b"")
                    (slot / "intent.json").chmod(0o600)
                candidate = child.resolve()
                self.assertEqual(candidate.sequence, 2)
                child.base.begin(candidate.head_sha256, "resume")
            finally:
                child.doCleanups()

    def test_dispatch_unknown_ack_resolves_without_inventing_ack(self):
        op = self.base.begin(self.head)
        with pair.locked_pair(self.base.datasets):
            j._append_phase(op, "dispatch", fixture.phase_payloads(op)["dispatch"])
        before = self.originals()
        candidate = self.resolve()
        self.preserved(before)
        self.assertFalse((self.base.path() / j._slot(1) / "ack.json").exists())
        self.assertFalse((self.base.path() / j._slot(1) / "terminal.json").exists())
        self.base.begin(candidate.head_sha256, "resume")

    def test_known_rejected_terminal_stays_rejected(self):
        op = self.phases(self.base.begin(self.head), rejected=True)
        with pair.locked_pair(self.base.datasets), self.assertRaises(ValueError):
            j._complete(op, {})
        self.resolve()
        terminal = json.loads(
            (self.base.path() / j._slot(1) / "terminal.json").read_bytes()
        )
        self.assertFalse(terminal["payload"]["native_outcome"]["accepted"])
        self.assertFalse((self.base.path() / j._slot(1) / "result.json").exists())

    def test_candidate_plus_failure_keeps_original_result_and_barrier(self):
        op = self.base.begin(self.head)
        candidate = self.base.complete(op)
        old = (self.base.path() / j._slot(1) / "result.json").read_bytes()
        with pair.locked_pair(self.base.datasets):
            j._fail(op, "late-current-refused", "postcondition-refused")
        resolved = self.resolve()
        self.assertEqual(
            (self.base.path() / j._slot(1) / "result.json").read_bytes(), old
        )
        self.assertTrue((self.base.path() / j._slot(1) / "failure.json").exists())
        self.assertNotEqual(candidate.head_sha256, resolved.head_sha256)

    def test_ready_candidate_lost_return_is_not_automatically_adopted(self):
        candidate = self.base.complete(self.base.begin(self.head))
        with self.assertRaises(ValueError):
            self.base.begin(self.head, "resume")
        resolved = self.resolve()
        self.assertNotEqual(candidate.head_sha256, resolved.head_sha256)
        self.assertEqual(resolved.sequence, 2)

    def test_interrupted_resolution_before_intent_or_before_publish_is_resolvable(self):
        for fault in ("before-intent", "after-intent", "rename"):
            child = type(self)("runTest")
            child.setUp()
            try:
                child.base.begin(child.head)
                prepared = child.prepare()
                write = j._write

                def fail(path, value):
                    if path.name == "intent.json" and value.get("kind") == "resolve":
                        if fault == "before-intent":
                            raise OSError("before write")
                        answer = write(path, value)
                        if fault == "after-intent":
                            raise OSError("after write")
                        return answer
                    return write(path, value)

                with mock.patch.object(
                    j, "_write", side_effect=fail
                ), mock.patch.object(
                    j.os,
                    "replace",
                    side_effect=OSError("rename") if fault == "rename" else None,
                    wraps=j.os.replace if fault != "rename" else None,
                ):
                    with child.assertRaises(OSError):
                        child.begin(prepared)
                previous = child.originals()
                candidate = child.resolve()
                child.preserved(previous)
                self.assertEqual(candidate.sequence, 3)
                child.base.begin(candidate.head_sha256, "resume")
            finally:
                child.doCleanups()

    def test_pending_published_resolution_lost_return_can_be_resolved(self):
        self.base.begin(self.head)
        prepared = self.prepare()
        inspect = j._inspect

        def fail(binding, sha):
            value = inspect(binding, sha)
            if value.head["sequence"] == 2 and value.head["state"] == "pending":
                raise ValueError("lost return")
            return value

        with mock.patch.object(j, "_inspect", side_effect=fail), self.assertRaises(
            ValueError
        ):
            self.begin(prepared)
        candidate = self.resolve()
        self.assertEqual(candidate.sequence, 3)

    def test_ready_published_resolution_lost_return_and_failed_postproof_resolve(self):
        for failed in (False, True):
            child = type(self)("runTest")
            child.setUp()
            try:
                child.base.begin(child.head)
                op = child.begin(child.prepare())
                first = child.complete(op)
                if failed:
                    with pair.locked_pair(child.base.datasets):
                        j._fail(op, "late-proof-refused", "postcondition-refused")
                with child.assertRaises(ValueError):
                    child.base.begin(child.head, "resume")
                second = child.resolve()
                self.assertNotEqual(first.head_sha256, second.head_sha256)
                self.assertEqual(second.sequence, 3)
                child.base.begin(second.head_sha256, "resume")
            finally:
                child.doCleanups()

    def test_root_headnext_orphan_is_preserved_and_later_native_publish_works(self):
        with mock.patch.object(
            j.os, "replace", side_effect=OSError("rename")
        ), self.assertRaises(OSError):
            self.base.begin(self.head)
        stage = self.base.path() / "HEAD.next"
        raw = stage.read_bytes()
        resolved = self.resolve()
        new = self.base.complete(self.base.begin(resolved.head_sha256, "resume"))
        self.assertEqual(new.sequence, 3)
        self.assertEqual(stage.read_bytes(), raw)

    def test_changed_basis_stale_preparation_and_wrong_anchor_refuse_before_claim(self):
        self.base.begin(self.head)
        prepared = self.prepare()
        before = set(self.base.path().iterdir())
        path = self.base.path() / j._slot(1) / "intent.json"
        body = json.loads(path.read_bytes())
        body["prepared_sha256"] = "f" * 64
        path.write_bytes(j.state.canonical(body))
        with self.assertRaises(ValueError):
            self.begin(prepared)
        self.assertEqual(set(self.base.path().iterdir()), before)
        with self.assertRaises(ValueError):
            self.prepare(checksum="f" * 64)
        changed = copy.deepcopy(prepared)
        changed["proof"]["phase"] = False
        with self.assertRaises(ValueError):
            self.begin(changed)

    def test_admitted_predecessor_ratchets_old_anchor(self):
        candidate = self.base.complete(self.base.begin(self.head))
        accepted = (self.base.path() / "HEAD.json").read_bytes()
        self.base.begin(candidate.head_sha256, "resume")
        with self.assertRaisesRegex(ValueError, "anchor-stale"):
            self.prepare()
        resolved = self.resolve(accepted, candidate.head_sha256)
        self.assertEqual(resolved.sequence, 3)

    def test_changed_old_bytes_after_resolution_block_further_begin(self):
        self.base.begin(self.head)
        resolved = self.resolve()
        path = self.base.path() / j._slot(1) / "intent.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(ValueError):
            self.base.begin(resolved.head_sha256, "resume")

    def test_resolution_token_cannot_append_native_phase_or_native_complete(self):
        self.base.begin(self.head)
        op = self.begin(self.prepare())
        with pair.locked_pair(self.base.datasets):
            with self.assertRaises(ValueError):
                j._append_phase(op, "dispatch", {})
            with self.assertRaises(ValueError):
                j._complete(op, {})
        self.complete(op)

    def test_prepare_is_readonly_and_has_no_io_native_permission_in_proof(self):
        self.base.begin(self.head)
        before = self.base.files()
        prepared = self.prepare()
        self.assertEqual(before, self.base.files())
        changed = copy.deepcopy(self.proof)
        changed["tls_verified"] = True
        with pair.locked_pair(self.base.datasets), self.assertRaises(ValueError):
            j.prepare_resolution(
                self.base.binding,
                self.anchor,
                self.head,
                j._digest(j.capture_basis(self.base.binding)),
                changed,
            )
        self.assertEqual(prepared["anchor"]["sha256"], self.head)

    def test_unknown_slot_or_foreign_metadata_refuses(self):
        self.base.begin(self.head)
        (self.base.path() / j._slot(1) / "foreign.json").write_bytes(b"{}")
        (self.base.path() / j._slot(1) / "foreign.json").chmod(0o600)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_external_blocked_capture_hash_is_required_and_rechecked(self):
        self.base.begin(self.head)
        with pair.locked_pair(self.base.datasets):
            basis = j.capture_basis(self.base.binding)
        expected = j._digest(basis)
        path = self.base.path() / j._slot(1) / "intent.json"
        path.write_bytes(path.read_bytes() + b" ")
        with pair.locked_pair(self.base.datasets), self.assertRaisesRegex(
            ValueError, "basis-changed"
        ):
            j.prepare_resolution(
                self.base.binding, self.anchor, self.head, expected, self.proof
            )

    def test_interrupted_resolution_does_not_launder_changed_old_native_bytes(self):
        self.base.begin(self.head)
        self.begin(self.prepare())
        path = self.base.path() / j._slot(1) / "intent.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "basis-file-changed"):
            self.prepare()

    def test_cross_directory_head_publish_syncs_source_after_rename(self):
        for publisher in ("resolution", "native-fallback"):
            child = type(self)("runTest")
            child.setUp()
            try:
                if publisher == "resolution":
                    child.base.begin(child.head)
                    prepared = child.prepare()
                    action = lambda: child.begin(prepared)
                else:
                    with mock.patch.object(
                        j.os, "replace", side_effect=OSError("orphan")
                    ), child.assertRaises(OSError):
                        child.base.begin(child.head)
                    resolved = child.resolve()
                    action = lambda: child.base.begin(resolved.head_sha256, "resume")
                original_replace = j.os.replace
                original_sync = j.backup.sync_directory
                renamed = []

                def replace(source, target):
                    result = original_replace(source, target)
                    renamed.append(Path(source).parent)
                    return result

                def sync(directory):
                    if renamed and Path(directory) == renamed[-1]:
                        raise OSError("source directory sync failed")
                    return original_sync(directory)

                with mock.patch.object(
                    j.os, "replace", side_effect=replace
                ), mock.patch.object(
                    j.backup, "sync_directory", side_effect=sync
                ), child.assertRaises(
                    OSError
                ):
                    action()
                self.assertTrue(renamed)
            finally:
                child.doCleanups()

    def test_noncanonical_results_refuse_after_resolution(self):
        for native in (False, True):
            child = type(self)("runTest")
            child.setUp()
            try:
                child.base.begin(child.head)
                candidate = child.resolve()
                if native:
                    candidate = child.base.complete(
                        child.base.begin(candidate.head_sha256, "resume")
                    )
                path = child.base.path() / j._slot(candidate.sequence) / "result.json"
                path.write_bytes(path.read_bytes() + b" ")
                with pair.locked_pair(child.base.datasets), child.assertRaises(
                    ValueError
                ):
                    j._inspect(child.base.binding, candidate.head_sha256)
            finally:
                child.doCleanups()

    def test_basis_limit_stops_before_reading_next_file(self):
        self.base.begin(self.head)
        read = j._read_any
        seen = []

        def tracked(path, seal):
            seen.append(str(path))
            return read(path, seal)

        with pair.locked_pair(self.base.datasets), mock.patch.object(
            j, "BASIS_BYTES_LIMIT", 0
        ), mock.patch.object(j, "_read_any", side_effect=tracked), self.assertRaises(
            ValueError
        ):
            j.capture_basis(self.base.binding)
        self.assertEqual(len(seen), 1)

    def test_native_result_contract_is_identical_before_and_after_resolution(self):
        for resolved in (False, True):
            for field, value in (
                ("sequence", True),
                ("profile_sha256", "f" * 64),
                ("intent_sha256", "f" * 64),
                ("evidence", []),
                ("phase_files", {}),
                ("phase_chain_sha256", "f" * 64),
            ):
                child = type(self)("runTest")
                child.setUp()
                try:
                    predecessor = child.head
                    if resolved:
                        child.base.begin(child.head)
                        predecessor = child.resolve().head_sha256
                    candidate = child.base.complete(child.base.begin(predecessor))
                    result_path = (
                        child.base.path() / j._slot(candidate.sequence) / "result.json"
                    )
                    result = json.loads(result_path.read_bytes())
                    result[field] = value
                    result_path.write_bytes(j.state.canonical(result))
                    head_path = child.base.path() / "HEAD.json"
                    head = json.loads(head_path.read_bytes())
                    head["result_sha256"] = j._digest(result)
                    head_path.write_bytes(j.state.canonical(head))
                    with self.subTest(resolved=resolved, field=field), pair.locked_pair(
                        child.base.datasets
                    ), self.assertRaises(ValueError):
                        j._inspect(child.base.binding, j._digest(head))
                finally:
                    child.doCleanups()

    def test_schema_two_runtime_is_refused_without_upgrade_or_cleanup(self):
        runtime_path = j.RUNTIME_ROOT / "runtime.json"
        legacy = dict(j.RUNTIME, schema_version=2, action_profile="owner-os-action-v1")
        runtime_path.write_bytes(j.state.canonical(legacy))
        before = self.base.files()
        with pair.locked_pair(self.base.datasets), self.assertRaises(ValueError):
            j._initialize(self.base.binding)
        self.assertEqual(before, self.base.files())
        with pair.locked_pair(self.base.datasets), self.assertRaises(ValueError):
            j.capture_basis(self.base.binding)
        self.assertEqual(before, self.base.files())
