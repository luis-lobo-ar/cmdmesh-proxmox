"""Internal metadata handoff uses real files/leases and unqualified evidence refs.

No proof hash in this fixture establishes a native worker fence or permission.
"""

import copy
from dataclasses import asdict
import importlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import test_persistence_owner_journal as fixture

j, pair, api = fixture.journal, fixture.pair, fixture.api


class RetirementTests(unittest.TestCase):
    def setUp(self):
        self.r = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_retirement"
        )
        self.base = fixture.OwnerJournalTests("runTest")
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.enterContext(
            mock.patch.object(self.r, "RUNTIME_ROOT", self.base.root / "handoff")
        )
        for name in ("post_guest_action", "post_owner_guest_action", "get"):
            self.enterContext(
                mock.patch.object(api, name, side_effect=AssertionError("native IO"))
            )
        self.owner = self.base.binding
        genesis = self.base.initialize()["head_sha256"]
        shutdown = self.base.complete(self.base.begin(genesis, "shutdown"))
        self.anchor_sha = shutdown.head_sha256
        self.anchor_raw = (self.base.path() / "HEAD.json").read_bytes()
        self.pending = self.base.begin(self.anchor_sha, "resume")
        dispatch = fixture.phase_payloads(self.pending)["dispatch"]
        with pair.locked_pair(self.base.datasets):
            self.pending = j._append_phase(self.pending, "dispatch", dispatch)
            j._fail(self.pending, "transition-unqualified", "unknown")
            self.basis = j.capture_basis(self.owner)
        self.evidence = {
            "phase": "os_quiesced",
            "host_epoch": dispatch["host_epoch"],
            "current_sha256": "a" * 64,
            "worker_fence_sha256": "b" * 64,
            "failure_provenance_sha256": "c" * 64,
            "source_manifest_sha256": "d" * 64,
            "accepted_prepared_sha256": self.pending.prepared_sha256,
        }

    def call(self, function, *args):
        with pair.locked_pair(self.base.datasets):
            return function(*args)

    def encoded(self, value):
        raw = j.state.canonical(value)
        return raw, j.state.sha256(raw)

    def prepare(self):
        raw, sha = self.encoded(self.evidence)
        return self.call(
            self.r._prepare,
            self.owner,
            self.anchor_raw,
            self.anchor_sha,
            j._digest(self.basis),
            raw,
            sha,
        )

    def begin(self):
        self.intent = self.prepare()
        self.h0, self.h0sha = self.encoded(self.intent)
        return self.call(self.r._begin, self.owner, self.h0, self.h0sha)

    def mark(self):
        return self.call(self.r._mark, self.begin())

    def complete(self, marked=None):
        marked = marked or self.mark()
        closing = {
            **self.evidence,
            "current_sha256": "e" * 64,
            "worker_fence_sha256": "f" * 64,
        }
        raw, sha = self.encoded(closing)
        return self.call(self.r._complete, marked, raw, sha)

    def originals(self):
        return self.base.files()

    def assert_preserved(self, original):
        current = self.base.files()
        self.assertEqual(original, {name: current[name] for name in original})

    @property
    def path(self):
        return self.r.RUNTIME_ROOT / self.owner.pair_key

    def test_complete_handoff_preserves_pending_head_and_never_certifies_resume(self):
        original = self.originals()
        intent = self.prepare()
        self.assertFalse(self.r.RUNTIME_ROOT.exists())
        self.assertEqual(intent["basis"], self.basis)
        result = self.complete()
        self.assert_preserved(original)
        value = self.r.validate_handoff(
            self.owner, self.h0, self.h0sha, result.raw, result.sha256
        )
        self.assertIs(value["legacy_retired"], True)
        self.assertIs(value["metadata_resolution_recorded"], True)
        self.assertIs(value["native_action_dispatched"], False)
        self.assertIs(value["original_native_operation_qualified"], False)
        inspected = self.call(
            self.r._inspect, self.owner, self.h0, self.h0sha, result.raw, result.sha256
        )
        self.assertEqual(inspected.completion, value)
        self.assertEqual(
            json.loads((self.base.path() / "HEAD.json").read_bytes())["state"],
            "pending",
        )
        with self.assertRaises(ValueError):
            self.call(j._inspect, self.owner, self.pending.pending_head_sha256)

    def test_each_claim_and_publication_is_one_way_without_replay(self):
        claim = self.begin()
        with self.assertRaises((ValueError, OSError)):
            self.call(self.r._begin, self.owner, self.h0, self.h0sha)
        marked = self.call(self.r._mark, claim)
        with self.assertRaises((ValueError, OSError)):
            self.call(self.r._mark, claim)
        complete = self.complete(marked)
        with self.assertRaises((ValueError, OSError)):
            self.complete(marked)
        self.assertEqual(complete.sha256, j.state.sha256(complete.raw))

    def test_proof_references_do_not_allow_epoch_or_preparation_substitution(self):
        for field, value in (
            ("phase", "stopped"),
            ("accepted_prepared_sha256", "f" * 64),
            (
                "host_epoch",
                {**self.evidence["host_epoch"], "mount_namespace": "mnt:[999]"},
            ),
        ):
            before = copy.deepcopy(self.evidence)
            self.evidence[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.prepare()
            self.evidence = before
        self.assertFalse(self.r.RUNTIME_ROOT.exists())

    def test_changed_basis_anchor_or_final_slot_refuses_before_claim(self):
        intent = self.prepare()
        raw, sha = self.encoded(intent)
        slot = self.base.path() / j._slot(2)
        extra = slot / "ack.json"
        extra.write_bytes(b"{}")
        extra.chmod(0o600)
        with self.assertRaises(ValueError):
            self.call(self.r._begin, self.owner, raw, sha)
        self.assertFalse(self.r.RUNTIME_ROOT.exists())

    def test_old_head_identity_is_never_relaxed_like_resolution_history(self):
        claim = self.begin()
        path = self.base.path() / "HEAD.json"
        raw = path.read_bytes()
        replacement = self.base.path() / "replacement"
        replacement.write_bytes(raw)
        replacement.chmod(0o600)
        os.replace(replacement, path)
        with self.assertRaises(ValueError):
            self.call(self.r._mark, claim)
        self.assertFalse((self.base.path() / self.r.MARKER).exists())

    def test_shared_runtime_is_pinned_separately_from_old_basis(self):
        claim = self.begin()
        path = j.RUNTIME_ROOT / "runtime.json"
        raw = path.read_bytes()
        replacement = self.base.root / "replacement-runtime"
        replacement.write_bytes(raw)
        replacement.chmod(0o600)
        os.replace(replacement, path)
        with self.assertRaises(ValueError):
            self.call(self.r._mark, claim)

    def test_shared_runtime_directory_identity_is_pinned_across_preparation(self):
        intent = self.prepare()
        raw, sha = self.encoded(intent)
        original = self.originals()
        lstat = Path.lstat

        def changed(path, *args, **kwargs):
            info = lstat(path, *args, **kwargs)
            if path == j.RUNTIME_ROOT:
                # Isolate the directory observation; actual control files stay unchanged.
                values = {
                    key: getattr(info, key)
                    for key in (
                        "st_dev",
                        "st_ino",
                        "st_mode",
                        "st_uid",
                        "st_gid",
                        "st_nlink",
                        "st_size",
                        "st_mtime_ns",
                        "st_ctime_ns",
                    )
                }
                values["st_ino"] += 1000000
                return SimpleNamespace(**values)
            return info

        with mock.patch.object(Path, "lstat", changed), self.assertRaises(ValueError):
            self.call(self.r._begin, self.owner, raw, sha)
        self.assert_preserved(original)
        self.assertFalse(self.r.RUNTIME_ROOT.exists())

    def test_shared_parent_replacement_with_unchanged_control_files_refuses_claim(self):
        intent = self.prepare()
        raw, sha = self.encoded(intent)
        original = self.originals()
        saved = self.base.root.with_name(self.base.root.name + "-saved-parent")
        self.base.root.rename(saved)
        self.base.root.mkdir(mode=0o700)
        for path in saved.iterdir():
            self.assertTrue(path.is_dir())
            path.rename(self.base.root / path.name)
        saved.rmdir()
        self.assert_preserved(original)
        with self.assertRaises(ValueError):
            self.call(self.r._begin, self.owner, raw, sha)
        self.assertFalse(self.r.RUNTIME_ROOT.exists())

    def test_partial_marker_blocks_both_ordinary_retry_and_old_admission(self):
        claim = self.begin()
        writer = self.r._write

        def partial(path, value, limit):
            if path.name == self.r.MARKER:
                path.write_bytes(b'{"partial":')
                path.chmod(0o600)
                raise OSError("modeled interrupted marker")
            return writer(path, value, limit)

        before = self.originals()
        with mock.patch.object(
            self.r, "_write", side_effect=partial
        ), self.assertRaises(OSError):
            self.call(self.r._mark, claim)
        self.assert_preserved(before)
        with self.assertRaises((ValueError, OSError)):
            self.call(self.r._mark, claim)
        with self.assertRaises(ValueError):
            self.call(j._inspect, self.owner, self.pending.pending_head_sha256)

    def test_marker_writer_cannot_change_the_requested_link_and_return_success(self):
        claim = self.begin()
        writer = self.r._write

        def change(path, value, limit):
            if path.name == self.r.MARKER:
                value["intent_sha256"] = "f" * 64
            return writer(path, value, limit)

        with mock.patch.object(self.r, "_write", side_effect=change), self.assertRaises(
            ValueError
        ):
            self.call(self.r._mark, claim)

    def test_partial_h1_is_preserved_and_cannot_be_implicitly_completed(self):
        marked = self.mark()
        writer = self.r._write

        def partial(path, value, limit):
            if path.name == "complete.json":
                path.write_bytes(b'{"partial":')
                path.chmod(0o600)
                raise OSError("modeled interrupted completion")
            return writer(path, value, limit)

        with mock.patch.object(
            self.r, "_write", side_effect=partial
        ), self.assertRaises(OSError):
            self.complete(marked)
        retained = (self.path / "complete.json").read_bytes()
        with self.assertRaises((ValueError, OSError)):
            self.complete(marked)
        self.assertEqual(retained, (self.path / "complete.json").read_bytes())

    def test_marker_foreign_content_or_metadata_never_qualifies_completion(self):
        marked = self.mark()
        path = self.base.path() / self.r.MARKER
        original = path.read_bytes()
        for value in (b"{}", original):
            path.write_bytes(value)
            path.chmod(0o644 if value == original else 0o600)
            with self.assertRaises((ValueError, OSError)):
                self.complete(marked)

    def test_changed_old_file_after_retirement_refuses_completion(self):
        marked = self.mark()
        path = self.base.path() / j._slot(2) / "failure.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(ValueError):
            self.complete(marked)

    def test_extra_new_or_old_membership_refuses_inspection(self):
        result = self.complete()
        extra = self.path / "failure.json"
        extra.write_bytes(b"{}")
        extra.chmod(0o600)
        with self.assertRaises(ValueError):
            self.call(
                self.r._inspect,
                self.owner,
                self.h0,
                self.h0sha,
                result.raw,
                result.sha256,
            )

    def test_final_membership_walk_cannot_hide_an_old_head_change(self):
        result = self.complete()
        same_legacy = self.r._same_legacy
        iterdir = Path.iterdir
        state = {"armed": False, "fired": False}

        def arm(*args):
            value = same_legacy(*args)
            state["armed"] = True
            return value

        def change(path):
            values = list(iterdir(path))
            if (
                state["armed"]
                and not state["fired"]
                and path == self.base.path() / j._slot(2)
            ):
                state["fired"] = True
                head = self.base.path() / "HEAD.json"
                head.write_bytes(head.read_bytes() + b" ")
            return iter(values)

        with mock.patch.object(
            self.r, "_same_legacy", side_effect=arm
        ), mock.patch.object(Path, "iterdir", change), self.assertRaises(ValueError):
            self.call(
                self.r._inspect,
                self.owner,
                self.h0,
                self.h0sha,
                result.raw,
                result.sha256,
            )
        self.assertTrue(state["fired"])

    def test_old_membership_walk_cannot_hide_new_intent_change_at_stage_return(self):
        for stage in ("begin", "mark"):
            child = type(self)("runTest")
            child.setUp()
            try:
                claim = child.begin() if stage == "mark" else None
                same_legacy = child.r._same_legacy
                iterdir = Path.iterdir
                state = {"armed": False, "fired": False}

                def arm(*args):
                    value = same_legacy(*args)
                    if (stage == "begin" and (child.path / "intent.json").exists()) or (
                        stage == "mark" and args[2] is True
                    ):
                        state["armed"] = True
                    return value

                def change(path):
                    values = list(iterdir(path))
                    if (
                        state["armed"]
                        and not state["fired"]
                        and path == child.base.path() / j._slot(2)
                    ):
                        state["fired"] = True
                        intent = child.path / "intent.json"
                        intent.write_bytes(intent.read_bytes() + b" ")
                    return iter(values)

                with self.subTest(stage=stage), mock.patch.object(
                    child.r, "_same_legacy", side_effect=arm
                ), mock.patch.object(Path, "iterdir", change), self.assertRaises(
                    ValueError
                ):
                    if stage == "begin":
                        child.begin()
                    else:
                        child.call(child.r._mark, claim)
                self.assertTrue(state["fired"])
            finally:
                child.doCleanups()

    def test_pure_decoder_rejects_flags_target_and_marker_link_substitution(self):
        result = self.complete()
        value = json.loads(result.raw)
        for field, replacement in (
            ("legacy_retired", 1),
            ("metadata_resolution_recorded", False),
            ("original_native_operation_qualified", True),
            ("native_action_dispatched", True),
            ("intent_sha256", "f" * 64),
        ):
            bad = {**value, field: replacement}
            raw, sha = self.encoded(bad)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.r.validate_handoff(self.owner, self.h0, self.h0sha, raw, sha)
        alien = j.Binding(self.owner.pair_key, "e" * 64, self.owner.guest)
        with self.assertRaises(ValueError):
            self.r.validate_handoff(
                alien, self.h0, self.h0sha, result.raw, result.sha256
            )

    def test_raw_inputs_are_exact_canonical_bytes_and_external_hashes(self):
        raw, sha = self.encoded(self.evidence)
        for body, digest in (
            (bytearray(raw), sha),
            (raw + b"\n", j.state.sha256(raw + b"\n")),
            (raw, "f" * 64),
        ):
            with self.subTest(body_type=type(body).__name__), self.assertRaises(
                ValueError
            ):
                self.call(
                    self.r._prepare,
                    self.owner,
                    self.anchor_raw,
                    self.anchor_sha,
                    j._digest(self.basis),
                    body,
                    digest,
                )
        self.assertFalse(self.r.RUNTIME_ROOT.exists())

    def test_pure_decoder_joins_anchor_to_pending_state_even_with_rehashed_links(self):
        result = self.complete()
        intent = json.loads(self.h0)
        intent["anchor"]["head"]["profile_sha256"] = "e" * 64
        intent["anchor"]["sha256"] = j._digest(intent["anchor"]["head"])
        raw_intent, intent_sha = self.encoded(intent)
        completion = json.loads(result.raw)
        completion["intent_sha256"] = intent_sha
        completion["intent_file"]["sha256"] = intent_sha
        completion["intent_file"]["identity"][6] = len(raw_intent)
        completion["marker"] = self.r._marker(self.owner, intent_sha)
        marker_raw = j.state.canonical(completion["marker"])
        completion["marker_file"]["sha256"] = j.state.sha256(marker_raw)
        completion["marker_file"]["identity"][6] = len(marker_raw)
        raw_complete, complete_sha = self.encoded(completion)
        with self.assertRaises(ValueError):
            self.r.validate_handoff(
                self.owner, raw_intent, intent_sha, raw_complete, complete_sha
            )

    def test_pure_decoder_rejects_rehashed_known_manifest_contradictions(self):
        result = self.complete()
        for path, replacement in (
            (("shared_runtime", "identity", 6), 1),
            (("basis", "files", "profile.json", "sha256"), "f" * 64),
            (("basis", "files", "genesis.json", "sha256"), "f" * 64),
            (("basis", "files", "HEAD.json", "identity", 6), 1),
        ):
            intent = json.loads(self.h0)
            target = intent
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            raw_intent, intent_sha = self.encoded(intent)
            completion = json.loads(result.raw)
            completion["intent_sha256"] = intent_sha
            completion["intent_file"]["sha256"] = intent_sha
            completion["intent_file"]["identity"][6] = len(raw_intent)
            completion["marker"] = self.r._marker(self.owner, intent_sha)
            marker_raw = j.state.canonical(completion["marker"])
            completion["marker_file"]["sha256"] = j.state.sha256(marker_raw)
            completion["marker_file"]["identity"][6] = len(marker_raw)
            completion["basis_sha256"] = j._digest(intent["basis"])
            raw_complete, complete_sha = self.encoded(completion)
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.r.validate_handoff(
                    self.owner, raw_intent, intent_sha, raw_complete, complete_sha
                )

    def test_aggregate_bound_refuses_before_reading_or_claiming(self):
        with mock.patch.object(self.r, "BASIS_LIMIT", 1), mock.patch.object(
            j.observe, "read_regular", wraps=j.observe.read_regular
        ) as read:
            with self.assertRaises(ValueError):
                self.prepare()
            self.assertFalse(
                any(
                    Path(call.args[0]).is_relative_to(j.RUNTIME_ROOT)
                    for call in read.call_args_list
                )
            )
        self.assertFalse(self.r.RUNTIME_ROOT.exists())

    def test_symlink_hardlink_and_unknown_paths_do_not_enter_handoff(self):
        path = self.base.path() / j._slot(2) / "failure.json"
        raw = path.read_bytes()
        saved = self.base.root / "saved-failure"
        saved.write_bytes(raw)
        saved.chmod(0o600)
        path.unlink()
        path.symlink_to(saved)
        with self.assertRaises((ValueError, OSError)):
            self.prepare()
        path.unlink()
        os.link(saved, path)
        with self.assertRaises((ValueError, OSError)):
            self.prepare()
        self.assertFalse(self.r.RUNTIME_ROOT.exists())

    def test_pure_validation_never_reads_controls_or_invokes_native_work(self):
        result = self.complete()
        with mock.patch(
            "os.open", side_effect=AssertionError("file IO")
        ), mock.patch.object(Path, "lstat", side_effect=AssertionError("file IO")):
            value = self.r.validate_handoff(
                self.owner, self.h0, self.h0sha, result.raw, result.sha256
            )
        self.assertIs(value["native_action_dispatched"], False)

    def test_partial_h0_claim_preserves_legacy_and_blocks_a_second_claim(self):
        intent = self.prepare()
        raw, sha = self.encoded(intent)
        original = self.originals()
        writer = self.r._write

        def partial(path, value, limit):
            if path.name == "intent.json":
                path.write_bytes(b'{"partial":')
                path.chmod(0o600)
                raise OSError("modeled interrupted claim")
            return writer(path, value, limit)

        with mock.patch.object(
            self.r, "_write", side_effect=partial
        ), self.assertRaises(OSError):
            self.call(self.r._begin, self.owner, raw, sha)
        self.assert_preserved(original)
        with self.assertRaises((ValueError, OSError)):
            self.call(self.r._begin, self.owner, raw, sha)
        self.assertFalse((self.base.path() / self.r.MARKER).exists())

    def test_marker_directory_fsync_failure_is_uncertain_and_never_replayed(self):
        claim = self.begin()
        sync = self.r.backup.sync_directory

        def uncertain(path):
            if path == self.base.path():
                raise OSError("modeled directory fsync failure")
            return sync(path)

        with mock.patch.object(
            self.r.backup, "sync_directory", side_effect=uncertain
        ), self.assertRaises(OSError):
            self.call(self.r._mark, claim)
        retained = (self.base.path() / self.r.MARKER).read_bytes()
        with self.assertRaises((ValueError, OSError)):
            self.call(self.r._mark, claim)
        self.assertEqual(retained, (self.base.path() / self.r.MARKER).read_bytes())
        self.assertFalse((self.path / "complete.json").exists())

    def test_old_head_change_during_marker_write_prevents_a_retired_return(self):
        claim = self.begin()
        writer = self.r._write

        def change(path, value, limit):
            result = writer(path, value, limit)
            if path.name == self.r.MARKER:
                head = self.base.path() / "HEAD.json"
                head.write_bytes(head.read_bytes() + b" ")
            return result

        with mock.patch.object(self.r, "_write", side_effect=change), self.assertRaises(
            ValueError
        ):
            self.call(self.r._mark, claim)
        self.assertTrue((self.base.path() / self.r.MARKER).exists())
        self.assertFalse((self.path / "complete.json").exists())

    def test_h1_publication_does_not_hide_a_late_shared_runtime_change(self):
        marked = self.mark()
        writer = self.r._write

        def change(path, value, limit):
            result = writer(path, value, limit)
            if path.name == "complete.json":
                shared = j.RUNTIME_ROOT / "runtime.json"
                shared.write_bytes(shared.read_bytes() + b" ")
            return result

        with mock.patch.object(self.r, "_write", side_effect=change), self.assertRaises(
            ValueError
        ):
            self.complete(marked)
        self.assertTrue((self.path / "complete.json").exists())

    def test_final_inspection_error_retains_candidate_without_success(self):
        marked = self.mark()
        inspect = self.r._inspect

        def final_error(*args):
            inspect(*args)
            raise ValueError("modeled final context error")

        with mock.patch.object(
            self.r, "_inspect", side_effect=final_error
        ), self.assertRaises(ValueError):
            self.complete(marked)
        self.assertTrue((self.path / "complete.json").exists())
        self.assertEqual(
            json.loads((self.base.path() / "HEAD.json").read_bytes())["state"],
            "pending",
        )

    def test_runtime_writer_cannot_mutate_the_expected_profile(self):
        intent = self.prepare()
        raw, sha = self.encoded(intent)
        writer = self.r._write

        def change(path, value, limit):
            if path == self.r.RUNTIME_ROOT / "runtime.json":
                value["legacy_schema"] = 99
            return writer(path, value, limit)

        with mock.patch.object(self.r, "_write", side_effect=change), self.assertRaises(
            ValueError
        ):
            self.call(self.r._begin, self.owner, raw, sha)
        self.assertEqual(self.r.RUNTIME["legacy_schema"], 3)
        self.assertFalse((self.base.path() / self.r.MARKER).exists())


if __name__ == "__main__":
    unittest.main()
