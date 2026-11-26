"""Local parent/file event witness; caller current/old-slot leases are separate."""

import copy
from dataclasses import replace
import json
import os
import unittest
from unittest import mock

import test_persistence_owner_attempt as fixture
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_publication_witness as witness,
)


class PublicationWitnessTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.AttemptTests("runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.r = self.case.r
        self.retirement = self.case.case
        self.owner = self.retirement.owner
        self.h0, self.sha = self.case.h0, self.case.sha

    def prepare(self, action):
        root = self.r.RUNTIME_ROOT
        pair = self.retirement.path
        if action == "finish-runtime":
            root.mkdir(mode=0o700)
            return (
                None,
                None,
                root / "runtime.json",
                self.r.state.canonical(fixture.profile.RUNTIME),
            )
        self.case.version_two()
        pair.mkdir(mode=0o700)
        if action == "record-intent":
            return None, None, pair / "intent.json", self.h0
        self.r.backup.write_private(pair / "intent.json", json.loads(self.h0))
        marker = self.r.state.canonical(self.r._marker(self.owner, self.sha))
        path = self.retirement.base.path() / self.r.MARKER
        if action == "publish-marker":
            return None, None, path, marker
        self.r.backup.write_private(path, json.loads(marker))

        def descriptor(path):
            return {
                "path": str(path),
                "sha256": self.r.state.sha256(path.read_bytes()),
                "identity": list(self.r.observe.stable(path.stat())),
            }

        closing = copy.deepcopy(json.loads(self.h0)["caller_evidence"])
        closing["current_sha256"] = self.r.state.sha256(
            b"synthetic unqualified closing"
        )
        body = self.r._completion(
            self.owner,
            self.sha,
            descriptor(pair / "intent.json"),
            marker,
            descriptor(path),
            json.loads(self.h0)["basis"],
            closing,
        )
        raw = self.r.state.canonical(body)
        return raw, self.r.state.sha256(raw), pair / "complete.json", raw

    def scope(self, action, complete=None, complete_sha=None):
        return witness.observe_control_publication(
            self.owner,
            self.h0,
            self.sha,
            action,
            event_profile=witness.EVENT_PROFILE,
            complete_raw=complete,
            complete_sha256=complete_sha,
        )

    def test_intent_has_one_closed_receipt_and_no_visible_staging(self):
        _, _, path, expected = self.prepare("record-intent")
        before = self.retirement.originals()
        with self.scope("record-intent") as phase:
            self.assertIsNone(phase.receipt)
            receipt = phase.publish()
            self.assertEqual(receipt.path, str(path))
            self.assertEqual(receipt.payload_sha256, self.sha)
            self.assertIs(phase.seal, phase)
        self.assertTrue(phase.closed)
        self.assertEqual(path.read_bytes(), expected)
        self.assertEqual(set(p.name for p in path.parent.iterdir()), {"intent.json"})
        self.retirement.assert_preserved(before)

    def test_runtime_and_marker_use_only_derived_payloads(self):
        _, _, path, raw = self.prepare("publish-marker")
        with self.scope("publish-marker") as phase:
            phase.publish()
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(phase.receipt.payload_sha256, self.r.state.sha256(raw))

    def test_completion_binds_selected_bytes(self):
        raw, sha, path, _ = self.prepare("record-completion")
        with self.scope("record-completion", raw, sha) as phase:
            phase.publish()
        self.assertEqual(path.read_bytes(), raw)

    def test_shared_runtime_allows_other_private_pair_churn_after_publication(self):
        self.prepare("finish-runtime")
        other = ("a" if self.owner.pair_key[0] != "a" else "b") * 64
        with self.scope("finish-runtime") as phase:
            phase.publish()
            sibling = self.r.RUNTIME_ROOT / other
            sibling.mkdir(mode=0o700)
            sibling.rmdir()

    def test_wrong_action_profile_or_completion_hash_refuses(self):
        for value in ("unknown", True, []):
            with self.subTest(value=value), self.assertRaises(ValueError):
                with self.scope(value):
                    pass
        self.prepare("record-intent")
        with self.assertRaises(ValueError):
            with witness.observe_control_publication(
                self.owner, self.h0, self.sha, "record-intent", event_profile="guess"
            ):
                pass

    def test_publish_is_single_use_and_closed_context_cannot_publish(self):
        self.prepare("record-intent")
        with self.assertRaisesRegex(ValueError, "poisoned"):
            with self.scope("record-intent") as phase:
                phase.publish()
                with self.assertRaises(ValueError):
                    phase.publish()
        with self.assertRaises(ValueError):
            phase.publish()

    def test_context_without_publication_is_not_positive(self):
        _, _, path, _ = self.prepare("record-intent")
        with self.assertRaises(ValueError):
            with self.scope("record-intent"):
                pass
        self.assertFalse(path.exists())

    def test_existing_destination_is_never_replaced(self):
        _, _, path, raw = self.prepare("record-intent")
        path.write_bytes(raw)
        path.chmod(0o600)
        before = self.r.observe.stable(path.stat())
        with self.assertRaises(ValueError):
            with self.scope("record-intent") as phase:
                phase.publish()
        self.assertEqual(self.r.observe.stable(path.stat()), before)

    def test_transient_unknown_sibling_during_primitive_refuses(self):
        _, _, path, raw = self.prepare("record-intent")
        original = witness.atomic.publish_observed

        def injected(*args, **kwargs):
            receipt = original(*args, **kwargs)
            sibling = path.parent / "unexpected"
            sibling.write_bytes(b"extra")
            sibling.unlink()
            return receipt

        with mock.patch.object(
            witness.atomic, "publish_observed", side_effect=injected
        ):
            with self.assertRaises(ValueError):
                with self.scope("record-intent") as phase:
                    phase.publish()
        self.assertEqual(path.read_bytes(), raw)

    def test_old_root_equal_byte_write_is_not_an_intentional_marker_event(self):
        self.prepare("publish-marker")
        original = witness.atomic.publish_observed
        head = self.retirement.base.path() / "HEAD.json"
        raw = head.read_bytes()

        def injected(*args, **kwargs):
            result = original(*args, **kwargs)
            head.write_bytes(raw)
            return result

        with mock.patch.object(
            witness.atomic, "publish_observed", side_effect=injected
        ):
            with self.assertRaises(ValueError):
                with self.scope("publish-marker") as phase:
                    phase.publish()

    def test_named_final_same_byte_write_after_publish_refuses(self):
        _, _, path, raw = self.prepare("record-intent")
        with self.assertRaises(ValueError):
            with self.scope("record-intent") as phase:
                phase.publish()
                path.write_bytes(raw)

    def test_wrong_anonymous_receipt_token_refuses(self):
        self.prepare("record-intent")
        original = witness.atomic.publish_observed

        def injected(*args, **kwargs):
            return replace(original(*args, **kwargs), anonymous_name="#wrong")

        with mock.patch.object(
            witness.atomic, "publish_observed", side_effect=injected
        ):
            with self.assertRaises(ValueError):
                with self.scope("record-intent") as phase:
                    phase.publish()

    def test_unknown_primitive_result_cannot_be_qualified_from_full_file(self):
        _, _, path, raw = self.prepare("record-intent")
        original = witness.atomic.publish_observed

        def injected(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("unknown result")

        before = len(os.listdir("/proc/self/fd"))
        with mock.patch.object(
            witness.atomic, "publish_observed", side_effect=injected
        ):
            with self.assertRaisesRegex(OSError, "unknown result"):
                with self.scope("record-intent") as phase:
                    phase.publish()
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_failed_primitive_cannot_be_retried_in_the_same_scope(self):
        self.prepare("record-intent")
        with self.assertRaisesRegex(ValueError, "poisoned"):
            with self.scope("record-intent") as phase:
                with mock.patch.object(
                    witness.atomic,
                    "publish_observed",
                    side_effect=OSError("before write"),
                ):
                    with self.assertRaises(OSError):
                        phase.publish()
                with self.assertRaisesRegex(ValueError, "single-use"):
                    phase.publish()

    def test_changed_binding_refuses_before_a_file_is_published(self):
        _, _, path, _ = self.prepare("record-intent")
        with self.assertRaises(ValueError):
            with self.scope("record-intent") as phase:
                object.__setattr__(
                    self.owner,
                    "authority_sha256",
                    self.r.state.sha256(b"wrong binding"),
                )
                phase.publish()
        self.assertFalse(path.exists())

    def test_missing_stored_intent_blocks_marker_before_publication(self):
        _, _, path, _ = self.prepare("publish-marker")
        (self.retirement.path / "intent.json").unlink()
        with self.assertRaises(ValueError):
            with self.scope("publish-marker") as phase:
                phase.publish()
        self.assertFalse(path.exists())

    def test_changed_intent_blocks_completion_before_publication(self):
        raw, sha, path, _ = self.prepare("record-completion")
        (self.retirement.path / "intent.json").write_bytes(b"foreign")
        with self.assertRaises(ValueError):
            with self.scope("record-completion", raw, sha) as phase:
                phase.publish()
        self.assertFalse(path.exists())

    def test_equal_byte_marker_descriptor_drift_blocks_completion(self):
        raw, sha, path, _ = self.prepare("record-completion")
        marker = self.retirement.base.path() / self.r.MARKER
        before = marker.read_bytes()
        marker.write_bytes(before)
        with self.assertRaises(ValueError):
            with self.scope("record-completion", raw, sha) as phase:
                phase.publish()
        self.assertFalse(path.exists())

    def test_binding_changed_by_last_prewrite_probe_cannot_publish(self):
        _, _, path, _ = self.prepare("record-intent")
        original = self.owner.authority_sha256
        try:
            with self.assertRaises(ValueError):
                with self.scope("record-intent") as phase:
                    check = phase._parent.check_events

                    def drift():
                        check()
                        object.__setattr__(self.owner, "authority_sha256", "f" * 64)

                    with mock.patch.object(
                        phase._parent, "check_events", side_effect=drift
                    ):
                        phase.publish()
            self.assertFalse(path.exists())
        finally:
            object.__setattr__(self.owner, "authority_sha256", original)

    def test_caught_publish_event_failure_permanently_poisoned_context(self):
        self.prepare("finish-runtime")
        failures = []
        with self.assertRaises(ValueError):
            with self.scope("finish-runtime") as phase:
                check = phase._parent.check_events
                fired = False

                def transient():
                    nonlocal fired
                    if phase.receipt is not None and not fired:
                        fired = True
                        extra = self.r.RUNTIME_ROOT / "unexpected"
                        extra.write_bytes(b"event")
                        extra.unlink()
                    return check()

                with mock.patch.object(
                    phase._parent, "check_events", side_effect=transient
                ):
                    try:
                        phase.publish()
                    except ValueError as error:
                        failures.append(str(error))
                self.assertEqual(
                    failures, ["persistence-owner-retirement-attempt-event"]
                )

    def test_caught_late_seal_event_also_poisoned_context(self):
        self.prepare("finish-runtime")
        with self.assertRaisesRegex(ValueError, "poisoned"):
            with self.scope("finish-runtime") as phase:
                phase.publish()
                extra = self.r.RUNTIME_ROOT / "unexpected"
                extra.write_bytes(b"event")
                extra.unlink()
                with self.assertRaises(ValueError):
                    phase.seal.check_events()

    def test_repeated_release_never_closes_a_reused_foreign_descriptor(self):
        self.prepare("record-intent")
        with self.scope("record-intent") as phase:
            phase.publish()
        target = phase._parent.event
        path = self.retirement.base.root / "foreign-descriptor"
        path.write_bytes(b"foreign")
        source = os.open(path, os.O_RDONLY)
        if source != target:
            os.dup2(source, target)
            os.close(source)
        try:
            try:
                phase.release()
            except (ValueError, OSError):
                pass
            opened = True
            try:
                os.fstat(target)
            except OSError:
                opened = False
            self.assertTrue(opened, "repeat cleanup closed an unrelated reused FD")
        finally:
            try:
                os.close(target)
            except OSError:
                pass

    def test_inherited_phase_cannot_publish_from_a_forked_process(self):
        self.prepare("record-intent")
        with self.scope("record-intent") as phase:
            read, write = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(read)
                try:
                    try:
                        phase.publish()
                        result = b"published"
                    except ValueError:
                        result = b"refused"
                    os.write(write, result)
                finally:
                    os._exit(0)
            os.close(write)
            try:
                result = os.read(read, 64)
            finally:
                os.close(read)
                os.waitpid(child, 0)
            self.assertEqual(result, b"refused")
            phase.publish()


if __name__ == "__main__":
    unittest.main()
