"""Mandatory durable native-phase metadata does not authorize a native action."""

import copy
import json
from pathlib import Path
import unittest
from unittest import mock

import test_persistence_owner_journal as fixture

journal, pair, api = fixture.journal, fixture.pair, fixture.api


class OwnerJournalPhaseTests(unittest.TestCase):
    def setUp(self):
        self.base = fixture.OwnerJournalTests("runTest")
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.head = self.base.initialize()["head_sha256"]
        self.pending = self.base.begin(self.head)
        self.payloads = fixture.phase_payloads(self.pending)

    def append(self, pending, stage, payload=None):
        with pair.locked_pair(self.base.datasets):
            return journal._append_phase(
                pending, stage, self.payloads[stage] if payload is None else payload
            )

    def finish_phases(self):
        pending = self.pending
        for stage in self.payloads:
            pending = self.append(pending, stage)
        return pending

    def test_complete_requires_all_three_phases_without_a_bypass(self):
        pending = self.pending
        for stage in (None, "dispatch", "ack"):
            if stage is not None:
                pending = self.append(pending, stage)
            with pair.locked_pair(self.base.datasets), self.assertRaises(ValueError):
                journal._complete(pending, {"current": "caller-validated"})
        pending = self.append(pending, "terminal")
        with pair.locked_pair(self.base.datasets):
            candidate = journal._complete(pending, {"current": "caller-validated"})
        self.assertEqual(
            set(candidate.phases.files), {"dispatch.json", "ack.json", "terminal.json"}
        )
        self.assertEqual(
            candidate.phases.sha256, journal._digest(candidate.phases.files)
        )

    def test_append_refreshes_token_and_old_token_cannot_append_or_complete(self):
        current = self.append(self.pending, "dispatch")
        before = self.base.files()
        for use in ("append", "complete"):
            with self.subTest(use=use), self.assertRaises(ValueError):
                if use == "append":
                    self.append(self.pending, "ack")
                else:
                    with pair.locked_pair(self.base.datasets):
                        journal._complete(self.pending, {})
        self.assertEqual(before, self.base.files())
        self.assertEqual(set(current.phases.files), {"dispatch.json"})
        self.append(current, "ack")

    def test_out_of_order_duplicate_or_unknown_phase_never_writes(self):
        for stage in ("ack", "terminal", "../dispatch", "ticket"):
            before = self.base.files()
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                self.append(self.pending, stage, {})
            self.assertEqual(before, self.base.files())
        current = self.append(self.pending, "dispatch")
        before = self.base.files()
        with self.assertRaises(ValueError):
            self.append(current, "dispatch")
        self.assertEqual(before, self.base.files())

    def test_wrong_action_scope_clock_or_secret_fields_refuse_before_record(self):
        for change in (
            {"action": "start"},
            {"prepared_sha256": "f" * 64},
            {"clock": True},
            {"entry_sha256": "not-a-digest"},
            {"binding": dict(self.payloads["dispatch"]["binding"], vmid=103)},
            {"parameters": {"forceStop": "1", "timeout": "60"}},
            {"csrf": "PRIVATE_SENTINEL"},
        ):
            before = self.base.files()
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.append(
                    self.pending, "dispatch", dict(self.payloads["dispatch"], **change)
                )
            self.assertEqual(before, self.base.files())

    def test_ack_and_terminal_must_match_the_same_target_task_and_classifier(self):
        pending = self.append(self.pending, "dispatch")
        for change in (
            {"tls_verified": False},
            {"upid": self.payloads["ack"]["upid"].replace(":102:", ":103:")},
            {"upid": self.payloads["ack"]["upid"].replace(":vzshutdown:", ":vzstart:")},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.append(pending, "ack", dict(self.payloads["ack"], **change))
        pending = self.append(pending, "ack")
        for fault in ("foreign-task", "forged-outcome", "running"):
            value = copy.deepcopy(self.payloads["terminal"])
            if fault == "foreign-task":
                value["task"]["id"] = "103"
            if fault == "forged-outcome":
                value["native_outcome"]["accepted"] = 1
            if fault == "running":
                value["task"].pop("exitstatus")
                value["task"]["status"] = "running"
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.append(pending, "terminal", value)

    def test_rejected_terminal_is_retained_but_cannot_publish_ready_head(self):
        pending = self.append(self.append(self.pending, "dispatch"), "ack")
        value = copy.deepcopy(self.payloads["terminal"])
        value["task"]["exitstatus"] = "error"
        value["log"] = [{"n": 1, "t": "TASK ERROR: refused"}]
        value["native_outcome"] = api.native_outcome(value["task"], value["log"])
        pending = self.append(pending, "terminal", value)
        with pair.locked_pair(self.base.datasets), self.assertRaises(ValueError):
            journal._complete(pending, {})
        self.assertTrue(
            (self.base.path() / journal._slot(1) / "terminal.json").exists()
        )
        with self.assertRaises(ValueError):
            self.base.begin(self.head, "resume")

    def test_every_phase_durability_failure_preserves_a_barrier(self):
        write = journal._write
        for stage in ("dispatch", "ack", "terminal"):
            case = fixture.OwnerJournalTests("runTest")
            case.setUp()
            try:
                head = case.initialize()["head_sha256"]
                pending = case.begin(head)
                payloads = fixture.phase_payloads(pending)
                for previous in payloads:
                    if previous == stage:
                        break
                    with pair.locked_pair(case.datasets):
                        pending = journal._append_phase(
                            pending, previous, payloads[previous]
                        )

                def fail(path, value):
                    checksum = write(path, value)
                    if path.name == stage + ".json":
                        raise OSError("injected post-fsync failure")
                    return checksum

                with self.subTest(stage=stage), mock.patch.object(
                    journal, "_write", side_effect=fail
                ), pair.locked_pair(case.datasets), self.assertRaises(OSError):
                    journal._append_phase(pending, stage, payloads[stage])
                with self.assertRaises(ValueError):
                    case.begin(head, "resume")
                with pair.locked_pair(case.datasets), self.assertRaises(ValueError):
                    journal._append_phase(pending, stage, payloads[stage])
            finally:
                case.doCleanups()

    def test_valid_record_drift_after_write_cannot_return_a_fresh_token(self):
        write = journal._write
        for stage in ("dispatch", "ack", "terminal"):
            case = fixture.OwnerJournalTests("runTest")
            case.setUp()
            try:
                head = case.initialize()["head_sha256"]
                pending = case.begin(head)
                payloads = fixture.phase_payloads(pending)
                for previous in payloads:
                    if previous == stage:
                        break
                    with pair.locked_pair(case.datasets):
                        pending = journal._append_phase(
                            pending, previous, payloads[previous]
                        )

                def drift(path, value):
                    checksum = write(path, value)
                    if path.name == stage + ".json":
                        changed = copy.deepcopy(value)
                        if stage == "dispatch":
                            changed["payload"]["entry_sha256"] = "f" * 64
                        elif stage == "ack":
                            parts = changed["payload"]["upid"].split(":")
                            parts[2] = f"{int(parts[2], 16) + 1:08X}"
                            changed["payload"]["upid"] = ":".join(parts)
                        else:
                            changed["payload"]["log"] = [
                                {"n": 1, "t": "different valid task detail"},
                                {"n": 2, "t": "TASK OK"},
                            ]
                        path.write_bytes(journal.state.canonical(changed))
                    return checksum

                with self.subTest(stage=stage), mock.patch.object(
                    journal, "_write", side_effect=drift
                ), pair.locked_pair(case.datasets), self.assertRaises(ValueError):
                    journal._append_phase(pending, stage, payloads[stage])
                # The drifted record remains valid in isolation. Refusal must
                # bind what was requested, rather than reject its syntax.
                journal._inspect(case.binding, pending.pending_head_sha256)
                with self.assertRaises(ValueError):
                    case.begin(head, "resume")
            finally:
                case.doCleanups()

    def test_capture_recomputes_raw_hashes_scope_and_metadata_without_io(self):
        pending = self.finish_phases()
        slot = self.base.path() / journal._slot(1)
        intent = json.loads((slot / "intent.json").read_bytes())
        raw = {name: (slot / name).read_bytes() for name in pending.phases.files}
        with mock.patch.object(
            journal.observe, "read_regular", side_effect=AssertionError("capture IO")
        ), mock.patch.object(
            api, "post_guest_action", side_effect=AssertionError("native")
        ):
            captured = journal.validate_phase_capture(
                self.base.binding, intent, raw, pending.phases.files
            )
        self.assertEqual(captured.sha256, pending.phases.sha256)
        for fault in ("raw", "metadata", "missing"):
            changed, descriptors = dict(raw), copy.deepcopy(pending.phases.files)
            if fault == "raw":
                changed["ack.json"] = b"{}"
            if fault == "metadata":
                descriptors["ack.json"]["identity"][2] |= 0o040
            if fault == "missing":
                changed.pop("ack.json")
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                journal.validate_phase_capture(
                    self.base.binding, intent, changed, descriptors
                )

    def test_failure_barrier_can_follow_phases_using_the_original_pending(self):
        self.finish_phases()
        with pair.locked_pair(self.base.datasets):
            journal._fail(self.pending, "unknown-ack", "unknown")
        with self.assertRaises(ValueError):
            journal._inspect(self.base.binding, self.pending.pending_head_sha256)

    def test_old_metadata_profile_is_not_silently_upgraded(self):
        with mock.patch.object(
            journal, "RUNTIME_ROOT", self.base.root / "unused-journal"
        ):
            self.base.initialize()
            path = journal.RUNTIME_ROOT / "runtime.json"
            old = dict(journal.RUNTIME, schema_version=1)
            path.write_bytes(journal.state.canonical(old))
            before = self.base.files()
            with self.assertRaises(ValueError):
                self.base.initialize()
            self.assertEqual(before, self.base.files())


if __name__ == "__main__":
    unittest.main()
