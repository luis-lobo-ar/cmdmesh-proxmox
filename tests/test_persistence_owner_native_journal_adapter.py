"""Real local v4 publications; no native request or live admission is modeled as proof."""

import os
import unittest
from unittest import mock

import test_persistence_owner_native_ready as ready
import test_persistence_owner_request_journal as journal_fixture


class NativeJournalAdapterTests(unittest.TestCase):
    setUp = ready.NativeReadyTests.setUp
    used_head = ready.NativeReadyTests.used_head

    def adapter(self, head=None):
        return self.n._native_journal(
            self.binding,
            self.f.mount,
            accepted_head_sha256=self.head if head is None else head,
        )

    def model(self):
        fixture = journal_fixture.RequestJournalTests("runTest")
        fixture.j, fixture.owner, fixture.guest = (
            self.j,
            self.binding,
            self.binding.guest,
        )
        fixture.epoch = self.j.observe.decode(
            self.f.s.probe_protocol(allow_mutation=True).raw
        )["host_epoch"]
        fixture.call = lambda function, *args: function(*args)
        return fixture

    def dispatch_payload(self, fixture, operation):
        with mock.patch.object(
            fixture, "append", side_effect=lambda op, stage, payload: payload
        ):
            return fixture.dispatch(operation)

    def through_terminal(self, tx, kind="shutdown"):
        fixture = self.model()
        tx.begin(kind=kind, prepared_sha256="c" * 64)
        tx.dispatch(self.dispatch_payload(fixture, tx.pending))
        observation = fixture.observation(tx.pending)
        tx.observed(observation)
        tx.ack(fixture.certified(tx.pending, observation))
        with mock.patch.object(
            fixture, "append", side_effect=lambda op, stage, payload: payload
        ):
            terminal = fixture.terminal(tx.pending)
        tx.terminal(terminal)

    def test_both_kinds_publish_fixed_prefix_and_ready_candidate(self):
        for kind in ("shutdown", "resume"):
            with self.subTest(kind=kind):
                with self.adapter() as tx:
                    self.through_terminal(tx, kind)
                    result = tx.complete({"modeled_current": kind})
                    self.assertEqual(result.sequence, 1 if kind == "shutdown" else 2)
                    self.assertEqual(
                        tuple(tx.pending.phases.records),
                        tuple(name + ".json" for name in self.j.STAGES),
                    )
                    tx.check()
                self.head = result.head_sha256

    def test_ready_used_history_stays_retained_while_next_slot_grows(self):
        head = self.used_head()
        old = self.j.RUNTIME_ROOT / self.binding.pair_key / self.j._slot(1)
        original = {path.name: path.read_bytes() for path in old.iterdir()}
        with self.adapter(head) as tx:
            self.through_terminal(tx)
            tx.complete({"modeled_current": "shutdown"})
        self.assertEqual(
            {path.name: path.read_bytes() for path in old.iterdir()}, original
        )

    def test_same_byte_old_file_mutation_during_begin_is_not_hidden(self):
        original = self.j._begin
        path = self.j.RUNTIME_ROOT / self.binding.pair_key / "genesis.json"

        def changed(*args):
            pending = original(*args)
            with path.open("r+b") as stream:
                stream.write(path.read_bytes())
            return pending

        with self.assertRaises(ValueError), self.adapter() as tx:
            with mock.patch.object(self.j, "_begin", side_effect=changed):
                tx.begin(kind="shutdown", prepared_sha256="c" * 64)
        self.assertIsNotNone(tx.pending)
        with mock.patch.object(self.j, "_begin") as begin:
            with self.assertRaises(ValueError):
                tx.begin(kind="shutdown", prepared_sha256="c" * 64)
            begin.assert_not_called()

    def test_new_phase_becomes_immutable_before_next_transition(self):
        fixture = self.model()
        with self.assertRaises(ValueError), self.adapter() as tx:
            tx.begin(kind="shutdown", prepared_sha256="c" * 64)
            tx.dispatch(self.dispatch_payload(fixture, tx.pending))
            path = (
                self.j.RUNTIME_ROOT
                / self.binding.pair_key
                / self.j._slot(1)
                / "dispatch.json"
            )
            with path.open("r+b") as stream:
                stream.write(path.read_bytes())
            tx.check()

    def test_persistent_unknown_child_refuses_without_consuming_a_slot(self):
        with self.assertRaises(ValueError), self.adapter() as tx:
            path = self.j.RUNTIME_ROOT / self.binding.pair_key / "unexpected"
            path.touch(mode=0o600)
            tx.begin(kind="shutdown", prepared_sha256="c" * 64)
        self.assertIsNone(tx.pending)
        self.assertFalse(path.with_name(self.j._slot(1)).exists())

    def test_partial_phase_publication_poison_prevents_retry(self):
        fixture = self.model()
        original = self.j._append_phase

        def fail(*args):
            original(*args)
            raise OSError("modeled failure after phase publication")

        with self.assertRaisesRegex(OSError, "after phase"), self.adapter() as tx:
            tx.begin(kind="shutdown", prepared_sha256="c" * 64)
            with mock.patch.object(self.j, "_append_phase", side_effect=fail):
                tx.dispatch(self.dispatch_payload(fixture, tx.pending))
        with mock.patch.object(self.j, "_append_phase") as append:
            with self.assertRaises(ValueError):
                tx.dispatch({})
            append.assert_not_called()
        self.assertTrue(
            (
                self.j.RUNTIME_ROOT
                / self.binding.pair_key
                / self.j._slot(1)
                / "dispatch.json"
            ).exists()
        )

    def test_invalid_ack_keeps_observation_and_refuses_ack_publication(self):
        fixture = self.model()
        observation = None
        with self.assertRaises(ValueError), self.adapter() as tx:
            tx.begin(kind="shutdown", prepared_sha256="c" * 64)
            tx.dispatch(self.dispatch_payload(fixture, tx.pending))
            observation = fixture.observation(tx.pending)
            tx.observed(observation)
            tx.ack({})
        slot = self.j.RUNTIME_ROOT / self.binding.pair_key / self.j._slot(1)
        recorded = self.j.observe.decode((slot / "ack-observed.json").read_bytes())
        self.assertEqual(recorded["payload"], observation)
        self.assertFalse((slot / "ack.json").exists())
        self.assertFalse((slot / "result.json").exists())

    def test_transient_old_slot_child_during_append_is_observed(self):
        head = self.used_head()
        fixture = self.model()
        original = self.j._append_phase
        path = (
            self.j.RUNTIME_ROOT / self.binding.pair_key / self.j._slot(1) / "unexpected"
        )

        def changed(*args):
            pending = original(*args)
            path.touch(mode=0o600)
            path.unlink()
            return pending

        with self.assertRaises(ValueError), self.adapter(head) as tx:
            tx.begin(kind="shutdown", prepared_sha256="c" * 64)
            with mock.patch.object(self.j, "_append_phase", side_effect=changed):
                tx.dispatch(self.dispatch_payload(fixture, tx.pending))

    def test_wrong_phase_and_duplicate_begin_never_call_primitive(self):
        with self.adapter() as tx:
            with mock.patch.object(self.j, "_append_phase") as append:
                with self.assertRaises(ValueError):
                    tx.ack({})
                append.assert_not_called()
        with self.adapter() as tx:
            tx.begin(kind="shutdown", prepared_sha256="c" * 64)
            with mock.patch.object(self.j, "_begin") as begin:
                with self.assertRaises(ValueError):
                    tx.begin(kind="shutdown", prepared_sha256="c" * 64)
                begin.assert_not_called()

    def test_late_candidate_mutation_refuses_and_releases_all_fds(self):
        before = len(os.listdir("/proc/self/fd"))
        with self.assertRaises(ValueError), self.adapter() as tx:
            self.through_terminal(tx)
            result = tx.complete({"modeled_current": "shutdown"})
            path = (
                self.j.RUNTIME_ROOT
                / self.binding.pair_key
                / self.j._slot(result.sequence)
                / "result.json"
            )
            with path.open("r+b") as stream:
                stream.write(path.read_bytes())
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)


if __name__ == "__main__":
    unittest.main()
