"""Real native chain observers; task/current evidence is explicitly modeled."""

import os
import unittest
from unittest import mock

import test_persistence_owner_native_namespace as namespace_fixture
import test_persistence_owner_request_journal as journal_fixture


class NativeReadyTests(unittest.TestCase):
    def setUp(self):
        self.f = namespace_fixture.NativeNamespaceTests("runTest")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.n = namespace_fixture.candidate
        self.j, self.binding = self.f.j, self.f.binding
        self.f.initialize()
        self.head = self.j._digest(self.j._genesis(self.binding))

    def observe(self, head=None):
        return self.n._observe_ready_journal(
            self.binding,
            self.f.mount,
            accepted_head_sha256=self.head if head is None else head,
        )

    def used_head(self):
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
        pending = self.j._begin(self.binding, self.head, "shutdown", "a" * 64)
        operation = fixture.terminal(fixture.through_ack(pending))
        return self.j._complete(operation, {"modeled_current": "shutdown"}).head_sha256

    def test_genesis_observation_is_readonly_and_has_retained_fds(self):
        before = self.f.f.files()
        with self.observe() as held:
            self.assertIn(
                str(self.j.RUNTIME_ROOT / self.binding.pair_key / "HEAD.json"),
                held.nodes,
            )
        self.assertEqual(self.f.f.files(), before)

    def test_used_chain_including_phase_files_is_retained(self):
        head = self.used_head()
        with self.observe(head) as held:
            names = {os.path.basename(path) for path in held.nodes}
            self.assertTrue(
                {
                    "dispatch.json",
                    "ack-observed.json",
                    "ack.json",
                    "terminal.json",
                    "result.json",
                }
                <= names
            )

    def test_stale_head_and_pending_prefix_are_not_ready_authority(self):
        pending = self.j._begin(self.binding, self.head, "shutdown", "a" * 64)
        for head in (self.head, pending.pending_head_sha256):
            with self.subTest(head=head), self.assertRaises(ValueError):
                with self.observe(head):
                    self.fail("pending admitted as ready")

    def test_same_byte_old_phase_write_is_observed(self):
        head = self.used_head()
        path = (
            self.j.RUNTIME_ROOT
            / self.binding.pair_key
            / self.j._slot(1)
            / "ack-observed.json"
        )
        mutated = False
        with self.assertRaises(ValueError):
            with self.observe(head):
                raw = path.read_bytes()
                with path.open("r+b") as stream:
                    stream.write(raw)
                mutated = True
        self.assertTrue(mutated)

    def test_transient_unknown_selected_pair_child_is_observed(self):
        mutated = False
        with self.assertRaises(ValueError):
            with self.observe():
                path = self.j.RUNTIME_ROOT / self.binding.pair_key / "unexpected"
                path.touch(mode=0o600)
                path.unlink()
                mutated = True
        self.assertTrue(mutated)

    def test_partial_constructor_failure_releases_new_and_parent_fds(self):
        before = len(os.listdir("/proc/self/fd"))
        original = os.open

        def fail(path, *args, **kwargs):
            if os.fsdecode(path) == "HEAD.json":
                raise OSError("modeled HEAD open failure")
            return original(path, *args, **kwargs)

        with mock.patch.object(os, "open", side_effect=fail):
            with self.assertRaisesRegex(OSError, "modeled HEAD open failure"):
                with self.observe():
                    self.fail("failed observer admitted")
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)


if __name__ == "__main__":
    unittest.main()
