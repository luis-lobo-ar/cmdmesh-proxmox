"""Frozen legacy admission refuses a per-pair tombstone before any new SDK exists.

Markers here are injected fixture states, not a qualified durable publisher or
native worker fence. All guest/current/API providers are modeled or forbidden.
"""

import json
import os
import subprocess
import sys
import unittest
from unittest import mock

import test_persistence_owner_journal as fixture
import test_persistence_owner_transition as transition_fixture

j, pair, api = fixture.journal, fixture.pair, fixture.api
MARKER = "RETIRED-v4.json"


class RetirementCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.base = fixture.OwnerJournalTests("runTest")
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        for name in ("post_guest_action", "post_owner_guest_action", "get"):
            self.enterContext(
                mock.patch.object(api, name, side_effect=AssertionError("native IO"))
            )

    def marker(self, body, base=None):
        base = base or self.base
        with pair.locked_pair(base.datasets):
            path = base.path() / MARKER
            path.write_bytes(body)
            path.chmod(0o600)
        return path

    def test_marker_refuses_all_legacy_journal_layouts_without_rewriting_history(self):
        # Fresh fixture roots model independent owners, never a nonce reset.
        for layout in ("ready", "pending", "completed", "resolved"):
            child = fixture.OwnerJournalTests("runTest")
            child.setUp()
            try:
                anchor = child.initialize()["head_sha256"]
                raw_anchor = (child.path() / "HEAD.json").read_bytes()
                head = anchor
                if layout != "ready":
                    pending = child.begin(anchor)
                    head = pending.pending_head_sha256
                    if layout == "completed":
                        head = child.complete(pending).head_sha256
                    if layout == "resolved":
                        with pair.locked_pair(child.datasets):
                            basis = j.capture_basis(child.binding)
                            prepared = j.prepare_resolution(
                                child.binding,
                                raw_anchor,
                                anchor,
                                j._digest(basis),
                                {
                                    "phase": "os_quiesced",
                                    "current_sha256": "d" * 64,
                                    "worker_fence_sha256": "e" * 64,
                                },
                            )
                            raw = j.state.canonical(prepared)
                            resolution = j.begin_resolution(
                                child.binding, raw, j.state.sha256(raw)
                            )
                            head = j.complete_resolution(resolution).head_sha256
                with pair.locked_pair(child.datasets):
                    j._inspect(child.binding, head)
                self.marker(b'{"fixture":"retired"}', child)
                preserved = child.files()
                calls = (
                    lambda: j._inspect(child.binding, head),
                    lambda: j._initialize(child.binding),
                    lambda: j._begin(child.binding, head, "resume", "f" * 64),
                    lambda: j.capture_basis(child.binding),
                )
                for call in calls:
                    with self.subTest(layout=layout), pair.locked_pair(
                        child.datasets
                    ), self.assertRaises(ValueError):
                        call()
                self.assertEqual(preserved, child.files())
            finally:
                child.doCleanups()

    @unittest.skipUnless(
        os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
    )
    def test_stale_legacy_preparation_cannot_post_after_marker(self):
        for body in (b"", b'{"partial":', b'{"fixture":"retired"}'):
            old = transition_fixture.OwnerTransitionTests("runTest")
            old.setUp()
            try:
                head = old.initialize()
                prepared = old.prepare(head)
                raw = old.sdk.state.canonical(prepared)
                checksum = old.sdk.state.sha256(raw)
                self.marker(body, old.case)
                preserved = old.case.files()
                for call in (
                    lambda: old.sdk.initialize(old.checkpoint, head),
                    lambda: old.sdk.inspect_initialization(old.checkpoint, head),
                    lambda: old.sdk.prepare(old.checkpoint, head, "shutdown"),
                    lambda: old.sdk.inspect_transition(old.checkpoint, raw, checksum),
                    lambda: old.operate(prepared),
                ):
                    with self.subTest(body=body), self.assertRaises(ValueError):
                        call()
                self.assertEqual(old.post_count, 0)
                self.assertEqual(preserved, old.case.files())
                self.assertFalse(old.app_held)
                self.assertEqual(old.native_locks, set())
            finally:
                old.doCleanups()

    def unrelated_owner(self):
        datasets = {"data": {"guid": "33"}, "config": {"guid": "44"}}
        owner = j.Binding(
            j.state.pair_key(datasets),
            "e" * 64,
            api.GuestBinding("pve-other", 103, "4" * 64, "5" * 64, "6" * 64),
        )
        with pair.locked_pair(datasets, initialize=True):
            head = j._initialize(owner)["head_sha256"]
        return datasets, owner, head

    @unittest.skipUnless(
        os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
    )
    def test_legacy_status_refuses_marker_after_a_modeled_completed_transition(self):
        old = transition_fixture.OwnerTransitionTests("runTest")
        old.setUp()
        try:
            prepared = old.prepare(old.initialize())
            completed = old.operate(prepared)
            raw = old.sdk.state.canonical(prepared)
            checksum = old.sdk.state.sha256(raw)
            before = old.sdk.status(
                old.checkpoint, raw, checksum, completed["head_sha256"]
            )
            self.assertTrue(before["os_transition_verified"])
            self.assertEqual(old.post_count, 1)
            self.marker(b'{"fixture":"retired"}', old.case)
            preserved = old.case.files()
            with self.assertRaises(ValueError):
                old.sdk.status(old.checkpoint, raw, checksum, completed["head_sha256"])
            self.assertEqual(old.post_count, 1)
            self.assertEqual(preserved, old.case.files())
        finally:
            old.doCleanups()

    def test_marker_does_not_disable_an_unrelated_pair(self):
        self.base.initialize()
        datasets, other, head = self.unrelated_owner()
        self.marker(b'{"fixture":"retired"}')
        with pair.locked_pair(datasets):
            view = j._inspect(other, head)
        self.assertEqual(view.head["state"], "ready")

    def test_no_history_tombstone_prevents_later_legacy_initialization(self):
        self.unrelated_owner()  # Valid shared runtime, no invented old history.
        with pair.locked_pair(self.base.datasets, initialize=True):
            self.base.path().mkdir(mode=0o700)
        self.marker(b'{"fixture":"no-legacy"}')
        before = self.base.files()
        with pair.locked_pair(self.base.datasets), self.assertRaises(
            (ValueError, OSError)
        ):
            j._initialize(self.base.binding)
        self.assertEqual(before, self.base.files())
        self.assertEqual({p.name for p in self.base.path().iterdir()}, {MARKER})

    def test_retirement_must_wait_for_the_actual_existing_pair_lease(self):
        self.base.initialize()
        code = """
import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import persistence_pair_lock as pair
pair.backup.RUNTIME_ROOT=Path(sys.argv[2])
try:
    with pair.locked_pair(json.loads(sys.argv[3])):
        print('unexpected admission')
        sys.exit(1)
except ValueError as error:
    if str(error)!='persistence-pair-busy': raise
    print('busy')
"""
        with pair.locked_pair(self.base.datasets):
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    code,
                    str(fixture.ROOT / "ansible"),
                    str(j.backup.RUNTIME_ROOT),
                    json.dumps(self.base.datasets),
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "busy")
        with pair.locked_pair(self.base.datasets):
            pass


if __name__ == "__main__":
    unittest.main()
