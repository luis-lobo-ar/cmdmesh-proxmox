"""Export the actual final worker frame under borrowed real local leases."""

from dataclasses import FrozenInstanceError
from contextlib import contextmanager
import os
import unittest
from unittest import mock

import test_persistence_owner_transition as transition_fixture


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class CurrentFramesTests(unittest.TestCase):
    def setUp(self):
        # Preserve the actual legacy entry point before the fixture models it.
        from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
            persistence_owner_current,
        )

        self.legacy_worker = persistence_owner_current._current_leased
        self.case = transition_fixture.OwnerTransitionTests("runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.c = self.case.sdk.current
        self.state = self.c.state
        self.events = []
        self.calls = 0
        self.collected = []
        self.closing_error = False
        self.fast_error = False
        self.invalid_closing = False
        raw = self.case.config.read_bytes()
        digest = self.state.sha256(raw)
        model = self.case.model
        model.request["policy"]["application"]["config_sha256"] = digest
        model.frame["retained"]["application"]["config"]["sha256"] = digest
        model.frame["application"]["config_sha256"] = digest
        for path, checksum in self.c.runtime.reference_paths(model.request).items():
            model.frame["reference"]["files"][path]["sha256"] = checksum
        for key in ("prepared", "completion"):
            self.case.checkpoint[key + "_sha256"] = self.state.sha256(
                self.state.canonical(self.case.checkpoint[key])
            )
        self.enterContext(
            mock.patch.object(
                self.c.runtime, "_collect_leased", side_effect=self.collect
            )
        )
        self.enterContext(
            mock.patch.object(self.c, "_fast_close", side_effect=self.fast)
        )
        self.enterContext(
            mock.patch.object(self.c.observe, "load_guard", return_value=model.guard)
        )

    def assert_leases(self):
        self.case.assert_outer_leases()
        self.assertIn(self.case.model.request["policy"]["vmid"], self.case.native_locks)
        with self.assertRaises(ValueError):
            self.case.native_writer(self.case.model.request["policy"]["vmid"])

    def collect(self, *args):
        self.assert_leases()
        self.calls += 1
        self.events.append("worker-" + str(self.calls))
        if self.calls == 2 and self.closing_error:
            raise ValueError("final native provider failed")
        frame = self.case.model.evidence()["observation"]
        frame["guest"]["runtime"]["uptime"] += self.calls
        if self.calls == 2 and self.invalid_closing:
            frame["application"]["record_count"] += 1
        self.collected.append(frame)
        return frame

    def fast(self, *args):
        self.assert_leases()
        self.events.append("fast-close")
        if self.fast_error:
            raise ValueError("final metadata changed")

    def scope(self):
        return self.case.sdk._leased(self.case.checkpoint, self.case.phase, None)

    def worker(self, scope):
        return self.c._current_frames_leased(
            self.case.checkpoint, scope.entry, scope.raw
        )

    def decode(self, raw):
        return self.c.observe.decode(raw)

    def test_distinct_actual_final_frame_is_published_after_fast_closure(self):
        with self.scope() as scope:
            with self.worker(scope) as frames:
                self.assertIsNone(frames.closing_raw)
                self.assertIs(frames.completed, False)
                self.events.append("slow-caller-work")
                first = self.decode(frames.initial_raw)
            self.assert_leases()
            self.assertIs(frames.completed, True)
            final = self.decode(frames.closing_raw)
            self.assertEqual(
                final["observation"]["guest"]["runtime"]["uptime"],
                first["observation"]["guest"]["runtime"]["uptime"] + 1,
            )
            self.assertEqual(
                self.events, ["worker-1", "slow-caller-work", "worker-2", "fast-close"]
            )
        self.assertEqual(self.case.native_locks, set())
        self.assertFalse(self.case.app_held)

    def test_canonical_bytes_and_frozen_holder_have_no_mutable_frame_alias(self):
        with self.scope() as scope:
            with self.worker(scope) as frames:
                decoded = self.decode(frames.initial_raw)
                decoded["observation"]["application"]["record_count"] = 900
                self.assertNotEqual(self.decode(frames.initial_raw), decoded)
                with self.assertRaises(FrozenInstanceError):
                    frames.closing_raw = b"forged"
            for raw in (frames.initial_raw, frames.closing_raw):
                self.assertIs(type(raw), bytes)
                self.assertEqual(self.state.canonical(self.decode(raw)), raw)

    def test_final_worker_failure_cannot_publish_completed_capture(self):
        self.closing_error = True
        with self.scope() as scope:
            with self.assertRaisesRegex(ValueError, "final native provider"):
                with self.worker(scope) as frames:
                    pass
            self.assertIsNone(frames.closing_raw)
            self.assertIs(frames.completed, False)
            self.assertNotIn("fast-close", self.events)

    def test_intrinsically_invalid_final_app_cannot_publish_capture(self):
        self.invalid_closing = True
        with self.scope() as scope:
            with self.assertRaises(ValueError):
                with self.worker(scope) as frames:
                    pass
            self.assertIsNone(frames.closing_raw)
            self.assertIs(frames.completed, False)

    def test_fast_closure_failure_cannot_publish_completed_capture(self):
        self.fast_error = True
        with self.scope() as scope:
            with self.assertRaisesRegex(ValueError, "final metadata"):
                with self.worker(scope) as frames:
                    pass
            self.assertEqual(self.events, ["worker-1", "worker-2", "fast-close"])
            self.assertIsNone(frames.closing_raw)
            self.assertIs(frames.completed, False)

    def test_caller_body_failure_does_not_run_or_export_final_worker(self):
        with self.scope() as scope:
            with self.assertRaisesRegex(ValueError, "caller refused"):
                with self.worker(scope) as frames:
                    raise ValueError("caller refused")
            self.assertEqual(self.calls, 1)
            self.assertIsNone(frames.closing_raw)
            self.assertIs(frames.completed, False)

    def test_existing_entry_point_still_yields_initial_independent_dictionary(self):
        with self.scope() as scope:
            with self.legacy_worker(
                self.case.checkpoint, scope.entry, scope.raw
            ) as first:
                first["observation"]["application"]["record_count"] = 900
            self.assertEqual(first["observation"]["application"]["record_count"], 900)
            self.assertEqual(self.calls, 2)
            self.assertEqual(self.case.model.frame["application"]["record_count"], 2)

    def test_final_entry_failure_prevents_closing_worker_and_capture(self):
        with self.scope() as scope:
            with self.assertRaisesRegex(ValueError, "late entry"):
                with self.worker(scope) as frames:
                    self.c._entry_leased.side_effect = ValueError("late entry")
            self.assertEqual(self.calls, 1)
            self.assertIsNone(frames.closing_raw)
            self.assertIs(frames.completed, False)

    def test_late_capture_slot_corruption_refuses_instead_of_publishing(self):
        for field, replacement in (("initial_raw", b"{}"), ("closing_raw", b"{}")):
            with self.subTest(field=field), self.scope() as scope:
                self.calls = 0
                with self.assertRaises(ValueError):
                    with self.worker(scope) as frames:
                        # Model a bad internal caller deliberately bypassing frozen setattr.
                        object.__setattr__(frames, field, replacement)

    def test_final_fast_closure_cannot_rewrite_capture_or_hide_failure(self):
        with self.scope() as scope:
            with self.assertRaises(ValueError):
                with self.worker(scope) as frames:
                    original = self.c._fast_close.side_effect

                    def corrupt(*args):
                        original(*args)
                        object.__setattr__(frames, "initial_raw", b"{}")

                    self.c._fast_close.side_effect = corrupt

    def test_closing_frame_memory_change_during_fast_closure_refuses(self):
        with self.scope() as scope:
            with self.assertRaises(ValueError):
                with self.worker(scope) as frames:
                    original = self.c._fast_close.side_effect

                    def corrupt(*args):
                        original(*args)
                        args[3]["observation"]["application"]["record_count"] += 1

                    self.c._fast_close.side_effect = corrupt
            self.assertIsNone(frames.closing_raw)
            self.assertIs(frames.completed, False)

    def test_stopped_capture_exports_two_equal_fresh_workers_under_same_leases(self):
        self.case.phase = "stopped"

        @contextmanager
        def stopped(*args):
            self.assert_leases()
            self.calls += 1
            self.events.append("worker-" + str(self.calls))
            yield self.case.model.evidence("stopped")["observation"]
            self.events.append("stopped-worker-close")

        with mock.patch.object(
            self.c.observe, "_stopped_source_leased", side_effect=stopped
        ):
            with self.scope() as scope:
                with self.worker(scope) as frames:
                    self.events.append("slow-caller-work")
                self.assert_leases()
                self.assertIs(frames.completed, True)
                self.assertEqual(frames.initial_raw, frames.closing_raw)
        self.assertEqual(
            self.events,
            [
                "worker-1",
                "stopped-worker-close",
                "slow-caller-work",
                "worker-2",
                "stopped-worker-close",
                "fast-close",
            ],
        )

    def test_mutated_internal_initial_frame_cannot_mask_exported_uptime_regression(
        self,
    ):
        original = self.c.runtime._collect_leased.side_effect

        def mutate(*args):
            frame = original(*args)
            if self.calls == 1:
                frame["guest"]["runtime"]["uptime"] = 1000
            else:
                self.collected[0]["guest"]["runtime"]["uptime"] = 100
                frame["guest"]["runtime"]["uptime"] = 101
            return frame

        self.c.runtime._collect_leased.side_effect = mutate
        with self.scope() as scope:
            with self.assertRaises(ValueError):
                with self.worker(scope) as frames:
                    self.assertEqual(
                        self.decode(frames.initial_raw)["observation"]["guest"][
                            "runtime"
                        ]["uptime"],
                        1000,
                    )
            self.assertIsNone(frames.closing_raw)
            self.assertIs(frames.completed, False)

    def test_initial_frame_memory_drift_during_final_fast_closure_refuses(self):
        with self.scope() as scope:
            with self.assertRaises(ValueError):
                with self.worker(scope) as frames:
                    original = self.c._fast_close.side_effect

                    def corrupt(*args):
                        original(*args)
                        self.collected[0]["guest"]["runtime"]["uptime"] += 1

                    self.c._fast_close.side_effect = corrupt
            self.assertIsNone(frames.closing_raw)
            self.assertIs(frames.completed, False)


if __name__ == "__main__":
    unittest.main()
