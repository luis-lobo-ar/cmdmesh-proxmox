"""Real local flocks; current/native providers are explicitly modeled.

This tests private executor lease machinery, not native admission or dispatch.
"""

import copy
from contextlib import contextmanager
import importlib
import os
import unittest
from unittest import mock

import test_persistence_owner_native_handoff as handoff_fixture
from test_persistence_owner_phase_admission import admission_inputs


class NativeScopeTests(unittest.TestCase):
    def setUp(self):
        self.n = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils."
            "persistence_owner_native_executor"
        )
        self.fixture = handoff_fixture.NativeHandoffTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.handoff = self.fixture.select()
        self.model = self.fixture.case.model
        self.policy = self.model.request["policy"]
        self.root = self.fixture.case.old.base.root
        self.config = self.root / "scope-application.json"
        self.config.write_bytes(b"synthetic private application configuration")
        self.config.chmod(0o600)
        self.config_lock = self.n.runtime.config_lock
        self.native_root = self.root / "scope-native-locks"
        self.native_root.mkdir(mode=0o700)
        self.enterContext(
            mock.patch.object(self.config_lock, "LOCK_ROOT", self.native_root)
        )
        self.enterContext(mock.patch.object(self.config_lock, "ROOT_UID", os.geteuid()))
        for vmid in (self.policy["vmid"], self.policy["retired_guest"]["vmid"]):
            with self.config_lock.read_guest(vmid, initialize=True):
                pass
        with self.n.runtime.pair_lock.locked_pair(
            self.policy["datasets"], initialize=True
        ):
            pass
        original = self.n.observe.locked_config
        self.original_app_lock = original

        @contextmanager
        def app_lock(path, uid, gid):
            with original(self.config, os.geteuid(), os.getegid()) as raw:
                yield raw

        self.enterContext(
            mock.patch.object(self.n.observe, "locked_config", side_effect=app_lock)
        )
        self.phase = "os_quiesced"
        self.events = []
        self.worker_error = False
        self.enterContext(
            mock.patch.object(self.n.current, "_entry_leased", side_effect=self.entry)
        )
        self.enterContext(
            mock.patch.object(
                self.n.current, "_current_frames_leased", side_effect=self.frames
            )
        )
        for name in ("post_guest_action", "post_owner_guest_action"):
            self.enterContext(
                mock.patch.object(
                    self.n.journal.api,
                    name,
                    side_effect=AssertionError("no native request"),
                )
            )

    def entry(self, checkpoint, phase, prior):
        self.assertEqual(phase, self.phase)
        return admission_inputs(self.model, phase)[1]

    @contextmanager
    def frames(self, checkpoint, entry, raw, prior):
        self.assert_outer_locks()
        with self.assertRaises(ValueError):
            self.config_lock.require_write_available(self.policy["vmid"])
        self.events.append(("open", self.phase))
        value = self.n.current._CurrentFrames(
            self.n.state.canonical(admission_inputs(self.model, self.phase)[0]), None
        )
        yield value
        self.events.append(("close", self.phase))
        if self.worker_error:
            raise ValueError("modeled current close failure")
        object.__setattr__(value, "closing_raw", value.initial_raw)

    def assert_outer_locks(self):
        with self.assertRaises(ValueError):
            self.config_lock.require_write_available(
                self.policy["retired_guest"]["vmid"]
            )
        with self.assertRaises(ValueError):
            with self.n.runtime.pair_lock.locked_pair(self.policy["datasets"]):
                self.fail("pair lock released")
        with self.assertRaises(ValueError):
            with self.original_app_lock(self.config, os.geteuid(), os.getegid()):
                self.fail("application lock released")

    def assert_all_released(self):
        for vmid in (self.policy["vmid"], self.policy["retired_guest"]["vmid"]):
            self.config_lock.require_write_available(vmid)
        with self.n.runtime.pair_lock.locked_pair(self.policy["datasets"]):
            pass
        with self.original_app_lock(self.config, os.geteuid(), os.getegid()):
            pass

    def test_invalid_handoff_refuses_before_lease_io(self):
        with mock.patch.object(
            self.n.runtime.pair_lock,
            "locked_pair",
            side_effect=AssertionError("lease IO"),
        ):
            with self.assertRaises(ValueError):
                with self.n._leased(object(), "shutdown", None):
                    self.fail("invalid handoff admitted")

    def test_real_locks_span_separately_closed_running_and_stopped_frames(self):
        before = len(os.listdir("/proc/self/fd"))
        with self.n._leased(self.handoff, "shutdown", None) as scope:
            original = copy.deepcopy(scope.entry)
            with self.n._phase_current(scope) as first:
                self.assertFalse(first.completed)
            self.assertTrue(first.completed)
            with self.n._native_window(scope):
                self.assert_outer_locks()
                self.config_lock.require_write_available(self.policy["vmid"])
                self.assertEqual(self.events[-1], ("close", "os_quiesced"))
                self.phase = "stopped"
            with self.n._phase_current(scope, final=True) as second:
                self.assertFalse(second.completed)
            self.assertTrue(second.completed)
            self.assertEqual(scope.entry, original)
            self.assertEqual(scope.latest.entry["phase"], "stopped")
            self.assertEqual(scope.latest.evidence["phase"], "stopped")
        self.assert_all_released()
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_resume_uses_explicit_prior_and_a_separate_running_frame(self):
        self.phase = "stopped"
        prior = admission_inputs(self.model, "stopped")[2]
        with self.n._leased(self.handoff, "resume", prior) as scope:
            with self.n._phase_current(scope):
                pass
            with self.n._native_window(scope):
                self.phase = "os_quiesced"
            with self.n._phase_current(scope, final=True):
                pass
            self.assertEqual(scope.entry["phase"], "stopped")
            self.assertEqual(scope.latest.evidence["phase"], "os_quiesced")
        self.assert_all_released()

    def test_window_refuses_unclosed_or_absent_before_worker(self):
        with self.n._leased(self.handoff, "shutdown", None) as scope:
            with self.assertRaises(ValueError):
                with self.n._native_window(scope):
                    self.fail("missing current")
            with self.n._phase_current(scope):
                with self.assertRaises(ValueError):
                    with self.n._native_window(scope):
                        self.fail("current context spans native request")
        self.assert_all_released()

    def test_failed_before_worker_poison_blocks_window_and_releases_locks(self):
        with self.assertRaisesRegex(ValueError, "closed-or-poisoned"):
            with self.n._leased(self.handoff, "shutdown", None) as scope:
                self.worker_error = True
                with self.assertRaisesRegex(
                    ValueError, "modeled current close failure"
                ):
                    with self.n._phase_current(scope):
                        pass
                with self.assertRaises(ValueError):
                    with self.n._native_window(scope):
                        self.fail("failed current admitted")
        self.assert_all_released()

    def test_window_is_single_use_and_target_is_reacquired_after_body_error(self):
        with self.assertRaisesRegex(OSError, "modeled lost response"):
            with self.n._leased(self.handoff, "shutdown", None) as scope:
                with self.n._phase_current(scope):
                    pass
                try:
                    with self.n._native_window(scope):
                        raise OSError("modeled lost response")
                finally:
                    with self.assertRaises(ValueError):
                        self.config_lock.require_write_available(self.policy["vmid"])
                    with self.assertRaises(ValueError):
                        with self.n._native_window(scope):
                            self.fail("second native window")
        self.assert_all_released()

    def test_final_current_requires_finished_window_and_rejects_wrong_phase(self):
        with self.assertRaises(AssertionError):
            with self.n._leased(self.handoff, "shutdown", None) as scope:
                with self.assertRaises(ValueError):
                    with self.n._phase_current(scope, final=True):
                        self.fail("premature final worker")
                with self.n._phase_current(scope):
                    pass
                with self.n._native_window(scope):
                    pass
                with self.n._phase_current(scope, final=True):
                    self.fail("wrong phase")
        self.assert_all_released()

    def test_stopped_without_prior_refuses_before_any_lease(self):
        with mock.patch.object(
            self.n.runtime.pair_lock,
            "locked_pair",
            side_effect=AssertionError("lease IO"),
        ):
            with self.assertRaises(ValueError):
                with self.n._leased(self.handoff, "resume", None):
                    self.fail("missing stopped prior")

    def test_failed_exit_uses_only_v4_failure_route_while_pair_is_held(self):
        pending = self.n.journal.Pending(
            self.handoff.journal_binding,
            1,
            "shutdown",
            "1" * 64,
            "2" * 64,
            "3" * 64,
            "4" * 64,
            self.n.journal.Seal(),
            self.n.journal.PhaseChain({}, {}, "5" * 64),
        )
        calls = []

        def failure(actual, code, outcome):
            self.assertIs(actual, pending)
            self.assertEqual(outcome, "unknown")
            with self.assertRaises(ValueError):
                with self.n.runtime.pair_lock.locked_pair(self.policy["datasets"]):
                    self.fail("pair closed before failure record")
            for vmid in (self.policy["vmid"], self.policy["retired_guest"]["vmid"]):
                self.config_lock.require_write_available(vmid)
            calls.append(code)

        with mock.patch.object(
            self.n.journal, "_fail", side_effect=failure
        ), mock.patch.object(
            self.fixture.r.legacy,
            "_fail",
            side_effect=AssertionError("legacy failure route"),
        ):
            with self.assertRaisesRegex(OSError, "modeled transport error"):
                with self.n._leased(self.handoff, "shutdown", None) as scope:
                    scope.pending, scope.outcome = pending, "unknown"
                    raise OSError("modeled transport error")
        self.assertEqual(calls, ["native-transition-unqualified"])
        self.assert_all_released()

    def test_successful_scope_rejects_window_without_final_phase(self):
        with self.assertRaisesRegex(ValueError, "final-phase-required"):
            with self.n._leased(self.handoff, "shutdown", None) as scope:
                with self.n._phase_current(scope):
                    pass
                with self.n._native_window(scope):
                    self.phase = "stopped"
        self.assert_all_released()

    def test_current_input_mutation_refuses_before_window(self):
        with self.assertRaisesRegex(ValueError, "scope-memory"):
            with self.n._leased(self.handoff, "shutdown", None) as scope:
                with self.n._phase_current(scope):
                    pass
                scope.entry["guest"]["runtime"]["uptime"] += 1
                with self.n._native_window(scope):
                    self.fail("mutated original admitted")
        self.assert_all_released()

    def test_pair_close_failure_preserves_primary_error_and_releases_real_fd(self):
        pair_path = (
            self.n.runtime.pair_lock.backup.RUNTIME_ROOT
            / "locks"
            / (self.handoff.selection._private_binding.pair_key + ".json")
        )
        original_close = os.close
        close_faults = []
        armed = False

        def close(fd):
            try:
                is_pair = os.readlink(f"/proc/self/fd/{fd}") == str(pair_path)
            except OSError:
                is_pair = False
            original_close(fd)
            if is_pair and armed:
                close_faults.append(fd)
                raise OSError("modeled pair descriptor close error")

        with mock.patch.object(os, "close", side_effect=close):
            with self.assertRaisesRegex(
                ValueError, "primary operation error"
            ) as caught:
                with self.n._leased(self.handoff, "shutdown", None):
                    armed = True
                    raise ValueError("primary operation error")
        self.assertEqual(len(close_faults), 1)
        self.assertTrue(any("OSError" in note for note in caught.exception.__notes__))
        self.assert_all_released()


if __name__ == "__main__":
    unittest.main()
