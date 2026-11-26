"""Actual local process/FD mutex tests; no managed runtime or native permission."""

import copy
from contextlib import contextmanager
import multiprocessing
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_bootstrap as bootstrap,
)


@contextmanager
def fixture_scope(root):
    root = Path(root)
    with mock.patch.object(
        bootstrap.profile, "RUNTIME_ROOT", root / "handoff"
    ), mock.patch.object(
        bootstrap.r, "RUNTIME_ROOT", root / "handoff"
    ), mock.patch.object(
        bootstrap.r.legacy, "RUNTIME_ROOT", root / "legacy"
    ), mock.patch.object(
        bootstrap.r.legacy, "ROOT_UID", os.getuid()
    ), mock.patch.object(
        bootstrap.attempt, "_WALK_ROOT", root
    ):
        yield


def other_owner(root, connection, initialize, gate=None, hold=False):
    with fixture_scope(root):
        if gate is not None:
            gate.wait(5)
        try:
            with bootstrap.locked_runtime_bootstrap(initialize=initialize):
                if hold:
                    connection.send("entered")
                    connection.recv()
            connection.send("closed" if hold else "acquired")
        except ValueError as error:
            connection.send("busy" if "bootstrap-busy" in str(error) else str(error))
        finally:
            connection.close()


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cmdmesh-owner-bootstrap-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.enterContext(fixture_scope(self.root))
        self.path = self.root / bootstrap.LOCK_NAME

    def lock(self, initialize=False):
        return bootstrap.locked_runtime_bootstrap(initialize=initialize)

    def initialize(self):
        with self.lock(True):
            pass
        return self.path.read_bytes()

    def process(self, initialize=False, gate=None, hold=False):
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe()
        process = context.Process(
            target=other_owner, args=(str(self.root), child, initialize, gate, hold)
        )
        process.start()
        child.close()

        def cleanup():
            if process.is_alive():
                process.terminate()
                process.join(3)
            if process.is_alive():
                process.kill()
                process.join(3)
            parent.close()

        self.addCleanup(cleanup)
        return process, parent

    def test_missing_lock_never_initializes_implicitly(self):
        with self.assertRaises(ValueError):
            with self.lock():
                pass
        self.assertEqual(list(self.root.iterdir()), [])
        for value in (1, "true", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                with bootstrap.locked_runtime_bootstrap(initialize=value):
                    pass

    def test_explicit_initialization_only_creates_owner_neutral_mutex(self):
        raw = self.initialize()
        body = bootstrap.r.observe.decode(raw)
        self.assertEqual(set(self.root.iterdir()), {self.path})
        self.assertEqual(body["runtime_path"], str(self.root / "handoff"))
        self.assertEqual(body["publication_protocol"], bootstrap.profile.PROTOCOL)
        self.assertNotIn("pair_key", body)
        before = bootstrap.r.observe.stable(self.path.stat())
        with self.lock(True):
            pass
        self.assertEqual(self.path.read_bytes(), raw)
        self.assertEqual(bootstrap.r.observe.stable(self.path.stat()), before)

    def test_other_process_refuses_then_acquires_after_release(self):
        self.initialize()
        with self.lock():
            process, connection = self.process()
            self.assertTrue(connection.poll(5))
            self.assertEqual(connection.recv(), "busy")
            process.join(3)
            self.assertEqual(process.exitcode, 0)
        process, connection = self.process()
        self.assertTrue(connection.poll(5))
        self.assertEqual(connection.recv(), "acquired")
        process.join(3)
        self.assertEqual(process.exitcode, 0)

    def test_two_initializers_never_enter_together(self):
        context = multiprocessing.get_context("spawn")
        gate = context.Event()
        actors = [self.process(True, gate, True) for _ in range(2)]
        gate.set()
        outcomes = []
        for process, connection in actors:
            self.assertTrue(connection.poll(5))
            outcomes.append(connection.recv())
        self.assertLessEqual(outcomes.count("entered"), 1)
        for result in outcomes:
            self.assertIn(
                result,
                ("entered", "busy", "persistence-owner-retirement-attempt-event"),
            )
        for (process, connection), result in zip(actors, outcomes):
            if result == "entered":
                connection.send("release")
                self.assertTrue(connection.poll(5))
                self.assertIn(
                    connection.recv(),
                    ("closed", "persistence-owner-retirement-attempt-event"),
                )
            process.join(3)
            self.assertEqual(process.exitcode, 0)
        with self.lock():
            pass
        self.assertFalse((self.root / "handoff").exists())

    def test_process_death_releases_same_persistent_mutex(self):
        raw = self.initialize()
        before = bootstrap.r.observe.stable(self.path.stat())
        process, connection = self.process(hold=True)
        self.assertTrue(connection.poll(5))
        self.assertEqual(connection.recv(), "entered")
        with self.assertRaisesRegex(ValueError, "bootstrap-busy"):
            with self.lock():
                pass
        process.terminate()
        process.join(3)
        self.assertFalse(process.is_alive())
        with self.lock():
            pass
        self.assertEqual(self.path.read_bytes(), raw)
        self.assertEqual(bootstrap.r.observe.stable(self.path.stat()), before)

    def test_nested_independent_descriptor_is_busy(self):
        self.initialize()
        with self.lock():
            with self.assertRaisesRegex(ValueError, "bootstrap-busy"):
                with self.lock():
                    pass
        with self.lock():
            pass

    def test_partial_foreign_or_public_records_are_preserved(self):
        canonical = self.initialize()
        for raw in (b"", b'{"partial":', b"foreign"):
            self.path.write_bytes(raw)
            before = self.path.read_bytes()
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                with self.lock(True):
                    pass
            self.assertEqual(self.path.read_bytes(), before)
        self.path.write_bytes(canonical)
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            with self.lock(True):
                pass
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o644)

    def test_symlink_hardlink_and_special_files_are_never_read_or_replaced(self):
        canonical = self.initialize()
        self.path.unlink()
        outside = self.root / "outside"
        outside.write_bytes(canonical)
        outside.chmod(0o600)
        self.path.symlink_to(outside)
        with self.assertRaises(ValueError):
            with self.lock(True):
                pass
        self.assertTrue(self.path.is_symlink())
        self.path.unlink()
        os.link(outside, self.path)
        with self.assertRaises(ValueError):
            with self.lock(True):
                pass
        self.assertEqual(outside.stat().st_nlink, 2)
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(ValueError):
            with self.lock(True):
                pass
        self.assertEqual(outside.read_bytes(), canonical)

    def test_parent_must_be_private_before_initialization(self):
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            with self.lock(True):
                pass
        self.assertFalse(self.path.exists())

    def test_replacement_or_same_byte_write_suppresses_success(self):
        raw = self.initialize()
        with self.assertRaises(ValueError):
            with self.lock():
                self.path.unlink()
                self.path.write_bytes(raw)
                self.path.chmod(0o600)
        with self.assertRaises(ValueError):
            with self.lock():
                self.path.write_bytes(raw)

    def test_same_byte_event_refuses_with_metadata_closer_explicitly_modeled(self):
        raw = self.initialize()
        # Isolate actual inotify coverage; this is not metadata-close acceptance.
        with mock.patch.object(
            bootstrap.attempt._Reader, "close_named", return_value=None
        ):
            with self.assertRaisesRegex(ValueError, "attempt-event"):
                with self.lock():
                    self.path.write_bytes(raw)

    def test_profile_drift_cannot_return_a_positive_context(self):
        self.initialize()
        with mock.patch.object(
            bootstrap.profile, "RUNTIME", copy.deepcopy(bootstrap.profile.RUNTIME)
        ):
            with self.assertRaises(ValueError):
                with self.lock():
                    bootstrap.profile.RUNTIME["target_schema"] = 999

    def test_release_failure_refuses_and_preserves_primary_error(self):
        self.initialize()
        release = bootstrap.attempt._Reader.release
        before = len(os.listdir("/proc/self/fd"))

        def fail(reader):
            release(reader)
            raise OSError("release failed")

        with mock.patch.object(
            bootstrap.attempt._Reader, "release", side_effect=fail, autospec=True
        ):
            with self.assertRaisesRegex(OSError, "release failed"):
                with self.lock():
                    pass
            with self.assertRaisesRegex(RuntimeError, "body failed") as caught:
                with self.lock():
                    raise RuntimeError("body failed")
        self.assertTrue(
            any("secondary bootstrap" in n for n in caught.exception.__notes__)
        )
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)
        with self.lock():
            pass

    def test_body_failure_releases_lease_without_runtime_creation(self):
        self.initialize()
        with self.assertRaisesRegex(RuntimeError, "body failed"):
            with self.lock():
                raise RuntimeError("body failed")
        with self.lock():
            pass
        self.assertEqual(set(self.root.iterdir()), {self.path})

    def test_shared_parent_may_gain_the_actual_runtime_under_the_mutex(self):
        with self.lock(True):
            runtime = bootstrap.profile.RUNTIME_ROOT
            runtime.mkdir(mode=0o700)
            raw = bootstrap.r.state.canonical(bootstrap.profile.RUNTIME)
            bootstrap.atomic.publish_private(
                runtime / "runtime.json", raw, protocol=bootstrap.profile.PROTOCOL
            )
        with self.lock():
            self.assertEqual((runtime / "runtime.json").read_bytes(), raw)
        self.assertEqual(set(self.root.iterdir()), {self.path, runtime})

    def test_failed_initializer_preserves_complete_unaccepted_mutex_candidate(self):
        content = bootstrap.atomic._content

        def fail_after_link(fd, raw):
            result = content(fd, raw)
            if os.fstat(fd).st_nlink == 1:
                raise OSError("final proof failed")
            return result

        entered = False
        with mock.patch.object(
            bootstrap.atomic, "_content", side_effect=fail_after_link
        ):
            with self.assertRaisesRegex(OSError, "final proof failed"):
                with self.lock(True):
                    entered = True
        self.assertFalse(entered)
        self.assertTrue(self.path.exists())
        self.assertFalse(bootstrap.profile.RUNTIME_ROOT.exists())
        # A fresh mutex lease does not assert success of its old initializer.
        with self.lock():
            pass


if __name__ == "__main__":
    unittest.main()
