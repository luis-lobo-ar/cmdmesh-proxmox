"""Stopped lifecycle inspection borrows the real caller's application lease."""

import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import test_persistence_observe as fixtures
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_observe as observe,
    persistence_state as state,
)


class OwnerCurrentTests(unittest.TestCase):
    def setUp(self):
        scratch = fixtures.ROOT / ".generated"
        scratch.mkdir(mode=0o700, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=scratch, prefix="owner-current-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.database_path = fixtures.ObserverTests.database(self)
        self.config = self.root / "application.json"
        self.raw = b'{"credential":"synthetic-private-value"}'
        self.config.write_bytes(self.raw)
        self.config.chmod(0o600)
        self.p = fixtures.policy()
        self.p["schema_version"] = 3
        self.p["datasets"]["data"]["mountpoint"] = str(self.root)
        self.p["datasets"]["config"]["mountpoint"] = str(self.root)
        self.p["mapping"] = {"offset": 0, "uid": os.getuid(), "gid": os.getgid()}
        self.p["application"] = {
            "instance_id": "a" * 32,
            "config_sha256": state.sha256(self.raw),
        }
        self.guest = fixtures.guest()
        for index, target in (
            (0, "/var/lib/reference-ledger"),
            (1, "/etc/reference-ledger"),
        ):
            self.guest["config"]["mp" + str(index)] = (
                str(self.root) + ",mp=" + target + ",backup=0"
            )
        self.guest.update(
            status="stopped", runtime={"vmid": 101, "pid": 0, "uptime": 0}
        )
        self.host = {"boot_id": "synthetic-epoch"}
        self.request = {"policy": self.p, "backup_store": {}, "source": {}}

        def retained(p):
            state.require(self.config.read_bytes() == self.raw, "test-config-changed")
            return {"invariants": "same"}

        self.guard = SimpleNamespace(
            collect=mock.Mock(side_effect=retained), validate=mock.Mock()
        )
        self.stack = self.enterContext(ExitStack())
        self.stack.enter_context(
            mock.patch.object(
                observe, "guest_facts", side_effect=lambda p: copy.deepcopy(self.guest)
            )
        )
        self.stack.enter_context(
            mock.patch.object(
                observe, "host_facts", side_effect=lambda r: copy.deepcopy(self.host)
            )
        )
        self.stack.enter_context(
            mock.patch.object(observe, "mount_facts", return_value={"id": 42})
        )
        self.stack.enter_context(
            mock.patch.object(
                observe, "native", side_effect=AssertionError("native dispatch")
            )
        )

    def worker(self, raw=None):
        return observe._stopped_source_leased(
            self.request,
            self.guard,
            {"boot_id": "synthetic-epoch"},
            self.raw if raw is None else raw,
        )

    def test_borrowed_application_lock_is_not_reacquired_or_released(self):
        before = {path.name: path.read_bytes() for path in self.root.iterdir()}
        with observe.locked_config(self.config, os.getuid(), os.getgid()) as raw:
            with mock.patch.object(
                observe, "locked_config", side_effect=AssertionError("nested lock")
            ):
                with self.worker(raw) as result:
                    self.assertTrue(result["quiesced"])
                    self.assertEqual(result["application"]["record_count"], 1)
                    self.assertFalse(result["backup_verified"])
                    self.assertNotIn("synthetic-private-value", json.dumps(result))
            with self.assertRaisesRegex(state.PersistenceError, "writer-active"):
                with observe.locked_config(self.config, os.getuid(), os.getgid()):
                    self.fail("worker released caller lease")
        with observe.locked_config(self.config, os.getuid(), os.getgid()):
            pass
        self.assertEqual(
            before, {path.name: path.read_bytes() for path in self.root.iterdir()}
        )

    def test_unsafe_guest_refuses_before_any_retained_read(self):
        original = copy.deepcopy(self.guest)
        cases = [
            {"status": "running", "runtime": {"vmid": 101, "pid": 1234, "uptime": 10}},
            {"runtime": {"vmid": 101, "pid": 1234, "uptime": 0}},
            {"runtime": {"vmid": 101, "pid": 0, "uptime": 1}},
            {"runtime": {"vmid": True, "pid": 0, "uptime": 0}},
            {"config": dict(original["config"], tags="foreign")},
            {"ha_membership": True},
            {"pending": [{"key": "memory", "pending": 1024}]},
        ]
        for change in cases:
            with self.subTest(change=change):
                self.guest = dict(copy.deepcopy(original), **change)
                self.guard.collect.reset_mock()
                with mock.patch.object(
                    observe, "read_database", side_effect=AssertionError("early SQL")
                ), mock.patch.object(
                    observe, "mount_facts", side_effect=AssertionError("early mount")
                ):
                    with self.assertRaises(state.PersistenceError):
                        with self.worker():
                            self.fail("unsafe guest accepted")
                self.guard.collect.assert_not_called()

    def test_wrong_raw_or_policy_refuses_without_data_or_lock_access(self):
        for raw in (b"foreign", "text", None, False):
            with self.subTest(raw=raw), mock.patch.object(
                observe, "read_database", side_effect=AssertionError("early SQL")
            ):
                with self.assertRaises(state.PersistenceError):
                    with observe._stopped_source_leased(
                        self.request, self.guard, self.host, raw
                    ):
                        self.fail("wrong bytes accepted")
        self.p["schema_version"] = 2
        with self.assertRaises(state.PersistenceError):
            with self.worker():
                self.fail("non-owner worker accepted")
        self.guard.collect.assert_not_called()

    def test_late_guest_host_and_mount_drift_refuse(self):
        for kind in ("guest", "host", "mount"):
            with self.subTest(kind=kind), observe.locked_config(
                self.config, os.getuid(), os.getgid()
            ):
                self.guest["status"] = "stopped"
                self.host = {"boot_id": "synthetic-epoch"}
                with self.assertRaisesRegex(state.PersistenceError, "source-changed"):
                    with self.worker():
                        if kind == "guest":
                            self.guest["status"] = "running"
                        elif kind == "host":
                            self.host["boot_id"] = "different-epoch"
                        else:
                            self.stack.enter_context(
                                mock.patch.object(
                                    observe, "mount_facts", return_value={"id": 43}
                                )
                            )

    def test_sql_changes_after_yield_refuse(self):
        with observe.locked_config(self.config, os.getuid(), os.getgid()):
            with self.assertRaisesRegex(state.PersistenceError, "database-changed"):
                with self.worker():
                    with sqlite3.connect(self.database_path) as db:
                        db.execute(
                            "UPDATE entries SET value='changed after observation'"
                        )

    def test_guard_changes_after_yield_refuse(self):
        with observe.locked_config(self.config, os.getuid(), os.getgid()):
            with self.assertRaisesRegex(state.PersistenceError, "source-changed"):
                with self.worker():
                    self.guard.collect.side_effect = None
                    self.guard.collect.return_value = {"invariants": "changed"}

    def test_config_changes_after_yield_refuse(self):
        with self.assertRaisesRegex(state.PersistenceError, "test-config-changed"):
            with observe.locked_config(self.config, os.getuid(), os.getgid()):
                with self.worker():
                    self.config.write_bytes(b'{"credential":"changed"}')

    def test_caller_exception_is_not_converted_to_success(self):
        with observe.locked_config(self.config, os.getuid(), os.getgid()):
            with self.assertRaisesRegex(RuntimeError, "caller failed"):
                with self.worker():
                    raise RuntimeError("caller failed")
            with self.assertRaisesRegex(state.PersistenceError, "writer-active"):
                with observe.locked_config(self.config, os.getuid(), os.getgid()):
                    self.fail("caller exception released caller's lease")

    def test_existing_application_context_still_acquires_its_own_lease(self):
        with observe.locked_application(self.p, self.guard) as app:
            self.assertEqual(app["record_count"], 1)
            with self.assertRaisesRegex(state.PersistenceError, "writer-active"):
                with observe.locked_config(self.config, os.getuid(), os.getgid()):
                    self.fail("public application observer lost its lease")


if __name__ == "__main__":
    unittest.main()
