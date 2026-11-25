"""A successor source requires its owner guard and a stopped-only collector."""

from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_observe as observe,
    persistence_config_lock as config_lock,
    persistence_state as state,
)
import test_persistence_observe as fixtures

HANDOFF_SHA = "68a40e2c9f696d5535085c94d4f55bc93d5b03644dfcbe254e0b5629403eb270"


def owner_guest(stopped=True):
    return {
        **fixtures.guest(),
        "status": "stopped" if stopped else "running",
        "runtime": {
            "vmid": 101,
            "pid": 0 if stopped else 123,
            "uptime": 0 if stopped else 1,
        },
    }


class OwnerObserverTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ObserverTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        locks = self.fixture.root / "locks"
        locks.mkdir(mode=0o700)
        (locks / "pve-config-101.lock").touch(mode=0o600)
        for patch in (
            mock.patch.object(config_lock, "LOCK_ROOT", locks),
            mock.patch.object(config_lock, "ROOT_UID", os.geteuid()),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def test_running_owner_refuses_before_strict_collection_or_application_reads(self):
        request, guard = self.fixture.source_stubs()
        request["policy"]["schema_version"] = 3
        with mock.patch.object(observe, "locked_application") as app, mock.patch.object(
            observe, "read_database"
        ) as database, mock.patch.object(
            observe, "guest_facts", return_value=owner_guest(False)
        ):
            for stopped in (False, True):
                with self.subTest(require_stopped=stopped), self.assertRaises(
                    state.PersistenceError
                ):
                    with observe.source_state(request, require_stopped=stopped):
                        self.fail("running owner accepted by stopped collector")
        guard.collect.assert_not_called()
        observe.mount_facts.assert_not_called()
        app.assert_not_called()
        database.assert_not_called()

    def test_stopped_owner_preserves_owner_facts_and_consistent_application_scope(self):
        request, guard = self.fixture.source_stubs()
        request["policy"]["schema_version"] = 3
        current = owner_guest()
        guard.collect.return_value = {
            "ownership": {"active": {"vmid": 101}},
            "invariants": "same",
        }
        guarded = guard.collect.return_value

        def collect(*args):
            with self.assertRaises(config_lock.ConfigLockError):
                config_lock.require_write_available(101)
            return guarded

        guard.collect.side_effect = collect
        application = {"instance_id": "a" * 32, "record_count": 1}
        events = []

        @contextmanager
        def app(*args):
            with self.assertRaises(config_lock.ConfigLockError):
                config_lock.require_write_available(101)
            events.append("locked")
            yield application
            events.append("closed")

        with mock.patch.object(
            observe, "guest_facts", return_value=current
        ), mock.patch.object(observe, "locked_application", side_effect=app):
            result = observe.observe(request)
        self.assertEqual(events, ["locked", "closed"])
        self.assertTrue(result["quiesced"])
        self.assertEqual(result["application"], application)
        self.assertEqual(result["guarded"]["ownership"]["active"]["vmid"], 101)
        self.assertFalse(result["backup_verified"])
        config_lock.require_write_available(101)

    def test_owner_refusal_is_not_swallowed_or_allowed_to_read_sql(self):
        request, guard = self.fixture.source_stubs()
        request["policy"]["schema_version"] = 3
        guard.collect.side_effect = state.PersistenceError("persistence-owner-mismatch")
        with mock.patch.object(
            observe,
            "guest_facts",
            return_value=owner_guest(),
        ), mock.patch.object(observe, "locked_application") as app:
            with self.assertRaisesRegex(state.PersistenceError, "owner-mismatch"):
                observe.observe(request)
        app.assert_not_called()

    def test_changed_guard_reference_at_close_cannot_return_source_success(self):
        request, guard = self.fixture.source_stubs()
        with mock.patch.object(
            observe,
            "load_guard",
            side_effect=[guard, state.PersistenceError("persistence-guard-changed")],
        ):
            with self.assertRaisesRegex(state.PersistenceError, "guard-changed"):
                observe.observe(request)

    def test_reference_recheck_follows_sql_closure_under_owner_lease(self):
        request, guard = self.fixture.source_stubs()
        request["policy"]["schema_version"] = 3
        events = []

        @contextmanager
        def app(*args):
            events.append("locked")
            yield {"record_count": 1}
            events.append("closed")

        def loaded(reference):
            if events:
                self.assertEqual(events, ["locked", "closed"])
                with self.assertRaises(config_lock.ConfigLockError):
                    config_lock.require_write_available(101)
                events.append("reference-rechecked")
            return guard

        with mock.patch.object(
            observe,
            "guest_facts",
            return_value=owner_guest(),
        ), mock.patch.object(
            observe, "locked_application", side_effect=app
        ), mock.patch.object(
            observe, "load_guard", side_effect=loaded
        ):
            observe.observe(request)
        self.assertEqual(events, ["locked", "closed", "reference-rechecked"])

    def test_owner_change_during_stopped_observation_refuses_success(self):
        request, guard = self.fixture.source_stubs()
        request["policy"]["schema_version"] = 3
        guard.collect.side_effect = [{"owner": 101}, {"owner": 100}]
        with mock.patch.object(
            observe,
            "guest_facts",
            return_value=owner_guest(),
        ), mock.patch.object(observe, "locked_application"):
            with self.assertRaisesRegex(state.PersistenceError, "source-changed"):
                observe.observe(request)

    def test_stopped_owner_requires_zero_typed_runtime_and_current_identity(self):
        request, guard = self.fixture.source_stubs()
        request["policy"]["schema_version"] = 3
        original = owner_guest()
        observe.validate_guest(request["policy"], original)
        for field, value in (
            ("pid", 123),
            ("pid", False),
            ("uptime", 1),
            ("uptime", False),
            ("vmid", 100),
            ("vmid", True),
        ):
            current = copy.deepcopy(original)
            current["runtime"][field] = value
            with self.subTest(field=field, value=value), mock.patch.object(
                observe, "guest_facts", return_value=current
            ), mock.patch.object(observe, "locked_application") as app:
                with self.assertRaises(state.PersistenceError):
                    observe.observe(request)
                app.assert_not_called()
        guard.collect.assert_not_called()

    def test_guest_reader_retains_owner_runtime_instead_of_only_status_text(self):
        policy = fixtures.policy()
        policy["schema_version"] = 3
        raw = {"vmid": 101, "status": "stopped", "pid": 0, "uptime": 0}
        replies = [fixtures.guest()["config"], raw, [], []]
        with mock.patch.object(
            observe,
            "native",
            side_effect=[json.dumps(value).encode() for value in replies],
        ):
            result = observe.guest_facts(policy)
        self.assertEqual(result.get("runtime"), {"vmid": 101, "pid": 0, "uptime": 0})

    @unittest.skipUnless(
        os.environ.get("CMDMESH_HANDOFF_GUARD_SOURCE"),
        "provide the pinned public owner guard",
    )
    def test_actual_owner_guard_load_and_request_contract(self):
        source = Path(os.environ["CMDMESH_HANDOFF_GUARD_SOURCE"]).absolute()
        path = self.fixture.root / "guard3.py"
        path.write_bytes(source.read_bytes())
        path.chmod(0o600)
        guard = observe.load_guard({"path": str(path), "sha256": HANDOFF_SHA})
        policy = json.loads(
            (source.parent / "handoff-manifest.example.json").read_bytes()
        )
        request = {
            "schema_version": 1,
            "source": {
                "selector": {
                    "origin": "example",
                    "node": policy["node"],
                    "kind": "proxmox.lxc",
                    "vmid": policy["vmid"],
                },
                "host_profile": dict.fromkeys(
                    (
                        "machine_id_sha256",
                        "ca_certificate_sha256",
                        "leaf_certificate_sha256",
                    ),
                    "a" * 64,
                ),
                "owner_tag": policy["owner_tag"],
                "generation_tag": policy["generation_tag"],
            },
            "policy": policy,
            "reference_guard": {"path": str(path), "sha256": HANDOFF_SHA},
            "backup_store": {
                "mountpoint": "/srv/backup",
                "source": "192.0.2.20:/backup",
                "file_uid": 99,
                "file_gid": 99,
            },
            "versions": {
                "pve-manager": "9.2.21",
                "pve-container": "6.1.14",
                "zfsutils-linux": "2.4.0-pve1",
            },
        }
        observe.validate_request(request, guard)
        changed = copy.deepcopy(request)
        changed["source"]["selector"]["vmid"] = policy["retired_guest"]["vmid"]
        with self.assertRaises(state.PersistenceError):
            observe.validate_request(changed, guard)
        changed = copy.deepcopy(request)
        changed["policy"]["schema_version"] = 2
        with self.assertRaises(ValueError):
            observe.validate_request(changed, guard)
        path.write_bytes(b"raise RuntimeError('must never execute changed code')\n")
        with self.assertRaisesRegex(state.PersistenceError, "guard-changed"):
            observe.load_guard(request["reference_guard"])
