"""Source qualification is read-only and does not mistake uptime for consistency."""

import copy
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_observe as observe,
)
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_state as state,
)


def policy():
    return {
        "node": "pve-example",
        "vmid": 101,
        "owner_tag": "cmdmesh-own-" + "1" * 32,
        "generation_tag": "cmdmesh-gen-" + "2" * 32,
        "mapping": dict(state.MAPPING),
        "rootfs": {"volume": "local:101/vm-101-disk-0.raw"},
        "datasets": {
            role: {"mountpoint": "/srv/example/" + role} for role in ("data", "config")
        },
    }


def guest():
    p = policy()
    return {
        "config": {
            "unprivileged": 1,
            "onboot": 0,
            "protection": 1,
            "tags": p["owner_tag"] + ";" + p["generation_tag"],
            "rootfs": p["rootfs"]["volume"] + ",size=2G",
            "mp0": "/srv/example/data,mp=/var/lib/reference-ledger,backup=0",
            "mp1": "/srv/example/config,mp=/etc/reference-ledger,backup=0",
        },
        "status": "running",
        "pending": [],
        "ha_membership": False,
    }


class ObserverTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".generated"
        scratch.mkdir(mode=0o700, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=scratch, prefix="observer-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def database(self):
        path = self.root / "ledger.sqlite3"
        with sqlite3.connect(path) as db:
            db.execute(observe.IDENTITY_SQL)
            db.execute(observe.ENTRIES_SQL)
            db.execute("INSERT INTO identity VALUES (?)", ("a" * 32,))
            db.execute(
                "INSERT INTO entries(operation_id,value) VALUES (?,?)",
                ("b" * 32, "a meaningful record"),
            )
        path.chmod(0o600)
        return path

    def test_early_guest_gate_rejects_unsafe_bind_network_owner_and_pending(self):
        observe.validate_guest(policy(), guest())
        reordered = guest()
        reordered["config"][
            "mp0"
        ] = "/srv/example/data,backup=0,mp=/var/lib/reference-ledger"
        observe.validate_guest(policy(), reordered)
        changes = [
            ("tags", "foreign"),
            ("mp0", "/srv/foreign,mp=/var/lib/reference-ledger,backup=0"),
            ("mp2", "/srv/foreign,mp=/foreign"),
            ("net0", "name=eth0,bridge=vmbr0"),
            ("onboot", 1),
            ("unprivileged", True),
            ("hookscript", "local:snippets/hook"),
            ("lock", "backup"),
            ("features", "nesting=1"),
            ("rootfs", "local:102/vm-102-disk-0.raw"),
        ]
        for key, value in changes:
            actual = guest()
            actual["config"][key] = value
            with self.subTest(key=key), self.assertRaises(state.PersistenceError):
                observe.validate_guest(policy(), actual)
        for key, value in (
            ("ha_membership", True),
            ("pending", [{"key": "memory", "pending": 1024}]),
            ("status", "unknown"),
        ):
            actual = guest()
            actual[key] = value
            with self.subTest(key=key), self.assertRaises(state.PersistenceError):
                observe.validate_guest(policy(), actual)

    def test_configuration_lock_is_nonblocking_and_never_rewrites_credentials(self):
        path = self.root / "application.json"
        path.write_bytes(b'{"private":"unchanged"}')
        path.chmod(0o600)
        before = path.read_bytes()
        with observe.locked_config(path, os.getuid(), os.getgid()):
            with self.assertRaisesRegex(state.PersistenceError, "writer-active"):
                with observe.locked_config(path, os.getuid(), os.getgid()):
                    self.fail("competing writer accepted")
        self.assertEqual(before, path.read_bytes())
        with observe.locked_config(path, os.getuid(), os.getgid()):
            pass
        path.chmod(0o644)
        with self.assertRaises(state.PersistenceError):
            with observe.locked_config(path, os.getuid(), os.getgid()):
                self.fail("public credentials accepted")

    def test_database_read_is_meaningful_hashed_and_has_no_values_or_token(self):
        path = self.database()
        before = path.read_bytes()
        result = observe.read_database(path, "a" * 32)
        self.assertEqual(result["record_count"], 1)
        self.assertEqual(result["database_sha256"], state.sha256(before))
        self.assertEqual(
            result["records_sha256"],
            state.sha256(state.canonical([[1, "b" * 32, "a meaningful record"]])),
        )
        self.assertNotIn("meaningful", json.dumps(result))
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), [path.name])

    def test_wrong_identity_schema_empty_or_malformed_records_refuse(self):
        for sql in (
            "UPDATE identity SET instance_id='foreign'",
            "CREATE TABLE foreign_data(value TEXT)",
            "DELETE FROM entries",
            "UPDATE entries SET operation_id='foreign'",
            "UPDATE entries SET value=''",
        ):
            path = self.database()
            with sqlite3.connect(path) as db:
                db.execute(sql)
            with self.subTest(sql=sql), self.assertRaises(state.PersistenceError):
                observe.read_database(path, "a" * 32)
            path.unlink()

    def test_live_journal_or_symlink_database_refuses(self):
        path = self.database()
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(path) + suffix)
            sidecar.touch(mode=0o600)
            with self.assertRaisesRegex(state.PersistenceError, "database-sidecar"):
                observe.read_database(path, "a" * 32)
            sidecar.unlink()
        alias = self.root / "alias"
        alias.symlink_to(path)
        with self.assertRaises(state.PersistenceError):
            observe.read_database(alias, "a" * 32)

    def test_covering_wrong_or_unsafe_nfs_mount_refuses(self):
        expected = {
            "mountpoint": "/srv/backup",
            "source": "192.0.2.20:/backup",
            "file_uid": 99,
            "file_gid": 99,
        }
        row = {
            "target": "/srv/backup",
            "source": expected["source"],
            "fstype": "nfs",
            "fsroot": "/",
            "id": 42,
            "options": "rw,hard,vers=3,proto=tcp,nodev,nosuid,noexec,nolock,local_lock=all",
        }
        observe.validate_mount(expected, {"filesystems": [row]})
        for field, value in (
            ("target", "/srv"),
            ("source", "192.0.2.21:/backup"),
            ("fstype", "ext4"),
            ("fsroot", "/subdir"),
            ("options", "rw,soft,vers=3,proto=tcp"),
        ):
            changed = dict(row, **{field: value})
            with self.subTest(field=field), self.assertRaises(state.PersistenceError):
                observe.validate_mount(expected, {"filesystems": [changed]})
        with self.assertRaises(state.PersistenceError):
            observe.validate_mount(expected, {"filesystems": [row, row]})

    def test_unknown_or_modified_guard_is_never_executed(self):
        marker = self.root / "executed"
        path = self.root / "guard.py"
        path.write_text(
            "from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()"
        )
        path.chmod(0o600)
        for checksum in (
            state.sha256(path.read_bytes()),
            observe.REFERENCE_GUARD_SHA256,
        ):
            with self.assertRaises(state.PersistenceError):
                observe.load_guard({"path": str(path), "sha256": checksum})
        self.assertFalse(marker.exists())

    def source_stubs(self):
        request = {"policy": policy(), "backup_store": {}, "reference_guard": {}}
        guard = mock.Mock()
        guard.collect.return_value = {"config": guest()["config"], "invariants": "same"}
        patches = [
            mock.patch.object(observe, "validate_request"),
            mock.patch.object(observe, "load_guard", return_value=guard),
            mock.patch.object(
                observe, "host_facts", return_value={"host": "qualified"}
            ),
            mock.patch.object(observe, "guest_facts", return_value=guest()),
            mock.patch.object(observe, "mount_facts", return_value={"id": 42}),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return request, guard

    def test_foreign_host_or_guest_refuses_before_application_collection(self):
        request, guard = self.source_stubs()
        with mock.patch.object(
            observe, "host_facts", side_effect=state.PersistenceError("wrong-host")
        ):
            with self.assertRaises(state.PersistenceError):
                observe.observe(request)
        actual = guest()
        actual["config"]["tags"] = "foreign"
        with mock.patch.object(observe, "guest_facts", return_value=actual):
            with self.assertRaises(state.PersistenceError):
                observe.observe(request)
        guard.collect.assert_not_called()

    def test_running_observation_does_not_read_sql_or_claim_quiescence(self):
        request, guard = self.source_stubs()
        with mock.patch.object(observe, "locked_application") as app:
            result = observe.observe(request)
        app.assert_not_called()
        self.assertFalse(result["quiesced"])
        self.assertIsNone(result["application"])
        with self.assertRaisesRegex(state.PersistenceError, "source-not-stopped"):
            with observe.source_state(request, require_stopped=True):
                self.fail("running source accepted for backup")

    def test_post_observation_mount_or_guest_drift_refuses(self):
        request, guard = self.source_stubs()
        with mock.patch.object(
            observe, "mount_facts", side_effect=[{"id": 42}, {"id": 43}]
        ):
            with self.assertRaisesRegex(state.PersistenceError, "source-changed"):
                observe.observe(request)
        with mock.patch.object(
            observe,
            "guest_facts",
            side_effect=[guest(), dict(guest(), status="stopped")],
        ):
            with self.assertRaises(state.PersistenceError):
                observe.observe(request)

    def test_live_database_metadata_is_not_removed_from_returned_facts(self):
        request, guard = self.source_stubs()
        first = {
            "config": guest()["config"],
            "application": {
                "config": {"sha256": "a" * 64},
                "database": {"bytes": 4096},
            },
        }
        after = copy.deepcopy(first)
        after["application"]["database"]["bytes"] = 8192
        guard.collect.side_effect = [first, after]
        result = observe.observe(request)
        self.assertEqual(result["guarded"]["application"]["database"]["bytes"], 4096)
        self.assertFalse(result["quiesced"])

    @unittest.skipUnless(
        os.environ.get("CMDMESH_REFERENCE_GUARD_SOURCE"),
        "provide the pinned public reference guard",
    )
    def test_actual_shared_guard_and_request_contract(self):
        source = Path(os.environ["CMDMESH_REFERENCE_GUARD_SOURCE"]).absolute()
        path = self.root / "guard.py"
        path.write_bytes(source.read_bytes())
        path.chmod(0o600)
        guard = observe.load_guard(
            {"path": str(path), "sha256": observe.REFERENCE_GUARD_SHA256}
        )
        p = json.loads((source.parent / "prestart-manifest.example.json").read_bytes())
        request = {
            "schema_version": 1,
            "source": {
                "selector": {
                    "origin": "example",
                    "node": p["node"],
                    "kind": "proxmox.lxc",
                    "vmid": p["vmid"],
                },
                "host_profile": dict.fromkeys(
                    (
                        "machine_id_sha256",
                        "ca_certificate_sha256",
                        "leaf_certificate_sha256",
                    ),
                    "a" * 64,
                ),
                "owner_tag": p["owner_tag"],
                "generation_tag": p["generation_tag"],
            },
            "policy": p,
            "reference_guard": {
                "path": str(path),
                "sha256": observe.REFERENCE_GUARD_SHA256,
            },
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
        for key in ("schema_version", "source", "policy", "backup_store", "versions"):
            changed = dict(request)
            del changed[key]
            with self.subTest(key=key), self.assertRaises(state.PersistenceError):
                observe.validate_request(changed, guard)
        changed = copy.deepcopy(request)
        changed["source"]["selector"]["vmid"] += 1
        with self.assertRaisesRegex(state.PersistenceError, "policy-mismatch"):
            observe.validate_request(changed, guard)


if __name__ == "__main__":
    unittest.main()
