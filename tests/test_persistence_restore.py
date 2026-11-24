"""Restore state transitions with real files and a synthetic ZFS executable.

These tests qualify the boundary, not native ZFS or recovered applications.
"""

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_restore as restore,
    persistence_state as state,
)
from test_persistence_state import manifest


class RestoreTests(unittest.TestCase):
    def setUp(self):
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(
            dir=ROOT / ".generated", prefix="restore-"
        )
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.model = manifest()
        self.manifest_raw = state.canonical(self.model)
        self.target = {
            "origin": "recovery-example",
            "node": "node-b",
            "host_profile": {k: "e" * 64 for k in self.model["source"]["host_profile"]},
            "versions": {
                "pve-manager": "9.2.1",
                "pve-container": "6.1.1",
                "zfsutils-linux": "2.4.0",
            },
            "pool": {"name": "recovery", "guid": "10"},
            "parent": {"name": "recovery/owned", "guid": "11"},
            "owner_tag": "cmdmesh-own-" + "6" * 32,
        }
        self.zfs = self.root / "zfs"
        self.zfs.write_text("#!" + sys.executable + "\n" + """import json,pathlib,sys
root=pathlib.Path(__file__).parent;a=sys.argv[1:]
assert a[0]=='receive' and a[1]=='-u'
assert not any(flag in a for flag in ('-F','-d','-e','-s','-A','-M'))
options=dict(a[i+1].split('=',1) for i in range(2,len(a)-1,2))
assert options['canmount']=='off' and options['mountpoint']=='none' and options['readonly']=='on'
assert all(options[k]=='off' for k in ('exec','devices','setuid','sharenfs','sharesmb'))
body=sys.stdin.buffer.read()
with (root/'events').open('a') as out:out.write(json.dumps({'argv':a,'body':body.decode()})+'\\n')
if (root/'fail').exists():sys.exit(23)
if (root/'delay').exists():
 import time;time.sleep(30)
""")
        self.zfs.chmod(0o700)
        self.request = {
            "schema_version": 1,
            "operation_id": "f" * 64,
            "manifest_sha256": state.sha256(self.manifest_raw),
            "target": self.target,
            "tools": {
                name: {
                    "path": str(self.zfs),
                    "sha256": state.sha256(self.zfs.read_bytes()),
                }
                for name in ("zfs", "zpool")
            },
            "streams": {},
        }
        for role in ("data", "config"):
            path = self.root / (role + ".zfs")
            path.write_bytes(("authenticated synthetic stream:" + role).encode())
            path.chmod(0o600)
            self.request["streams"][role] = {
                "path": str(path),
                "bytes": path.stat().st_size,
                "sha256": state.sha256(path.read_bytes()),
            }
        self.facts = {
            "host": {"boot_id": "same"},
            "pool": {"guid": "10"},
            "parent": {"guid": "11"},
            "received": {},
        }
        self.received = []

        def inspect(request, model, roles=()):
            self.assertEqual(request["target"], self.target)
            events = (
                (self.root / "events").read_text().splitlines()
                if (self.root / "events").exists()
                else []
            )
            self.assertEqual(len(events), len(roles))
            result = copy.deepcopy(self.facts)
            for role in roles:
                result["received"][role] = {
                    "snapshot_guid": model["datasets"][role]["snapshot_guid"]
                }
            self.received.append(tuple(roles))
            return result

        for patch in (
            mock.patch.object(restore, "RUNTIME_ROOT", self.root / "managed/restore"),
            mock.patch.object(
                restore,
                "TOOL_PATHS",
                {name: str(self.zfs) for name in ("zfs", "zpool")},
            ),
            mock.patch.object(restore, "inspect_target", side_effect=inspect),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def prepared(self):
        prepared = restore.prepare_restore(self.request, self.manifest_raw)
        raw = state.canonical(prepared)
        return raw, state.sha256(raw)

    def test_preparation_is_readonly_and_binds_exact_files_target_and_manifest(self):
        raw, trusted = self.prepared()
        value = restore.load_prepared(raw, trusted)
        self.assertEqual(value["manifest"], self.model)
        self.assertEqual(value["request"], self.request)
        self.assertFalse(restore.RUNTIME_ROOT.exists())
        self.assertFalse((self.root / "events").exists())
        with self.assertRaises(state.PersistenceError):
            restore.load_prepared(raw, "0" * 64)

    def test_one_receive_per_role_preserves_inputs_and_never_claims_app_recovery(self):
        raw, trusted = self.prepared()
        result = restore.execute_restore(raw, trusted)
        self.assertTrue(result["received_verified"])
        self.assertFalse(result["restore_verified"])
        self.assertFalse(result["application_verified"])
        self.assertFalse(result["source_unavailable_verified"])
        events = [
            json.loads(row) for row in (self.root / "events").read_text().splitlines()
        ]
        self.assertEqual(
            [event["argv"][-1] for event in events],
            ["recovery/owned/data", "recovery/owned/config"],
        )
        for event, role in zip(events, ("data", "config")):
            self.assertEqual(
                event["body"].encode(),
                Path(self.request["streams"][role]["path"]).read_bytes(),
            )
        self.assertEqual(set(result["received"]), {"data", "config"})
        self.assertTrue(any(restore.RUNTIME_ROOT.rglob("complete.json")))

    def test_changed_bytes_permissions_symlinks_or_shared_file_refuse_before_claim(
        self,
    ):
        raw, trusted = self.prepared()
        path = Path(self.request["streams"]["data"]["path"])
        original = path.read_bytes()
        path.write_bytes(b"changed")
        with self.assertRaises(state.PersistenceError):
            restore.execute_restore(raw, trusted)
        path.write_bytes(original)
        path.chmod(0o644)
        with self.assertRaises(state.PersistenceError):
            restore.execute_restore(raw, trusted)
        path.chmod(0o600)
        alias = path.with_suffix(".alias")
        os.link(path, alias)
        with self.assertRaises(state.PersistenceError):
            restore.execute_restore(raw, trusted)
        alias.unlink()
        path.rename(alias)
        path.symlink_to(alias)
        with self.assertRaises(state.PersistenceError):
            restore.execute_restore(raw, trusted)
        self.assertFalse(restore.RUNTIME_ROOT.exists())
        self.assertFalse((self.root / "events").exists())

    def test_target_drift_or_rehashed_wrong_manifest_cannot_dispatch(self):
        raw, trusted = self.prepared()
        self.facts["host"]["boot_id"] = "changed"
        with self.assertRaises(state.PersistenceError):
            restore.execute_restore(raw, trusted)
        self.assertFalse(restore.RUNTIME_ROOT.exists())
        frozen = json.loads(raw)
        frozen["manifest"]["application"]["record_count"] += 1
        changed = state.canonical(frozen)
        with self.assertRaises(state.PersistenceError):
            restore.execute_restore(changed, state.sha256(changed))
        self.assertFalse((self.root / "events").exists())

    def test_partial_failure_is_consumed_and_new_operation_cannot_retry_parent(self):
        raw, trusted = self.prepared()
        (self.root / "fail").touch(mode=0o600)
        with self.assertRaises(state.PersistenceError):
            restore.execute_restore(raw, trusted)
        self.assertTrue(any(restore.RUNTIME_ROOT.rglob("intent.json")))
        self.assertTrue(any(restore.RUNTIME_ROOT.rglob("failed.json")))
        self.assertFalse(any(restore.RUNTIME_ROOT.rglob("complete.json")))
        (self.root / "fail").unlink()
        with mock.patch.object(
            restore, "inspect_target", return_value=copy.deepcopy(self.facts)
        ):
            with self.assertRaises(state.PersistenceError):
                restore.execute_restore(raw, trusted)
            value = json.loads(raw)
            value["request"]["operation_id"] = "9" * 64
            changed = state.canonical(value)
            with self.assertRaises(state.PersistenceError):
                restore.execute_restore(changed, state.sha256(changed))
        self.assertEqual(len((self.root / "events").read_text().splitlines()), 1)

    def test_source_parent_overlap_wrong_kind_versions_and_boolean_sizes_refuse(self):
        cases = []
        value = copy.deepcopy(self.request)
        value["target"]["host_profile"] = self.model["source"]["host_profile"]
        value["target"]["pool"]["name"] = "tank"
        value["target"]["parent"]["name"] = "tank/example"
        cases.append(value)
        value = copy.deepcopy(self.request)
        value["target"]["parent"]["name"] = "recovery/../foreign"
        cases.append(value)
        value = copy.deepcopy(self.request)
        value["streams"]["data"]["bytes"] = True
        cases.append(value)
        value = copy.deepcopy(self.request)
        value["target"]["versions"]["zfsutils-linux"] = "2.3.0"
        cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(state.PersistenceError):
                restore.prepare_restore(value, self.manifest_raw)
        self.assertFalse((self.root / "events").exists())

    def test_timeout_preserves_uncertainty_and_stops_only_the_exact_receiver(self):
        raw, trusted = self.prepared()
        (self.root / "delay").touch(mode=0o600)
        original = restore.receive
        started = time.monotonic()
        with mock.patch.object(
            restore,
            "receive",
            side_effect=lambda *args: original(*args, timeout_seconds=0.1),
        ):
            with self.assertRaises(state.PersistenceError) as failed:
                restore.execute_restore(raw, trusted)
        self.assertEqual(failed.exception.code, "persistence-receive-command-uncertain")
        self.assertLess(time.monotonic() - started, 3)
        result = json.loads(
            next(restore.RUNTIME_ROOT.rglob("data-result.json")).read_bytes()
        )
        self.assertTrue(result["timed_out"])
        self.assertTrue(result["process_stopped"])
        self.assertFalse(any(restore.RUNTIME_ROOT.rglob("config-dispatch.json")))
        self.assertFalse(any(restore.RUNTIME_ROOT.rglob("complete.json")))

    def test_arming_failure_cannot_open_receiver_gate(self):
        raw, trusted = self.prepared()
        writer = restore.backup.write_private

        def fail_arm(path, value):
            if path.name == "data-process.json":
                raise OSError("synthetic journal failure")
            return writer(path, value)

        with mock.patch.object(restore.backup, "write_private", side_effect=fail_arm):
            with self.assertRaises(OSError):
                restore.execute_restore(raw, trusted)
        self.assertFalse((self.root / "events").exists())
        self.assertTrue(any(restore.RUNTIME_ROOT.rglob("failed.json")))

    def test_replacement_of_input_during_receive_cannot_publish_completion(self):
        raw, trusted = self.prepared()
        original = restore.receive

        def replace_input(*args):
            original(*args)
            if args[1] == "config":
                Path(self.request["streams"]["data"]["path"]).write_bytes(
                    b"replaced after sealed copy"
                )

        with mock.patch.object(restore, "receive", side_effect=replace_input):
            with self.assertRaises(state.PersistenceError):
                restore.execute_restore(raw, trusted)
        self.assertFalse(any(restore.RUNTIME_ROOT.rglob("complete.json")))
        events = [
            json.loads(row) for row in (self.root / "events").read_text().splitlines()
        ]
        self.assertEqual(events[0]["body"], "authenticated synthetic stream:data")
        self.assertTrue(any(restore.RUNTIME_ROOT.rglob("failed.json")))

    def test_custom_child_reaper_refuses_before_consuming_parent(self):
        with mock.patch.object(
            restore.signal, "getsignal", return_value=restore.signal.SIG_IGN
        ):
            with self.assertRaises(state.PersistenceError):
                self.prepared()
        self.assertFalse(restore.RUNTIME_ROOT.exists())
        self.assertFalse((self.root / "events").exists())

    def test_completion_write_failure_is_not_received_success_or_retry_permission(self):
        raw, trusted = self.prepared()
        writer = restore.backup.write_private

        def fail_completion(path, value):
            if path.name == "complete.json":
                raise OSError("synthetic publication failure")
            return writer(path, value)

        with mock.patch.object(
            restore.backup, "write_private", side_effect=fail_completion
        ):
            with self.assertRaises(OSError):
                restore.execute_restore(raw, trusted)
        self.assertTrue(any(restore.RUNTIME_ROOT.rglob("failed.json")))
        self.assertFalse(any(restore.RUNTIME_ROOT.rglob("complete.json")))
        with mock.patch.object(
            restore, "inspect_target", return_value=copy.deepcopy(self.facts)
        ):
            with self.assertRaises(state.PersistenceError):
                restore.execute_restore(raw, trusted)
        self.assertEqual(len((self.root / "events").read_text().splitlines()), 2)

    def test_runtime_profile_does_not_accept_boolean_as_integer_version(self):
        root = restore.runtime()
        profile = root / "profile.json"
        profile.write_bytes(
            state.canonical({**restore.PROFILE, "schema_version": True})
        )
        with self.assertRaises(state.PersistenceError):
            restore.runtime()
        self.assertFalse((self.root / "events").exists())


class TargetObservationTests(unittest.TestCase):
    def setUp(self):
        self.model = manifest()
        self.request = {
            "target": {
                "node": "node-b",
                "host_profile": {
                    key: "e" * 64 for key in self.model["source"]["host_profile"]
                },
                "versions": {
                    "pve-manager": "9.2.1",
                    "pve-container": "6.1.1",
                    "zfsutils-linux": "2.4.0",
                },
                "pool": {"name": "recovery", "guid": "10"},
                "parent": {"name": "recovery/owned", "guid": "11"},
                "owner_tag": "cmdmesh-own-" + "6" * 32,
            },
            "tools": {"zfs": {}, "zpool": {}},
        }
        self.rows = {"recovery/owned": "filesystem"}
        self.props = {
            "recovery/owned": {
                key: {"value": value, "source": "local"}
                for key, value in {
                    "type": "filesystem",
                    "guid": "11",
                    "mountpoint": "none",
                    "canmount": "off",
                    "mounted": "no",
                    "org.cmdmesh:owner": self.request["target"]["owner_tag"],
                }.items()
            }
        }
        self.pool = {"guid": "10", "health": "ONLINE", "readonly": "off"}

        def command(reference, arguments):
            if arguments[:2] == ["get", "-H"] and "guid,health,readonly" in arguments:
                return "".join(
                    key + "\t" + value + "\n" for key, value in self.pool.items()
                )
            if arguments[0] == "list":
                return "".join(
                    key + "\t" + value + "\n" for key, value in self.rows.items()
                )
            fields, name = arguments[-2:]
            return "".join(
                "\t".join(
                    (
                        name,
                        field,
                        self.props[name][field]["value"],
                        self.props[name][field]["source"],
                    )
                )
                + "\n"
                for field in fields.split(",")
            )

        for patch in (
            mock.patch.object(
                restore.observe, "host_facts", return_value={"boot_id": "same"}
            ),
            mock.patch.object(restore.stream, "tool", return_value="/synthetic/zfs"),
            mock.patch.object(restore, "native", side_effect=command),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def add_received(self, role):
        name = "recovery/owned/" + role
        snapshot = name + "@cmdmesh-" + self.model["operation_id"]
        self.rows.update({name: "filesystem", snapshot: "snapshot"})
        self.props[name] = {
            key: {"value": value, "source": "local"}
            for key, value in {
                "type": "filesystem",
                "guid": str(20 + len(self.rows)),
                "mounted": "no",
                "org.cmdmesh:owner": self.request["target"]["owner_tag"],
                **restore.OPTIONS,
            }.items()
        }
        self.props[snapshot] = {
            "guid": {
                "value": self.model["datasets"][role]["snapshot_guid"],
                "source": "-",
            }
        }

    def test_only_empty_exact_owned_parent_is_accepted(self):
        self.assertEqual(
            restore.inspect_target(self.request, self.model)["received"], {}
        )
        original = copy.deepcopy(self.props)
        for field, value in (
            ("guid", "99"),
            ("mounted", "yes"),
            ("canmount", "on"),
            ("mountpoint", "/srv/foreign"),
            ("type", "volume"),
            ("org.cmdmesh:owner", "foreign"),
        ):
            self.props = copy.deepcopy(original)
            self.props["recovery/owned"][field]["value"] = value
            with self.subTest(field=field), self.assertRaises(state.PersistenceError):
                restore.inspect_target(self.request, self.model)
        self.props = original
        self.props["recovery/owned"]["org.cmdmesh:owner"][
            "source"
        ] = "inherited from recovery"
        with self.assertRaises(state.PersistenceError):
            restore.inspect_target(self.request, self.model)

    def test_existing_child_snapshot_or_bookmark_is_not_an_empty_target(self):
        for name, kind in (
            ("recovery/owned/data", "filesystem"),
            ("recovery/owned@old", "snapshot"),
            ("recovery/owned#old", "bookmark"),
        ):
            self.rows = {"recovery/owned": "filesystem", name: kind}
            with self.subTest(name=name), self.assertRaises(state.PersistenceError):
                restore.inspect_target(self.request, self.model)

    def test_received_snapshots_must_match_trusted_manifest_and_stay_unmounted(self):
        self.add_received("data")
        self.add_received("config")
        result = restore.inspect_target(self.request, self.model, ("data", "config"))
        self.assertEqual(set(result["received"]), {"data", "config"})
        original = copy.deepcopy(self.props)
        for field, value in (
            ("mounted", "yes"),
            ("readonly", "off"),
            ("canmount", "on"),
            ("exec", "on"),
            ("sharenfs", "on"),
        ):
            self.props = copy.deepcopy(original)
            self.props["recovery/owned/data"][field]["value"] = value
            with self.subTest(field=field), self.assertRaises(state.PersistenceError):
                restore.inspect_target(self.request, self.model, ("data", "config"))
        self.props = original
        name = "recovery/owned/data@cmdmesh-" + self.model["operation_id"]
        self.props[name]["guid"]["value"] = "999"
        with self.assertRaises(state.PersistenceError):
            restore.inspect_target(self.request, self.model, ("data", "config"))

    def test_wrong_pool_or_foreign_extra_after_first_receive_stops_progress(self):
        for key, value in (("guid", "99"), ("health", "DEGRADED"), ("readonly", "on")):
            original = self.pool[key]
            self.pool[key] = value
            with self.subTest(key=key), self.assertRaises(state.PersistenceError):
                restore.inspect_target(self.request, self.model)
            self.pool[key] = original
        self.add_received("data")
        self.rows["recovery/owned/foreign"] = "filesystem"
        with self.assertRaises(state.PersistenceError):
            restore.inspect_target(self.request, self.model, ("data",))


if __name__ == "__main__":
    unittest.main()
