"""Backup manifests are typed descriptions, not self-authenticating evidence."""

import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(
    0, str(ROOT / "ansible/ansible_collections/cmdmesh/proxmox/plugins/module_utils")
)
import persistence_state as state


def manifest():
    operation = "a" * 64
    return {
        "document_type": "cmdmesh.proxmox.persistence.backup-manifest",
        "schema_version": 1,
        "profile_version": 1,
        "operation_id": operation,
        "source": {
            "selector": {
                "origin": "example",
                "node": "node-a",
                "kind": "proxmox.lxc",
                "vmid": 101,
            },
            "host_profile": {
                "machine_id_sha256": "b" * 64,
                "ca_certificate_sha256": "c" * 64,
                "leaf_certificate_sha256": "d" * 64,
            },
            "owner_tag": "cmdmesh-own-" + "2" * 32,
            "generation_tag": "cmdmesh-gen-" + "3" * 32,
        },
        "datasets": {
            role: {
                "name": "tank/example/" + role,
                "guid": str(i + 1),
                "snapshot": "tank/example/" + role + "@cmdmesh-" + operation,
                "snapshot_guid": str(i + 3),
                "createtxg": "99",
            }
            for i, role in enumerate(("data", "config"))
        },
        "application": {
            "instance_id": "4" * 32,
            "config_sha256": "5" * 64,
            "database_sha256": "6" * 64,
            "records_sha256": "7" * 64,
            "record_count": 1,
            "mapping": {"offset": 100000, "length": 65536, "uid": 1100, "gid": 1100},
        },
        "recipient": "age1" + "q" * 58,
        "artifacts": {
            role: {"name": role + ".zfs.age", "bytes": 8192, "sha256": str(i + 8) * 64}
            for i, role in enumerate(("data", "config"))
        },
    }


class ManifestTests(unittest.TestCase):
    def test_canonical_manifest_matches_separately_trusted_receipt(self):
        value = manifest()
        raw = state.canonical(value)
        self.assertEqual(state.load_manifest(raw, state.sha256(raw)), value)

    def test_modified_manifest_cannot_supply_its_own_trust(self):
        value = manifest()
        expected = state.sha256(state.canonical(value))
        value["source"]["selector"]["vmid"] = 102
        with self.assertRaises(state.PersistenceError):
            state.load_manifest(state.canonical(value), expected)

    def test_mixed_generations_same_guid_and_foreign_sibling_refuse(self):
        for field, wrong in (
            ("createtxg", "100"),
            ("guid", "1"),
            ("snapshot_guid", "3"),
            ("snapshot", "tank/example/config@foreign"),
            ("name", "other/example/config"),
        ):
            value = manifest()
            value["datasets"]["config"][field] = wrong
            with self.subTest(field=field), self.assertRaises(state.PersistenceError):
                state.validate_manifest(value)

    def test_extra_secrets_paths_booleans_and_unsupported_mapping_refuse(self):
        cases = []
        value = manifest()
        value["token"] = "never part of a manifest"
        cases.append(value)
        value = manifest()
        value["artifacts"]["data"]["name"] = "../foreign"
        cases.append(value)
        value = manifest()
        value["artifacts"]["data"]["bytes"] = True
        cases.append(value)
        value = manifest()
        value["application"]["mapping"]["offset"] = 200000
        cases.append(value)
        value = manifest()
        value["application"]["record_count"] = 0
        cases.append(value)
        for value in cases:
            with self.assertRaises(state.PersistenceError):
                state.validate_manifest(value)

    def test_duplicate_json_fields_and_unknown_version_refuse(self):
        value = manifest()
        raw = state.canonical(value)
        duplicate = raw[:-1] + b',"schema_version":1}'
        with self.assertRaises(state.PersistenceError):
            state.load_manifest(duplicate, state.sha256(duplicate))
        value["profile_version"] = 2
        with self.assertRaises(state.PersistenceError):
            state.validate_manifest(value)

    def test_pair_lock_key_is_shared_between_vmids_but_not_other_pairs(self):
        pair = manifest()["datasets"]
        self.assertEqual(
            state.pair_key(pair), state.pair_key(dict(reversed(list(pair.items()))))
        )
        other = copy.deepcopy(pair)
        other["config"]["guid"] = "50"
        self.assertNotEqual(state.pair_key(pair), state.pair_key(other))

    def test_float_uid_mapping_is_not_a_supported_integer_mapping(self):
        value = manifest()
        value["application"]["mapping"] = {
            k: float(v) for k, v in value["application"]["mapping"].items()
        }
        raw = state.canonical(value)
        with self.assertRaises(state.PersistenceError):
            state.load_manifest(raw, state.sha256(raw))

    def test_deep_json_and_python_values_have_typed_failure(self):
        raw = b"[" * 10000 + b"0" + b"]" * 10000
        with self.assertRaises(state.PersistenceError):
            state.load_manifest(raw, state.sha256(raw))
        value = 0
        for unused in range(10000):
            value = [value]
        with self.assertRaises(state.PersistenceError):
            state.canonical(value)


if __name__ == "__main__":
    unittest.main()
