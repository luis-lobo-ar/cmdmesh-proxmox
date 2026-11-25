"""Blank OS starts must not open a path to retained data or networking."""

import copy
import json
from pathlib import Path
import stat
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_blank_guard as guard,
    persistence_recipient as recipient,
)
from test_persistence_recipient import example_request


def model():
    request = example_request()
    config = recipient.create_request(request)
    for key in ("vmid", "ostemplate", "start"):
        del config[key]
    for key in ("cores", "memory", "swap", "unprivileged", "onboot", "protection"):
        config[key] = int(config[key])
    config.update(
        rootfs="local:102/vm-102-disk-0.raw,size=2G",
        arch="amd64",
        ostype="ubuntu",
        digest="c" * 40,
    )
    rootfs = {
        "path": "/var/lib/vz/images/102/vm-102-disk-0.raw",
        "identity": [1, 2, stat.S_IFREG | 0o600, 0, 0, 1, 2 * 1024**3],
        "uuid": "44444444-4444-4444-4444-444444444444",
    }
    generated = (
        "lxc.rootfs.path = /var/lib/lxc/102/rootfs\n"
        "lxc.cgroup2.cpu.max = 100000 100000\n"
        "lxc.cgroup2.cpuset.cpus = \n"
    )
    policy = {
        "schema_version": 1,
        "machine_id_sha256": "a" * 64,
        "node": "node-a",
        "vmid": 102,
        "source_vmid": 101,
        "config": config,
        "rootfs": rootfs,
        "generated_config_stable_sha256": guard.generated_fingerprint(
            generated.encode()
        )[0],
        "cpu_policy": {"allowed": [0, 1, 2, 3], "count": 1},
    }
    facts = {
        "machine_id_sha256": "a" * 64,
        "node": "node-a",
        "config": copy.deepcopy(config),
        "source_status": {"status": "stopped", "uptime": 0},
        "target_status": {"status": "stopped", "uptime": 0},
        "pending": [],
        "ha": [],
        "rootfs": {**copy.deepcopy(rootfs), "resolved_path": rootfs["path"]},
        "generated_config": generated,
        "cpu_available": [0, 1, 2, 3],
    }
    return policy, facts


class BlankGuardTests(unittest.TestCase):
    def test_exact_blank_recipient_is_only_boot_permission(self):
        policy, facts = model()
        self.assertIsNone(guard.validate(policy, facts, 102))

    def test_wrong_machine_guest_source_or_rootfs_refuses(self):
        policy, original = model()
        for key, value in (
            ("machine_id_sha256", "b" * 64),
            ("node", "other"),
            ("source_status", {"status": "running", "pid": 123}),
        ):
            facts = copy.deepcopy(original)
            facts[key] = value
            with self.assertRaises(guard.Refused):
                guard.validate(policy, facts, 102)
        with self.assertRaises(guard.Refused):
            guard.validate(policy, original, 101)
        for key, value in (("uuid", None), ("path", "/srv/foreign.raw")):
            facts = copy.deepcopy(original)
            facts["rootfs"][key] = value
            with self.assertRaises(guard.Refused):
                guard.validate(policy, facts, 102)

    def test_unsafe_policy_refuses_even_matching_observed_facts(self):
        for key, value in (
            ("net0", "name=eth0,bridge=vmbr0"),
            ("mp0", "/srv/retained,mp=/var/lib/reference-ledger"),
            ("lxc", []),
            ("features", "nesting=1"),
            ("hookscript", "run.pl"),
            ("cores", 2),
            ("cpulimit", "0"),
            ("memory", 1024),
            ("unprivileged", 0),
            ("onboot", 1),
            ("protection", 0),
            ("tags", "cmdmesh-ansible"),
        ):
            policy, facts = model()
            policy["config"][key] = value
            facts["config"] = copy.deepcopy(policy["config"])
            with self.assertRaises(guard.Refused):
                guard.validate(policy, facts, 102)

    def test_pending_ha_and_configuration_drift_refuse(self):
        policy, original = model()
        for field, value in (
            ("pending", [{"key": "mp0", "pending": "/srv/retained"}]),
            ("pending", [{"key": "memory"}, {"key": "memory"}]),
            ("ha", [{"sid": "ct:102"}]),
            ("config", {**original["config"], "description": "changed"}),
        ):
            facts = copy.deepcopy(original)
            facts[field] = value
            with self.assertRaises(guard.Refused):
                guard.validate(policy, facts, 102)

    def test_rootfs_permissions_link_count_and_identity_refuse(self):
        policy, original = model()
        for index, value in (
            (1, 99),
            (2, stat.S_IFLNK | 0o777),
            (3, 100000),
            (5, 2),
            (6, 0),
        ):
            facts = copy.deepcopy(original)
            facts["rootfs"]["identity"][index] = value
            with self.assertRaises(guard.Refused):
                guard.validate(policy, facts, 102)

    def test_json_duplicate_and_nonfinite_policy_refuse(self):
        for raw in (b'{"schema_version":1,"schema_version":1}', b'{"value":NaN}'):
            with self.assertRaises(guard.Refused):
                guard.decode(raw)

    def test_generated_config_changes_refuse_even_when_pve_config_matches(self):
        policy, original = model()
        for raw in (
            original["generated_config"]
            + "lxc.mount.entry = /srv/retained data none bind 0 0\n",
            original["generated_config"].replace("100000 100000", "max 100000"),
            original["generated_config"] + "lxc.cgroup2.cpuset.cpus = 0\n",
            original["generated_config"].replace(
                "cpuset.cpus = \n", "cpuset.cpus = 0,1\n"
            ),
            original["generated_config"].replace(
                "cpuset.cpus = \n", "cpuset.cpus = 4\n"
            ),
        ):
            facts = copy.deepcopy(original)
            facts["generated_config"] = raw
            with self.assertRaises(guard.Refused):
                guard.validate(policy, facts, 102)

    def test_empty_inherited_or_one_selected_cpu_requires_exact_quota_and_approved_parent(
        self,
    ):
        policy, facts = model()
        guard.validate(policy, facts, 102)
        facts["generated_config"] = facts["generated_config"].replace(
            "cpuset.cpus = \n", "cpuset.cpus = 2\n"
        )
        guard.validate(policy, facts, 102)
        for invalid in ([], [0, 1, 2, 3, 4], [False], [1, 0], [0, 0]):
            facts["cpu_available"] = invalid
            with self.assertRaises(guard.Refused):
                guard.validate(policy, facts, 102)


class BlankGuardCollectionTests(unittest.TestCase):
    def test_complete_collect_and_late_file_or_storage_drift(self):
        for fault in (None, "rootfs", "generated-config", "storage-resolution"):
            policy, baseline = model()
            machine = b"0123456789abcdef0123456789abcdef\n"
            policy["machine_id_sha256"] = guard.hashlib.sha256(
                machine.strip()
            ).hexdigest()
            current = {
                "inode": 2,
                "generated": baseline["generated_config"],
                "resolved": policy["rootfs"]["path"],
            }

            class FakePath:
                def __init__(self, path):
                    self.path = str(path)

                def __str__(self):
                    return self.path

                def resolve(self, strict=True):
                    return self

                def exists(self):
                    return True

                def lstat(self):
                    parts = policy["rootfs"]["identity"]
                    return SimpleNamespace(
                        st_dev=parts[0],
                        st_ino=current["inode"],
                        st_mode=parts[2],
                        st_uid=parts[3],
                        st_gid=parts[4],
                        st_nlink=parts[5],
                        st_size=parts[6],
                        st_mtime_ns=1,
                        st_ctime_ns=1,
                    )

                def read_text(self):
                    return "0-3\n"

            def files(path, limit):
                return (
                    machine
                    if str(path) == "/etc/machine-id"
                    else current["generated"].encode()
                )

            def native(argv):
                if argv[0] == "/usr/sbin/blkid":
                    return (
                        "TYPE=ext4\nUUID=" + policy["rootfs"]["uuid"] + "\n"
                    ).encode()
                if argv[0] == "/usr/sbin/pvesm":
                    return (current["resolved"] + "\n").encode()
                path = argv[2]
                if path.endswith("/config"):
                    return json.dumps(policy["config"]).encode()
                if path.endswith("/pending"):
                    return b"[]"
                if path.endswith("/status/current"):
                    return b'{"status":"stopped","uptime":0}'
                if fault == "rootfs":
                    current["inode"] = 999
                elif fault == "generated-config":
                    current[
                        "generated"
                    ] += "lxc.mount.entry = /srv/retained data none bind 0 0\n"
                elif fault == "storage-resolution":
                    current["resolved"] = "/srv/reconfigured/102/vm-102-disk-0.raw"
                return b"[]"

            with mock.patch.object(
                guard.os, "geteuid", return_value=0
            ), mock.patch.object(guard, "Path", FakePath), mock.patch.object(
                guard, "read_file", side_effect=files
            ), mock.patch.object(
                guard, "native", side_effect=native
            ), mock.patch.object(
                guard.socket, "gethostname", return_value=policy["node"]
            ):
                if fault is None:
                    guard.validate(policy, guard.collect(policy), 102)
                else:
                    with self.assertRaises(guard.Refused):
                        guard.validate(policy, guard.collect(policy), 102)


if __name__ == "__main__":
    unittest.main()
