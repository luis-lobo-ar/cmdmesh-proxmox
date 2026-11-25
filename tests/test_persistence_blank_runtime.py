"""A running API status alone does not qualify an isolated blank OS boot."""

import copy
import fcntl
import os
from pathlib import Path
import sys
import unittest
import tempfile
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_blank_runtime as runtime,
)
import test_persistence_blank_guard as fixtures


def model():
    policy, original = fixtures.model()
    value = {
        "config": copy.deepcopy(policy["config"]),
        "pending": [],
        "ha": [],
        "status": {
            "status": "running",
            "vmid": 102,
            "name": policy["config"]["hostname"],
            "type": "lxc",
            "cpus": 1,
            "maxmem": 536870912,
            "maxswap": 0,
            "maxdisk": 2147483648,
        },
        "source_status": {"status": "stopped", "uptime": 0},
        "init": {
            "pid": 234,
            "pstart": 500,
            "pid_namespace_inode": 20,
            "host_pid_namespace_inode": 10,
            "uid_map": [[0, 100000, 65536]],
            "gid_map": [[0, 100000, 65536]],
        },
        "cgroup": {
            "path": "0::/lxc/102/ns/init.scope",
            "effective_memory_bytes": 536870912,
            "memory_max": "536870912",
            "swap_max": "0",
            "cpu_max": "100000 100000",
            "cpus": [1],
        },
        "rootfs": {
            **copy.deepcopy(policy["rootfs"]),
            "backing_file": policy["rootfs"]["path"],
            "resolved_path": policy["rootfs"]["path"],
            "device": [7, 2],
            "filesystem_type": "ext4",
        },
        "security": {
            "net_namespace": "net:[20]",
            "host_net_namespace": "net:[10]",
            "apparmor_label": "lxc-102_</var/lib/lxc> (enforce)",
        },
        "generated_config": original["generated_config"],
        "guest": {
            "uid": 0,
            "gid": 0,
            "python": [3, 12, 3],
            "sqlite": "3.45.1",
            "hostname": policy["config"]["hostname"],
            "interfaces": ["lo"],
            "affinity": [1],
            "uid_map": [[0, 100000, 65536]],
            "gid_map": [[0, 100000, 65536]],
            "root_device": 1794,
            "machine_id_sha256": "b" * 64,
            "paths_absent": {name: True for name in runtime.ABSENT_PATHS},
            "uid_unused": True,
            "gid_unused": True,
            "account_names_unused": True,
            "systemd": {"code": 0, "stdout": "running\n", "stderr": ""},
            "failed_units": {"code": 0, "stdout": "", "stderr": ""},
        },
    }
    return policy, value


class BlankRuntimeTests(unittest.TestCase):
    def test_running_filesystem_capacity_is_distinct_from_raw_image_bytes(self):
        policy, value = model()
        value["status"]["maxdisk"] = 2040373248
        runtime.validate(policy, value)
        for invalid in (None, True, 0, -1, 2147483649):
            with self.subTest(invalid=invalid):
                value["status"]["maxdisk"] = invalid
                with self.assertRaises(ValueError):
                    runtime.validate(policy, value)
        value["status"]["maxdisk"] = 2040373248
        value["rootfs"]["identity"][6] -= 4096
        with self.assertRaises(ValueError):
            runtime.validate(policy, value)

    def test_complete_runtime_qualifies_no_application_claim(self):
        policy, value = model()
        self.assertIsNone(runtime.validate(policy, value))

    def test_running_api_with_wrong_kernel_identity_or_limits_refuses(self):
        for section, key, invalid in (
            ("init", "pid", True),
            ("init", "pstart", 0),
            ("init", "uid_map", [[0, 0, 65536]]),
            ("init", "pid_namespace_inode", 10),
            ("cgroup", "path", "0::/lxc/101/ns/init.scope"),
            ("cgroup", "cpu_max", "max 100000"),
            ("cgroup", "cpus", [0, 1]),
            ("cgroup", "memory_max", "1073741824"),
            ("cgroup", "swap_max", "536870912"),
            ("rootfs", "backing_file", "/srv/other.raw"),
            ("rootfs", "resolved_path", "/srv/other.raw"),
            ("rootfs", "uuid", "55555555-5555-5555-5555-555555555555"),
            ("security", "net_namespace", "net:[10]"),
            ("security", "apparmor_label", "unconfined"),
        ):
            policy, value = model()
            value[section][key] = invalid
            with self.assertRaises(ValueError):
                runtime.validate(policy, value)

    def test_guest_network_app_or_affinity_mismatch_refuses(self):
        for key, invalid in (
            ("interfaces", ["lo", "eth0"]),
            ("affinity", [2]),
            ("uid", 100000),
            ("uid_unused", False),
            ("account_names_unused", False),
            ("systemd", {"code": 1, "stdout": "degraded\n", "stderr": ""}),
        ):
            policy, value = model()
            value["guest"][key] = invalid
            with self.assertRaises(ValueError):
                runtime.validate(policy, value)
        policy, value = model()
        value["guest"]["paths_absent"]["/etc/reference-ledger"] = False
        with self.assertRaises(ValueError):
            runtime.validate(policy, value)

    def test_root_mtime_is_outside_runtime_identity_but_inode_is_bound(self):
        policy, value = model()
        # The image's first seven identity fields remain fixed across OS writes;
        # running proof intentionally excludes mtime/ctime rather than freezing them.
        runtime.validate(policy, value)
        value["rootfs"]["identity"][1] += 1
        with self.assertRaises(ValueError):
            runtime.validate(policy, value)

    def test_foreign_generated_bytes_pending_or_old_writer_refuse(self):
        for field, invalid in (
            ("generated_config", "lxc.cgroup2.cpu.max = max 100000\n"),
            ("pending", [{"key": "mp0", "pending": "/srv/retained"}]),
            ("source_status", {"status": "running", "uptime": 1}),
            ("ha", [{"sid": "ct:102"}]),
        ):
            policy, value = model()
            value[field] = invalid
            with self.assertRaises(ValueError):
                runtime.validate(policy, value)

    def test_systemd_false_boolean_is_not_exit_zero(self):
        policy, value = model()
        value["guest"]["systemd"]["code"] = False
        with self.assertRaises(ValueError):
            runtime.validate(policy, value)

    def test_native_config_shared_lock_excludes_writer_without_editing_file(self):
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        policy, _ = model()
        with tempfile.TemporaryDirectory(
            dir=ROOT / ".generated", prefix="runtime-lock-"
        ) as work:
            path = Path(work) / "pve-config-102.lock"
            path.write_bytes(b"")
            path.chmod(0o600)
            with mock.patch.object(
                runtime.config_lock, "LOCK_ROOT", Path(work)
            ), mock.patch.object(runtime.config_lock, "ROOT_UID", os.geteuid()):
                with path.open("rb") as writer:
                    with runtime.target_read_lock(policy):
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    with self.assertRaises(runtime.state.PersistenceError) as failure:
                        with runtime.target_read_lock(policy):
                            self.fail("busy native configuration lock accepted")
                    self.assertEqual(
                        failure.exception.code,
                        "persistence-blank-runtime-native-lock-busy",
                    )
                self.assertEqual(path.read_bytes(), b"")

    def test_wrong_initial_target_or_mapping_refuses_before_guest_execution(self):
        for fault in ("bind", "mapping"):
            policy, value = model()
            api = {
                key: value[key]
                for key in ("config", "pending", "ha", "status", "source_status")
            }
            kernel = {
                key: value[key]
                for key in ("init", "cgroup", "rootfs", "security", "generated_config")
            }
            if fault == "bind":
                api["config"]["mp0"] = "/srv/retained,mp=/data"
            else:
                kernel["init"]["uid_map"] = [[0, 0, 65536]]
            with mock.patch.object(runtime, "api", return_value=api), mock.patch.object(
                runtime, "kernel", return_value=kernel
            ), mock.patch.object(
                runtime.observe,
                "native",
                return_value=runtime.state.canonical(value["guest"]),
            ) as native:
                with self.assertRaises(ValueError):
                    runtime.collect_locked(policy)
                native.assert_not_called()

    def test_actual_kernel_pass_closes_image_and_generated_files_after_slow_reads(self):
        for fault in (None, "image", "generated"):
            policy, value = model()
            observed = {"inode": 2, "text": value["generated_config"], "pid_reads": 0}
            api = {key: value[key] for key in runtime.API_FIELDS}

            class FakePath:
                def __init__(self, path):
                    self.path = str(path)

                def __truediv__(self, part):
                    return FakePath(self.path + "/" + str(part))

                def __str__(self):
                    return self.path

                def resolve(self, strict=True):
                    return self

                def stat(self):
                    return SimpleNamespace(st_dev=1794)

                def lstat(self):
                    parts = policy["rootfs"]["identity"]
                    return SimpleNamespace(
                        st_dev=parts[0],
                        st_ino=observed["inode"],
                        st_mode=parts[2],
                        st_uid=0,
                        st_gid=0,
                        st_nlink=1,
                        st_size=parts[6],
                        st_mtime_ns=1,
                        st_ctime_ns=1,
                    )

            def pid(vmid):
                observed["pid_reads"] += 1
                if observed["pid_reads"] == 4:
                    if fault == "image":
                        observed["inode"] = 999
                    elif fault == "generated":
                        observed[
                            "text"
                        ] += "lxc.mount.entry = /srv/retained data none bind 0 0\n"
                return 234

            def text(path):
                name = str(path)
                if name.endswith("/loop/backing_file"):
                    return policy["rootfs"]["path"]
                if name.endswith(("/uid_map", "/gid_map")):
                    return "0 100000 65536\n"
                if name.endswith("/attr/current"):
                    return value["security"]["apparmor_label"]
                return {
                    "memory.max": "536870912",
                    "memory.swap.max": "0",
                    "cpu.max": "100000 100000",
                    "cpuset.cpus.effective": "1",
                }[name.rsplit("/", 1)[-1]]

            def native(argv):
                if argv[0] == "/usr/sbin/pct":
                    return runtime.state.canonical(value["guest"])
                if argv[0] == "/usr/sbin/pvesm":
                    return (policy["rootfs"]["path"] + "\n").encode()
                return ("TYPE=ext4\nUUID=" + policy["rootfs"]["uuid"] + "\n").encode()

            def regular(path, limit):
                raw = observed["text"].encode()
                return raw, SimpleNamespace(
                    st_dev=1,
                    st_ino=3,
                    st_mode=0o100600,
                    st_uid=0,
                    st_gid=0,
                    st_nlink=1,
                    st_size=len(raw),
                    st_mtime_ns=1,
                    st_ctime_ns=1,
                )

            with mock.patch.object(runtime, "Path", FakePath), mock.patch.object(
                runtime, "api", return_value=api
            ), mock.patch.object(
                runtime.memory, "lxc_pid", side_effect=pid
            ), mock.patch.object(
                runtime.memory, "init_state", return_value=(500, 20)
            ), mock.patch.object(
                runtime.memory, "namespace_inode", return_value=10
            ), mock.patch.object(
                runtime.memory,
                "memory_limit",
                return_value=(536870912, "0::/lxc/102/ns/init.scope"),
            ), mock.patch.object(
                runtime.memory, "read_text", side_effect=text
            ), mock.patch.object(
                runtime.observe, "native", side_effect=native
            ), mock.patch.object(
                runtime.observe, "read_regular", side_effect=regular
            ), mock.patch.object(
                runtime.os,
                "readlink",
                side_effect=lambda path: (
                    "net:[10]" if str(path) == "/proc/1/ns/net" else "net:[20]"
                ),
            ):
                if fault is None:
                    runtime.collect_locked(policy)
                else:
                    with self.assertRaises(ValueError):
                        runtime.collect_locked(policy)


if __name__ == "__main__":
    unittest.main()
