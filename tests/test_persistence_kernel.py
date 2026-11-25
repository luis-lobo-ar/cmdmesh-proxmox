"""Kernel evidence has an explicit binding independent of blank guest policy."""

import copy
from dataclasses import replace
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_kernel as kernel,
)
import test_persistence_blank_runtime as fixtures


def model():
    policy, runtime = fixtures.model()
    binding = kernel.KernelBinding(
        node=policy["node"],
        machine_id_sha256=policy["machine_id_sha256"],
        vmid=policy["vmid"],
        volume=policy["config"]["rootfs"].split(",", 1)[0],
        root_path=policy["rootfs"]["path"],
        root_identity=tuple(policy["rootfs"]["identity"]),
        root_uuid=policy["rootfs"]["uuid"],
        generated_sha256=policy["generated_config_stable_sha256"],
        allowed_cpus=tuple(policy["cpu_policy"]["allowed"]),
    )
    return binding, {
        key: copy.deepcopy(runtime[key]) for key in fixtures.runtime.KERNEL_FIELDS
    }


class KernelBindingTests(unittest.TestCase):
    def test_reference_kernel_validates_without_blank_guest_policy(self):
        binding, value = model()
        with mock.patch.object(
            kernel.reader.guard,
            "validate_policy",
            side_effect=AssertionError("blank policy must not be used"),
        ):
            kernel.validate(binding, value)
        self.assertFalse(hasattr(binding, "config"))
        self.assertFalse(hasattr(binding, "source_vmid"))

    def test_binding_rejects_wrong_target_identity_and_mutable_or_boolean_fields(self):
        binding, _ = model()
        for field, changed in (
            ("vmid", True),
            ("vmid", 99),
            ("volume", "local:101/vm-101-disk-0.raw"),
            ("root_path", "/srv/other.raw"),
            ("root_identity", list(binding.root_identity)),
            ("root_identity", (1, True, *binding.root_identity[2:])),
            ("allowed_cpus", [1]),
            ("allowed_cpus", (True,)),
            ("allowed_cpus", (2, 1)),
            ("machine_id_sha256", "wrong"),
        ):
            with self.subTest(field=field, changed=changed), self.assertRaises(
                ValueError
            ):
                replace(binding, **{field: changed})

    def test_wrong_runtime_process_backing_mapping_and_limits_refuse(self):
        binding, original = model()
        for section, key, changed in (
            ("init", "pstart", 0),
            ("init", "uid_map", [[0, 0, 65536]]),
            ("rootfs", "backing_file", "/srv/foreign.raw"),
            ("rootfs", "uuid", "55555555-5555-5555-5555-555555555555"),
            ("cgroup", "path", "0::/lxc/101/ns/init.scope"),
            ("cgroup", "cpu_max", "max 100000"),
            ("security", "apparmor_label", "unconfined"),
        ):
            value = copy.deepcopy(original)
            value[section][key] = changed
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                kernel.validate(binding, value)

    def test_host_mismatch_refuses_before_process_or_image_observation(self):
        binding, _ = model()
        with mock.patch.object(kernel.os, "geteuid", return_value=0), mock.patch.object(
            kernel.socket, "gethostname", return_value="wrong-node"
        ), mock.patch.object(kernel.reader, "kernel") as read:
            with self.assertRaises(ValueError):
                kernel.collect(binding)
        read.assert_not_called()

    def test_collection_admits_and_closes_host_and_kernel_without_blank_admission(self):
        binding, value = model()
        machine = b"a" * 32
        binding = replace(binding, machine_id_sha256=kernel.state.sha256(machine))
        with mock.patch.object(kernel.os, "geteuid", return_value=0), mock.patch.object(
            kernel.socket, "gethostname", return_value=binding.node
        ), mock.patch.object(
            kernel.observe, "read_regular", return_value=(machine + b"\n", None)
        ), mock.patch.object(
            kernel.reader, "kernel", return_value=value
        ) as read, mock.patch.object(
            kernel.reader.guard,
            "validate_policy",
            side_effect=AssertionError("blank policy must not be used"),
        ):
            self.assertEqual(kernel.collect(binding), value)
        self.assertEqual(read.call_count, 1)
        self.assertNotIn("schema_version", read.call_args.args[0])

    def test_late_host_change_refuses_collected_kernel(self):
        binding, value = model()
        machine = b"a" * 32
        binding = replace(binding, machine_id_sha256=kernel.state.sha256(machine))
        with mock.patch.object(kernel.os, "geteuid", return_value=0), mock.patch.object(
            kernel.socket, "gethostname", side_effect=[binding.node, "wrong-node"]
        ), mock.patch.object(
            kernel.observe, "read_regular", return_value=(machine, None)
        ), mock.patch.object(
            kernel.reader, "kernel", return_value=value
        ):
            with self.assertRaises(ValueError):
                kernel.collect(binding)
