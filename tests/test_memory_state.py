"""A memory observation is evidence only after strict identity/state validation."""

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "inspection"))


def expected():
    return {
        "request_id": "1" * 32,
        "selector": {
            "origin": "example",
            "node": "node-a",
            "kind": "proxmox.lxc",
            "vmid": 101,
        },
        "host_profile": {
            "machine_id_sha256": "a" * 64,
            "ca_certificate_sha256": "b" * 64,
            "leaf_certificate_sha256": "c" * 64,
        },
        "owner_tag": "cmdmesh-own-" + "2" * 32,
        "generation_tag": "cmdmesh-gen-" + "3" * 32,
    }


def observation():
    value = expected()
    return {
        "document_type": "cmdmesh.proxmox.lxc-memory.observation",
        "schema_version": 1,
        "request_id": value["request_id"],
        "origin": "example",
        "node": "node-a",
        "host_profile": value["host_profile"],
        "host_boot_id_sha256": "f" * 64,
        "kind": "proxmox.lxc",
        "vmid": 101,
        "tags": ["cmdmesh-ansible", value["owner_tag"], value["generation_tag"]],
        "configuration": {
            "digest": "d" * 40,
            "memory_mb": 256,
            "swap_mb": 0,
            "other_sha256": "e" * 64,
            "locked": False,
            "pending": False,
        },
        "runtime": {
            "status": "running",
            "memory_limit_bytes": 256 * 1024**2,
            "init_start_ticks": 100,
            "pid_namespace_inode": 200,
        },
        "host_capacity": {"total_bytes": 16 * 1024**3, "available_bytes": 8 * 1024**3},
        "versions": {"pve-manager": "9.2.21", "pve-container": "6.1.14"},
        "observed_at_unix_ms": 199000,
        "complete": True,
        "warnings": [],
    }


class MemoryStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import memory_state

        cls.state = memory_state

    def validate(self, value=None, wanted=None):
        return self.state.validate_observation(
            value if value is not None else observation(),
            wanted if wanted is not None else expected(),
            now_ms=200000,
            max_age_seconds=30,
        )

    def assert_invalid(self, value, code):
        with self.assertRaises(self.state.MemoryEvidenceError) as raised:
            self.validate(value)
        self.assertEqual(raised.exception.code, code)

    def test_complete_owned_running_state_has_stable_subject_key_and_no_mutation_authority(
        self,
    ):
        result = self.validate()
        self.assertEqual(len(result["subject_key"]), 64)
        self.assertEqual(result["configuration"]["memory_mb"], 256)
        self.assertFalse(result["mutation_authorized"])
        self.assertFalse(result["current_observation"])
        self.assertEqual(result["validation_scope"], "supplied-evidence-only")
        changed_label = expected()
        changed_label["selector"]["origin"] = "another-label"
        value = observation()
        value["origin"] = "another-label"
        self.assertEqual(
            self.validate(value, changed_label)["subject_key"], result["subject_key"]
        )

    def test_each_identity_and_generation_boundary_is_checked(self):
        for field, replacement in (
            ("origin", "other"),
            ("node", "node-b"),
            ("kind", "proxmox.vm"),
            ("vmid", 102),
            ("request_id", "9" * 32),
        ):
            value = observation()
            value[field] = replacement
            self.assert_invalid(value, "memory-identity-mismatch")
        for field in observation()["host_profile"]:
            value = observation()
            value["host_profile"][field] = "f" * 64
            self.assert_invalid(value, "memory-host-profile-mismatch")

    def test_missing_ambiguous_or_conflicting_actual_ownership_is_rejected(self):
        tag = expected()["owner_tag"]
        for tags in (
            ["cmdmesh-ansible"],
            ["cmdmesh-ansible", tag, tag, expected()["generation_tag"]],
            observation()["tags"] + ["cmdmesh-terraform"],
            observation()["tags"] + ["cmdmesh-gen-" + "4" * 32],
        ):
            value = observation()
            value["tags"] = tags
            self.assert_invalid(value, "memory-ownership-unqualified")

    def test_partial_warned_stale_future_and_missing_source_evidence_cannot_pass(self):
        for field, replacement, code in (
            ("complete", False, "memory-evidence-incomplete"),
            ("warnings", ["SYNTHETIC_PRIVATE_RESPONSE"], "memory-evidence-incomplete"),
            ("observed_at_unix_ms", 100000, "memory-evidence-time-unqualified"),
            ("observed_at_unix_ms", 201000, "memory-evidence-time-unqualified"),
        ):
            value = observation()
            value[field] = replacement
            self.assert_invalid(value, code)
        value = observation()
        del value["host_profile"]
        self.assert_invalid(value, "invalid-memory-evidence")

    def test_numeric_fields_do_not_accept_booleans_strings_or_missing_runtime(self):
        for path in (
            ("vmid",),
            ("configuration", "memory_mb"),
            ("configuration", "swap_mb"),
            ("runtime", "memory_limit_bytes"),
            ("runtime", "init_start_ticks"),
            ("runtime", "pid_namespace_inode"),
            ("host_capacity", "available_bytes"),
        ):
            for invalid in (True, "256", -1):
                value = observation()
                target = value
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = invalid
                self.assert_invalid(value, "invalid-memory-evidence")
        value = observation()
        del value["runtime"]["memory_limit_bytes"]
        self.assert_invalid(value, "invalid-memory-evidence")

    def test_stopped_locked_pending_or_unenforced_memory_is_not_ready(self):
        for section, field, replacement, code in (
            ("runtime", "status", "stopped", "memory-runtime-unqualified"),
            ("configuration", "locked", True, "memory-configuration-unqualified"),
            ("configuration", "pending", True, "memory-configuration-unqualified"),
            (
                "runtime",
                "memory_limit_bytes",
                128 * 1024**2,
                "memory-runtime-unqualified",
            ),
        ):
            value = observation()
            value[section][field] = replacement
            self.assert_invalid(value, code)

    def test_unknown_versions_or_fields_and_bad_digest_fail(self):
        value = observation()
        value["versions"]["pve-manager"] = "99.0.0"
        self.assert_invalid(value, "memory-version-unsupported")
        for path in (("extra",), ("configuration", "extra")):
            value = observation()
            target = value if len(path) == 1 else value[path[0]]
            target[path[-1]] = "SYNTHETIC_PRIVATE_RESPONSE"
            self.assert_invalid(value, "invalid-memory-evidence")
        value = observation()
        value["configuration"]["digest"] = "not-a-digest"
        self.assert_invalid(value, "invalid-memory-evidence")

    def test_validation_does_not_modify_supplied_evidence(self):
        value = observation()
        old = copy.deepcopy(value)
        result = self.validate(value)
        result["configuration"]["memory_mb"] = 512
        self.assertEqual(value, old)

    def test_leaf_rotation_and_resource_generation_do_not_bypass_the_subject_lock_key(
        self,
    ):
        old = self.validate()["subject_key"]
        value, wanted = observation(), expected()
        value["host_profile"]["leaf_certificate_sha256"] = "f" * 64
        wanted["host_profile"]["leaf_certificate_sha256"] = "f" * 64
        value["tags"][2] = "cmdmesh-gen-" + "4" * 32
        wanted["generation_tag"] = value["tags"][2]
        self.assertEqual(self.validate(value, wanted)["subject_key"], old)

    def test_schema_versions_and_expected_request_are_explicit(self):
        value = observation()
        value["schema_version"] = True
        self.assert_invalid(value, "invalid-memory-evidence")
        value["schema_version"] = 2
        self.assert_invalid(value, "memory-evidence-version-unsupported")
        wanted = expected()
        wanted["source"] = {"mode": "offline"}
        with self.assertRaises(self.state.MemoryEvidenceError) as raised:
            self.validate(wanted=wanted)
        self.assertEqual(raised.exception.code, "invalid-memory-request")

    def test_host_boot_identity_is_required_and_strictly_typed(self):
        for invalid in (None, True, "", "not-a-hash"):
            value = observation()
            value["host_boot_id_sha256"] = invalid
            self.assert_invalid(value, "invalid-memory-evidence")
        value = observation()
        del value["host_boot_id_sha256"]
        self.assert_invalid(value, "invalid-memory-evidence")


if __name__ == "__main__":
    unittest.main()
