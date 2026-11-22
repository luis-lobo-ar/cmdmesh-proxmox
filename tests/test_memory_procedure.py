"""Prepared memory intent freezes state; fresh checks prove only exact deltas."""

import copy
from pathlib import Path
import sys
import unittest

from test_memory_state import expected, observation

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(
    0, str(ROOT / "ansible/ansible_collections/cmdmesh/proxmox/plugins/module_utils")
)


class MemoryProcedureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import memory_state

        cls.state = memory_state

    def prepare(self, before=None, desired=512, policy=None):
        return self.state.prepare(
            expected(),
            before or observation(),
            desired,
            (
                policy
                if policy is not None
                else {
                    "mode": "observed-available-headroom",
                    "minimum_remaining_bytes": 1024**3,
                }
            ),
            now_ms=200000,
        )

    def after(self):
        value = observation()
        value["observed_at_unix_ms"] = 209000
        value["configuration"].update(memory_mb=512, digest="a" * 40)
        value["runtime"]["memory_limit_bytes"] = 512 * 1024**2
        return value

    def assert_fails(self, function, *args, code=None, **kwargs):
        with self.assertRaises(self.state.MemoryEvidenceError) as raised:
            function(*args, **kwargs)
        if code:
            self.assertEqual(raised.exception.code, code)

    def test_prepared_intent_freezes_request_baseline_desired_and_policy(self):
        before, wanted = observation(), expected()
        prepared = self.state.prepare(
            wanted,
            before,
            512,
            {"mode": "observed-available-headroom", "minimum_remaining_bytes": 0},
            now_ms=200000,
        )
        self.assertEqual(
            prepared["document_type"], "cmdmesh.proxmox.lxc-memory.prepared"
        )
        self.assertEqual(prepared["desired_memory_mb"], 512)
        self.assertEqual(prepared["baseline"], before)
        self.assertEqual(prepared["request"], wanted)
        self.assertEqual(len(prepared["subject_key"]), 64)
        prepared["baseline"]["configuration"]["memory_mb"] = 1024
        self.assertEqual(before["configuration"]["memory_mb"], 256)

    def test_invalid_policy_shrink_and_untyped_memory_fail(self):
        for desired in (True, "512", 0, 128, 2**31):
            self.assert_fails(self.prepare, desired=desired)
        for policy in (
            {},
            {"mode": "reserve-all", "minimum_remaining_bytes": 0},
            {"mode": "observed-available-headroom", "minimum_remaining_bytes": True},
            {"mode": "observed-available-headroom", "minimum_remaining_bytes": -1},
            {
                "mode": "observed-available-headroom",
                "minimum_remaining_bytes": 0,
                "ignore": True,
            },
        ):
            self.assert_fails(self.prepare, policy=policy)

    def test_already_desired_memory_is_an_unchanged_result_without_headroom_reservation(
        self,
    ):
        before = observation()
        before["host_capacity"]["available_bytes"] = 0
        prepared = self.prepare(before, desired=256)
        self.assertFalse(prepared["change_required"])
        fresh = copy.deepcopy(before)
        fresh["observed_at_unix_ms"] = 209000
        self.assertFalse(
            self.state.preflight(prepared, fresh, now_ms=210000)["change_required"]
        )
        result = self.state.verify(prepared, fresh, now_ms=210000)
        self.assertFalse(result["change_required"])
        self.assertTrue(all(result["checks"].values()))

    def test_capacity_uses_exact_growth_plus_private_remaining_bytes(self):
        before = observation()
        before["host_capacity"]["available_bytes"] = 256 * 1024**2 + 1024**3
        prepared = self.prepare(before)
        self.assertEqual(prepared["desired_memory_mb"], 512)
        before["host_capacity"]["available_bytes"] -= 1
        self.assert_fails(self.prepare, before, code="memory-capacity-insufficient")
        self.assert_fails(
            self.state.preflight,
            prepared,
            before,
            now_ms=200000,
            code="memory-capacity-insufficient",
        )

    def test_preflight_rejects_configuration_ownership_runtime_boot_and_host_drift(
        self,
    ):
        prepared = self.prepare()
        changes = [
            (("configuration", "digest"), "b" * 40),
            (("configuration", "other_sha256"), "b" * 64),
            (("configuration", "swap_mb"), 1),
            (("runtime", "init_start_ticks"), 101),
            (("runtime", "pid_namespace_inode"), 201),
            (("host_boot_id_sha256",), "a" * 64),
            (("host_capacity", "total_bytes"), 17 * 1024**3),
            (("tags",), ["cmdmesh-ansible"]),
        ]
        for path, replacement in changes:
            with self.subTest(path=path):
                fresh = observation()
                target = fresh
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = replacement
                self.assert_fails(self.state.preflight, prepared, fresh, now_ms=200000)

    def test_preflight_requires_fresh_complete_state_but_preserves_old_approved_baseline(
        self,
    ):
        prepared = self.prepare()
        fresh = observation()
        fresh["observed_at_unix_ms"] = 299000
        result = self.state.preflight(prepared, fresh, now_ms=300000)
        self.assertTrue(all(result["checks"].values()))
        self.assertFalse(result["current_observation"])
        self.assertFalse(result["mutation_authorized"])
        self.assert_fails(self.state.preflight, prepared, observation(), now_ms=300000)

    def test_postchecks_require_actual_config_and_enforcement_not_command_success(self):
        prepared = self.prepare()
        result = self.state.verify(prepared, self.after(), now_ms=210000)
        self.assertTrue(all(result["checks"].values()))
        self.assertEqual(result["phase"], "verify")
        self.assertFalse(result["mutation_authorized"])
        unchanged = observation()
        unchanged["observed_at_unix_ms"] = 209000
        self.assert_fails(
            self.state.verify,
            prepared,
            unchanged,
            now_ms=210000,
            code="memory-postcondition-failed",
        )
        unenforced = self.after()
        unenforced["runtime"]["memory_limit_bytes"] = 256 * 1024**2
        self.assert_fails(self.state.verify, prepared, unenforced, now_ms=210000)

    def test_postchecks_reject_restart_boot_change_unrelated_change_and_reused_digest(
        self,
    ):
        prepared = self.prepare()
        for path, replacement in [
            (("host_boot_id_sha256",), "a" * 64),
            (("runtime", "init_start_ticks"), 101),
            (("runtime", "pid_namespace_inode"), 201),
            (("configuration", "other_sha256"), "b" * 64),
            (("configuration", "swap_mb"), 1),
            (("configuration", "digest"), "d" * 40),
        ]:
            with self.subTest(path=path):
                fresh = self.after()
                target = fresh
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = replacement
                self.assert_fails(self.state.verify, prepared, fresh, now_ms=210000)

    def test_postcheck_does_not_require_volatile_free_memory_to_stay_equal(self):
        fresh = self.after()
        fresh["host_capacity"]["available_bytes"] = 0
        self.assertTrue(
            all(
                self.state.verify(self.prepare(), fresh, now_ms=210000)[
                    "checks"
                ].values()
            )
        )

    def test_prepared_contract_revalidates_all_bound_fields(self):
        for path, replacement in [
            (("schema_version",), True),
            (("subject_key",), "0" * 64),
            (("request", "selector", "vmid"), 102),
            (("baseline", "runtime", "memory_limit_bytes"), 0),
            (("extra",), True),
        ]:
            with self.subTest(path=path):
                prepared = self.prepare()
                target = prepared
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = replacement
                self.assert_fails(
                    self.state.preflight, prepared, observation(), now_ms=200000
                )


if __name__ == "__main__":
    unittest.main()
