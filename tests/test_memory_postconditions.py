"""Readable failed postconditions remain evidence; identity/source loss does not."""

import copy
import unittest

from test_memory_state import expected, observation


class MemoryPostconditionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import memory_state

        cls.state = memory_state

    def prepared(self):
        return self.state.prepare(
            expected(),
            observation(),
            512,
            {"mode": "observed-available-headroom", "minimum_remaining_bytes": 0},
            now_ms=200000,
        )

    def after(self):
        value = observation()
        value["configuration"].update(memory_mb=512, digest="a" * 40)
        value["runtime"]["memory_limit_bytes"] = 512 * 1024**2
        value["observed_at_unix_ms"] = 209000
        return value

    def test_typed_identity_evidence_can_report_an_unready_memory_state(self):
        value = self.after()
        value["configuration"].update(locked=True, pending=True)
        value["runtime"]["memory_limit_bytes"] = 256 * 1024**2
        evidence = self.state.validate_evidence(value, expected(), now_ms=210000)
        self.assertEqual(evidence["configuration"]["memory_mb"], 512)
        self.assertEqual(evidence["runtime"]["memory_limit_bytes"], 256 * 1024**2)
        self.assertFalse(evidence["current_observation"])
        self.assertFalse(evidence["mutation_authorized"])
        with self.assertRaises(self.state.MemoryEvidenceError):
            self.state.validate_observation(value, expected(), now_ms=210000)

    def test_matching_postconditions_have_fixed_boolean_checks_without_live_authority(
        self,
    ):
        result = self.state.postconditions(self.prepared(), self.after(), now_ms=210000)
        self.assertTrue(result["satisfied"])
        self.assertTrue(
            all(type(value) is bool and value for value in result["checks"].values())
        )
        self.assertEqual(
            set(result["checks"]),
            {
                "host-guest-identity",
                "ownership-generation",
                "fresh-complete",
                "host-boot-continuity",
                "runtime-continuity",
                "unchanged-state",
                "configuration-ready",
                "configuration-target",
                "enforced-memory-target",
                "configuration-digest-transition",
            },
        )
        self.assertFalse(result["current_observation"])
        self.assertFalse(result["mutation_authorized"])

    def test_configured_but_unenforced_memory_retains_exact_failed_check(self):
        value = self.after()
        value["runtime"]["memory_limit_bytes"] = 256 * 1024**2
        result = self.state.postconditions(self.prepared(), value, now_ms=210000)
        self.assertFalse(result["satisfied"])
        self.assertTrue(result["checks"]["configuration-target"])
        self.assertFalse(result["checks"]["enforced-memory-target"])
        self.assertTrue(result["checks"]["ownership-generation"])

    def test_locked_pending_restarted_or_rebooted_state_has_failed_checks(self):
        changes = [
            (("configuration", "locked"), True, "configuration-ready"),
            (("configuration", "pending"), True, "configuration-ready"),
            (("runtime", "init_start_ticks"), 101, "runtime-continuity"),
            (("host_boot_id_sha256",), "a" * 64, "host-boot-continuity"),
            (("configuration", "other_sha256"), "b" * 64, "unchanged-state"),
        ]
        for path, replacement, failed in changes:
            with self.subTest(path=path):
                value = self.after()
                target = value
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = replacement
                result = self.state.postconditions(
                    self.prepared(), value, now_ms=210000
                )
                self.assertFalse(result["satisfied"])
                self.assertFalse(result["checks"][failed])

    def test_invalid_identity_owner_source_or_shape_cannot_become_observed_failed_checks(
        self,
    ):
        for path, replacement in [
            (("node",), "node-b"),
            (("tags",), ["cmdmesh-ansible"]),
            (("complete",), False),
            (("warnings",), ["private"]),
            (("observed_at_unix_ms",), 1),
            (("runtime", "memory_limit_bytes"), "512"),
        ]:
            with self.subTest(path=path):
                value = self.after()
                target = value
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = replacement
                with self.assertRaises(self.state.MemoryEvidenceError):
                    self.state.postconditions(self.prepared(), value, now_ms=210000)

    def test_all_checks_are_computed_without_mutating_evidence(self):
        value = self.after()
        value["configuration"].update(memory_mb=256, digest="d" * 40, pending=True)
        value["runtime"]["memory_limit_bytes"] = 256 * 1024**2
        before = copy.deepcopy(value)
        result = self.state.postconditions(self.prepared(), value, now_ms=210000)
        self.assertFalse(result["checks"]["configuration-target"])
        self.assertFalse(result["checks"]["enforced-memory-target"])
        self.assertFalse(result["checks"]["configuration-ready"])
        self.assertFalse(result["checks"]["configuration-digest-transition"])
        self.assertEqual(value, before)


if __name__ == "__main__":
    unittest.main()
