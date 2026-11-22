"""Offline comparison must reject ambiguous or insufficient observations."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "inspection_compare", ROOT / "inspection/inspection.py"
)
INSPECTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSPECTION)


def observation(timestamp=190000):
    return {
        "document_type": "cmdmesh.proxmox.observation",
        "schema_version": 1,
        "origin": "example",
        "node": "node-a",
        "observed_at_unix_ms": timestamp,
        "hostname": "node-a",
        "packages_sha256": "a" * 64,
        "protected": {"/etc/hosts": "b" * 64},
        "apt_lists": {},
        "services": {
            "pveproxy": "active",
            "pvedaemon": "active",
            "pve-cluster": "active",
        },
        "snapshot": {
            "schema_version": 1,
            "complete": True,
            "warnings": [],
            "resources": [
                {
                    "kind": "proxmox.node",
                    "id": "node-a",
                    "properties": {"status": "online", "uptime": 100},
                },
                {
                    "kind": "proxmox.lxc",
                    "id": "node-a/101",
                    "properties": {
                        "node": "node-a",
                        "vmid": 101,
                        "name": "demo",
                        "status": "running",
                        "uptime": 50,
                        "maxmem": 1024,
                    },
                },
            ],
        },
    }


def request():
    before, after = observation(), observation(199000)
    after["snapshot"]["resources"][0]["properties"]["uptime"] += 9
    after["snapshot"]["resources"][1]["properties"]["uptime"] += 9
    return {
        "document_type": "cmdmesh.inspection.request",
        "schema_version": 1,
        "operation": "observation-compare",
        "input": {"before": before, "after": after},
        "config": {},
    }


class InspectionCompareTests(unittest.TestCase):
    def inspect(self, value):
        return INSPECTION.dispatch(value, now_ms=200000)

    def test_valid_comparison_accepts_nondecreasing_uptime_without_claiming_live_authority(
        self,
    ):
        result = self.inspect(request())
        self.assertEqual(result["outcome"], "observed", result)
        self.assertEqual(result["data"]["comparison"], "matches")
        self.assertFalse(result["data"]["current_observation"])
        self.assertFalse(result["data"]["mutation_authorized"])
        self.assertEqual(result["data"]["provenance"], "caller-asserted")
        self.assertEqual(result["data"]["guests"], 1)

    def test_conflicting_duplicate_guest_cannot_disappear_in_a_dictionary(self):
        value = request()
        hidden = copy.deepcopy(value["input"]["before"]["snapshot"]["resources"][1])
        hidden["properties"]["status"] = "stopped"
        value["input"]["before"]["snapshot"]["resources"].insert(1, hidden)
        result = self.inspect(value)
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["diagnostics"][0]["code"], "duplicate-resource")

    def test_complete_zero_guest_host_is_valid_but_missing_node_is_not(self):
        value = request()
        for frame in (value["input"]["before"], value["input"]["after"]):
            frame["snapshot"]["resources"] = frame["snapshot"]["resources"][:1]
        result = self.inspect(value)
        self.assertEqual(result["outcome"], "observed", result)
        self.assertEqual(result["data"]["guests"], 0)
        value["input"]["after"]["snapshot"]["resources"] = []
        self.assertEqual(self.inspect(value)["outcome"], "rejected")

    def test_only_exact_declared_delta_passes_and_unused_or_duplicate_delta_fails(self):
        value = request()
        value["input"]["after"]["snapshot"]["resources"][1]["properties"][
            "maxmem"
        ] = 2048
        self.assertEqual(self.inspect(value)["outcome"], "rejected")
        delta = {
            "path": ["resources", "proxmox.lxc", "node-a/101", "maxmem"],
            "before": 1024,
            "after": 2048,
        }
        value["input"]["permitted_deltas"] = [delta]
        result = self.inspect(value)
        self.assertEqual(result["outcome"], "observed", result)
        self.assertEqual(result["data"]["accepted_deltas"], 1)
        for changes in (
            [{**delta, "after": 4096}],
            [delta, delta],
            [{**delta, "path": ["resources", "*"]}],
        ):
            value["input"]["permitted_deltas"] = changes
            self.assertEqual(self.inspect(value)["outcome"], "rejected")
        value = request()
        value["input"]["permitted_deltas"] = [delta]
        self.assertEqual(self.inspect(value)["outcome"], "rejected")

    def test_restart_and_membership_changes_require_exact_deltas(self):
        for change in ("restart", "remove"):
            value = request()
            old = value["input"]["before"]["snapshot"]["resources"][1]
            if change == "restart":
                value["input"]["after"]["snapshot"]["resources"][1]["properties"][
                    "uptime"
                ] = 1
                delta = {
                    "path": ["resources", old["kind"], old["id"], "uptime"],
                    "before": 50,
                    "after": 1,
                }
            else:
                value["input"]["after"]["snapshot"]["resources"].pop()
                delta = {
                    "path": ["resources", old["kind"], old["id"]],
                    "before": old["properties"],
                    "after": None,
                }
            self.assertEqual(self.inspect(value)["outcome"], "rejected")
            value["input"]["permitted_deltas"] = [delta]
            self.assertEqual(self.inspect(value)["outcome"], "observed")

    def test_incomplete_or_warned_source_cannot_verify_a_comparison(self):
        for complete, warnings in ((False, []), (True, ["SYNTHETIC_PRIVATE_RESPONSE"])):
            value = request()
            value["input"]["after"]["snapshot"].update(
                complete=complete, warnings=warnings
            )
            result = self.inspect(value)
            self.assertEqual(result["outcome"], "incomplete")
            self.assertNotIn("SYNTHETIC_PRIVATE_RESPONSE", json.dumps(result))

    def test_times_and_sources_are_required_and_ordered(self):
        for field, replacement in (
            ("origin", "other"),
            ("node", "node-b"),
            ("observed_at_unix_ms", 200001),
            ("observed_at_unix_ms", 180000),
            ("observed_at_unix_ms", 0),
        ):
            value = request()
            value["input"]["after"][field] = replacement
            self.assertIn(self.inspect(value)["outcome"], {"rejected", "incomplete"})
        value = request()
        value["input"]["max_age_seconds"] = 1
        self.assertEqual(self.inspect(value)["outcome"], "incomplete")
        value = request()
        del value["input"]["before"]["observed_at_unix_ms"]
        self.assertEqual(self.inspect(value)["outcome"], "rejected")

    def test_required_resource_evidence_and_numeric_uptime_are_strict(self):
        for field, replacement in (
            ("uptime", True),
            ("uptime", "100"),
            ("uptime", -1),
            ("status", None),
            ("name", []),
        ):
            value = request()
            value["input"]["after"]["snapshot"]["resources"][1]["properties"][
                field
            ] = replacement
            self.assertEqual(self.inspect(value)["outcome"], "rejected")
        value = request()
        del value["input"]["after"]["snapshot"]["resources"][1]["properties"]["uptime"]
        self.assertEqual(self.inspect(value)["outcome"], "rejected")

    def test_protected_change_has_exact_hashes_and_no_raw_content_in_diagnostics(self):
        value = request()
        value["input"]["after"]["protected"]["/etc/hosts"] = "c" * 64
        result = self.inspect(value)
        self.assertEqual(result["outcome"], "rejected")
        value["input"]["permitted_deltas"] = [
            {"path": ["protected", "/etc/hosts"], "before": "b" * 64, "after": "c" * 64}
        ]
        self.assertEqual(self.inspect(value)["outcome"], "observed")
        value["input"]["before"]["protected"][
            "/etc/hosts"
        ] = "SYNTHETIC_PRIVATE_CONTENT"
        self.assertNotIn("SYNTHETIC_PRIVATE_CONTENT", json.dumps(self.inspect(value)))

    def test_inactive_management_services_are_not_verified_even_when_explicitly_permitted(
        self,
    ):
        value = request()
        value["input"]["after"]["services"]["pveproxy"] = "inactive"
        value["input"]["permitted_deltas"] = [
            {"path": ["services", "pveproxy"], "before": "active", "after": "inactive"}
        ]
        self.assertEqual(self.inspect(value)["outcome"], "incomplete")

    def test_unknown_schema_fields_and_unbounded_deltas_fail(self):
        for field, replacement in (
            ("schema_version", 2),
            ("command", "SYNTHETIC_PRIVATE_COMMAND"),
        ):
            value = request()
            value["input"]["after"][field] = replacement
            result = self.inspect(value)
            self.assertIn(result["outcome"], {"rejected", "unsupported"})
            self.assertNotIn("SYNTHETIC_PRIVATE_COMMAND", json.dumps(result))

    def test_describe_exposes_comparison_and_exact_deltas(self):
        value = request()
        value["operation"], value["input"] = "describe", {}
        action = next(
            item
            for item in self.inspect(value)["data"]["actions"]
            if item["id"] == "observation-compare"
        )
        self.assertEqual(set(action["input_schema"]["required"]), {"before", "after"})
        self.assertFalse(action["input_schema"]["additionalProperties"])
        frame = action["input_schema"]["properties"]["before"]
        forms = frame["properties"]["snapshot"]["properties"]["resources"]["items"][
            "oneOf"
        ]
        for form in forms:
            properties = form["properties"]["properties"]
            self.assertIn("uptime", properties["required"])
            self.assertIn("status", properties["required"])
            self.assertEqual(properties["properties"]["uptime"]["type"], "integer")
            self.assertEqual(properties["maxProperties"], 128)
        guest = next(
            form
            for form in forms
            if "vmid" in form["properties"]["properties"]["required"]
        )
        self.assertTrue(
            {"node", "vmid", "name", "status", "uptime"}.issubset(
                guest["properties"]["properties"]["required"]
            )
        )
        self.assertEqual(
            guest["properties"]["properties"]["properties"]["vmid"]["minimum"], 100
        )


if __name__ == "__main__":
    unittest.main()
