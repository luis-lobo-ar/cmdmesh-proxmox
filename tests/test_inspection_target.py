"""Typed target matching is useful offline without claiming live verification."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "inspection", ROOT / "inspection/inspection.py"
)
INSPECTION = importlib.util.module_from_spec(SPEC)


def snapshot():
    return {
        "schema_version": 1,
        "complete": True,
        "warnings": [],
        "resources": [
            {
                "kind": "proxmox.node",
                "id": "node-a",
                "properties": {"status": "online"},
            },
            {
                "kind": "proxmox.node",
                "id": "node-b",
                "properties": {"status": "online"},
            },
            {
                "kind": "proxmox.lxc",
                "id": "node-a/101",
                "properties": {
                    "node": "node-a",
                    "vmid": 101,
                    "name": "demo",
                    "status": "running",
                },
            },
            {
                "kind": "proxmox.vm",
                "id": "node-a/101",
                "properties": {
                    "node": "node-a",
                    "vmid": 101,
                    "name": "other-kind",
                    "status": "stopped",
                },
            },
            {
                "kind": "proxmox.lxc",
                "id": "node-b/101",
                "properties": {
                    "node": "node-b",
                    "vmid": 101,
                    "name": "other-node",
                    "status": "running",
                },
            },
        ],
    }


def request():
    return {
        "document_type": "cmdmesh.inspection.request",
        "schema_version": 1,
        "operation": "target-resolve",
        "input": {
            "source": {"mode": "offline", "origin": "example", "snapshot": snapshot()},
            "selector": {
                "origin": "example",
                "node": "node-a",
                "kind": "proxmox.lxc",
                "vmid": 101,
            },
        },
        "config": {},
    }


class InspectionTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        SPEC.loader.exec_module(INSPECTION)

    def inspect(self, value):
        return INSPECTION.dispatch(value, now_ms=200000)

    def test_exact_identity_does_not_cross_origins_nodes_or_kinds(self):
        result = self.inspect(request())
        self.assertEqual(result["outcome"], "observed")
        self.assertEqual(result["data"]["resolution"], "resolved")
        self.assertEqual(
            result["data"]["identity"],
            {"origin": "example", "node": "node-a", "kind": "proxmox.lxc", "vmid": 101},
        )
        self.assertEqual(result["data"]["source"]["mode"], "offline")
        self.assertEqual(
            result["data"]["source"]["collection_scope"], "caller-supplied-snapshot"
        )
        self.assertFalse(result["data"]["source"]["visibility_qualified"])
        self.assertFalse(result["data"]["current_observation"])
        self.assertFalse(result["data"]["mutation_authorized"])
        other = request()
        other["input"]["selector"]["origin"] = "other"
        result = self.inspect(other)
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["diagnostics"][0]["code"], "origin-mismatch")

    def test_partial_and_warned_snapshots_cannot_resolve_a_current_target(self):
        for complete, warnings in (
            (False, []),
            (True, ["private warning SYNTHETIC_ONLY"]),
        ):
            value = request()
            value["input"]["source"]["snapshot"].update(
                complete=complete, warnings=warnings
            )
            result = self.inspect(value)
            self.assertEqual(result["outcome"], "incomplete")
            self.assertEqual(result["data"]["resolution"], "indeterminate")
            self.assertFalse(result["data"]["current_observation"])
            self.assertNotIn("SYNTHETIC_ONLY", json.dumps(result))

    def test_duplicate_and_inconsistent_guest_evidence_is_rejected(self):
        duplicate = snapshot()
        duplicate["resources"].append(copy.deepcopy(duplicate["resources"][2]))
        wrong_node = snapshot()
        wrong_node["resources"][2]["properties"]["node"] = "node-b"
        wrong_id = snapshot()
        wrong_id["resources"][2]["properties"]["vmid"] = True
        for data in (duplicate, wrong_node, wrong_id):
            value = request()
            value["input"]["source"]["snapshot"] = data
            self.assertEqual(self.inspect(value)["outcome"], "rejected")

    def test_node_resolution_and_empty_complete_scope_are_explicit(self):
        value = request()
        value["input"]["selector"] = {
            "origin": "example",
            "node": "node-a",
            "kind": "proxmox.node",
        }
        self.assertEqual(
            self.inspect(value)["data"]["identity"], value["input"]["selector"]
        )
        value["input"]["source"]["snapshot"]["resources"] = []
        result = self.inspect(value)
        self.assertEqual(result["data"]["resolution"], "absent")
        self.assertFalse(result["data"]["current_observation"])

    def test_offline_timestamp_does_not_become_trusted_live_evidence(self):
        for timestamp, expected in (
            (199000, "reported-recent"),
            (100000, "stale"),
            (201000, "invalid"),
        ):
            value = request()
            value["input"]["source"]["observed_at_unix_ms"] = timestamp
            value["input"]["max_age_seconds"] = 10
            result = self.inspect(value)
            self.assertEqual(result["data"]["freshness"]["status"], expected)
            self.assertFalse(result["data"]["current_observation"])

    def test_unknown_version_action_fields_and_unscoped_selectors_fail(self):
        examples = []
        value = request()
        value["schema_version"] = 2
        examples.append(value)
        value = request()
        value["operation"] = "repair"
        examples.append(value)
        value = request()
        value["input"]["command"] = "SYNTHETIC_ONLY"
        examples.append(value)
        value = request()
        del value["input"]["selector"]["node"]
        examples.append(value)
        value = request()
        value["input"]["selector"]["vmid"] = True
        examples.append(value)
        value = request()
        value["input"]["source"]["mode"] = "trusted-live-file"
        examples.append(value)
        for value in examples:
            result = self.inspect(value)
            self.assertIn(result["outcome"], {"rejected", "unsupported"})
            self.assertNotIn("SYNTHETIC_ONLY", json.dumps(result))

    def test_origin_mismatch_explains_which_private_fields_to_check(self):
        value = request()
        value["input"]["selector"]["origin"] = "other"
        diagnostic = self.inspect(value)["diagnostics"][0]
        self.assertIn("selector.origin", " ".join(diagnostic["next_checks"]))
        self.assertIn("config.origin", " ".join(diagnostic["next_checks"]))
        self.assertTrue(diagnostic["recovery"])

    def test_describe_supplies_typed_request_fields_without_contacting_a_provider(self):
        value = request()
        value["operation"], value["input"] = "describe", {}
        action = self.inspect(value)["data"]["actions"][0]
        schema = action["input_schema"]
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), {"source", "selector"})
        forms = schema["properties"]["selector"]["oneOf"]
        guest = next(form for form in forms if "vmid" in form["required"])
        self.assertEqual(guest["properties"]["vmid"]["type"], "integer")
        self.assertEqual(guest["properties"]["vmid"]["minimum"], 100)


if __name__ == "__main__":
    unittest.main()
