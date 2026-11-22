#!/usr/bin/env python3
"""Emit synthetic current comparison input. Does not inspect or change a host."""
import copy
import json
import time

now = time.time_ns() // 1_000_000
before = {
    "document_type": "cmdmesh.proxmox.observation",
    "schema_version": 1,
    "origin": "example",
    "node": "node-a",
    "observed_at_unix_ms": now - 1000,
    "hostname": "node-a",
    "packages_sha256": "a" * 64,
    "protected": {"/etc/hosts": "b" * 64},
    "apt_lists": {},
    "services": {"pveproxy": "active", "pvedaemon": "active", "pve-cluster": "active"},
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
after = copy.deepcopy(before)
after["observed_at_unix_ms"] = now
after["snapshot"]["resources"][1]["properties"]["maxmem"] = 2048
print(
    json.dumps(
        {
            "document_type": "cmdmesh.inspection.request",
            "schema_version": 1,
            "operation": "observation-compare",
            "config": {},
            "input": {
                "before": before,
                "after": after,
                "permitted_deltas": [
                    {
                        "path": ["resources", "proxmox.lxc", "node-a/101", "maxmem"],
                        "before": 1024,
                        "after": 2048,
                    }
                ],
            },
        }
    )
)
