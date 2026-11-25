"""Command declaration and successful execution are separate typed facts."""

import copy
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    systemd_exec as execution,
)


def body():
    return {
        "type": "a(sasbttttuii)",
        "data": [
            [
                "/usr/bin/python3",
                ["/usr/bin/python3", "-I", "/opt/reference/guard.py"],
                False,
                100000000,
                1000000,
                101000000,
                2000000,
                234,
                1,
                0,
            ]
        ],
    }


class SystemdExecTests(unittest.TestCase):
    def test_preserves_every_typed_command_field(self):
        actual = execution.decode_commands(execution.state.canonical(body()))
        self.assertEqual(
            actual,
            [
                {
                    "path": "/usr/bin/python3",
                    "argv": ["/usr/bin/python3", "-I", "/opt/reference/guard.py"],
                    "ignore_errors": False,
                    "start_real_us": 100000000,
                    "start_monotonic_us": 1000000,
                    "stop_real_us": 101000000,
                    "stop_monotonic_us": 2000000,
                    "pid": 234,
                    "code": 1,
                    "status": 0,
                }
            ],
        )
        self.assertEqual(
            execution.decode_commands(b'{"type":"a(sasbttttuii)","data":[]}'), []
        )

    def test_invalid_shape_types_and_ranges_refuse(self):
        for index, invalid in (
            (0, "relative"),
            (1, []),
            (1, ["x\0"]),
            (2, 0),
            (3, True),
            (4, -1),
            (5, 2**64),
            (7, 2**32),
            (8, -1),
            (9, 256),
        ):
            value = body()
            value["data"][0][index] = invalid
            with self.assertRaises(execution.state.PersistenceError):
                execution.decode_commands(execution.state.canonical(value))
        for value in (
            {"type": "other", "data": []},
            {**body(), "extra": True},
            {"type": "a(sasbttttuii)", "data": [[]]},
        ):
            with self.assertRaises(execution.state.PersistenceError):
                execution.decode_commands(execution.state.canonical(value))

    def test_declared_command_is_not_execution_success(self):
        commands = execution.decode_commands(execution.state.canonical(body()))
        argv = commands[0]["argv"]
        execution.require_success(commands, argv, 99, 102)
        for fault in (
            "never",
            "ignored",
            "failed",
            "wrong-args",
            "extra-command",
            "stale-time",
        ):
            bad = copy.deepcopy(commands)
            if fault == "never":
                for key in (
                    "pid",
                    "code",
                    "status",
                    "start_real_us",
                    "stop_real_us",
                    "start_monotonic_us",
                    "stop_monotonic_us",
                ):
                    bad[0][key] = 0
            elif fault == "ignored":
                bad[0]["ignore_errors"] = True
            elif fault == "failed":
                bad[0]["status"] = 1
            elif fault == "wrong-args":
                bad[0]["argv"].append("--skip-checks")
            elif fault == "extra-command":
                bad.append(copy.deepcopy(bad[0]))
            else:
                bad[0]["start_real_us"] = 1000
            with self.assertRaises(execution.state.PersistenceError):
                execution.require_success(bad, argv, 99, 102)

    def test_read_uses_exact_typed_property_and_safe_encoded_unit_path(self):
        with mock.patch.object(
            execution.observe, "native", return_value=execution.state.canonical(body())
        ) as native:
            result = execution.commands("pve-container@102.service")
        self.assertEqual(result[0]["pid"], 234)
        native.assert_called_once_with(
            [
                "/usr/bin/busctl",
                "--json=short",
                "get-property",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1/unit/pve_2dcontainer_40102_2eservice",
                "org.freedesktop.systemd1.Service",
                "ExecStartPre",
            ]
        )
        with mock.patch.object(execution.observe, "native") as native:
            for invalid in (
                "../x.service",
                "x.service\n",
                "--x.service",
                "x.timer",
                None,
            ):
                with self.assertRaises(execution.state.PersistenceError):
                    execution.commands(invalid)
            native.assert_not_called()


if __name__ == "__main__":
    unittest.main()
