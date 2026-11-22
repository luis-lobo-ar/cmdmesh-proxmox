"""Actual core-to-bundle qualification. Explicit core binary, no infrastructure."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = ROOT / ".generated/core-transport-tests"
SCRATCH.mkdir(parents=True, exist_ok=True, mode=0o700)


class CoreTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = os.environ.get("CMDMESH_BIN")
        if not binary:
            raise unittest.SkipTest(
                "CMDMESH_BIN is required for cross-package qualification"
            )
        cls.binary = Path(binary).resolve(strict=True)
        cls.work = tempfile.TemporaryDirectory(dir=SCRATCH)
        cls.root = Path(cls.work.name)
        cls.bundle = cls.root / "inspector.pyz"
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/build_inspector.py"),
                "--out",
                str(cls.bundle),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        cls.digest = json.loads(result.stdout)["sha256"]

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.environment = self.base / "environment.json"
        self.config = {"schema_version": 1, "origin": "example"}

    def command(self, operation, value, timeout=10):
        environment = {
            "schema_version": 1,
            "providers": {
                "native": {
                    "executable": str(self.bundle),
                    "expected_sha256": self.digest,
                    "config": self.config,
                    "env_allowlist": [],
                }
            },
        }
        self.environment.write_text(json.dumps(environment))
        self.environment.chmod(0o600)
        inputs = self.base / "input.json"
        inputs.write_text(json.dumps(value))
        inputs.chmod(0o600)
        return [
            str(self.binary),
            "--config",
            str(self.environment),
            "inspection",
            "run",
            "--inspector",
            "native",
            "--operation",
            operation,
            "--input",
            str(inputs),
            "--timeout-seconds",
            str(timeout),
        ]

    def run_action(self, operation, value):
        result = subprocess.run(
            self.command(operation, value), capture_output=True, text=True, timeout=15
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["executable_sha256"], self.digest)
        self.assertEqual(receipt["result"]["operation"], operation)
        return result.returncode, receipt["result"]

    def test_actual_describe_offline_target_and_unsupported_action(self):
        code, result = self.run_action("describe", {})
        self.assertEqual(code, 0, result)
        self.assertEqual(
            {item["id"] for item in result["data"]["actions"]},
            {
                "target-resolve",
                "observation-compare",
                "controller-diagnose",
                "ssh-diagnose",
                "tls-diagnose",
            },
        )
        request = json.loads(
            (ROOT / "examples/inspection/resolve-offline.json").read_text()
        )
        code, result = self.run_action("target-resolve", request["input"])
        self.assertEqual(code, 0, result)
        self.assertEqual(result["data"]["resolution"], "resolved")
        self.assertFalse(result["data"]["current_observation"])
        code, result = self.run_action("repair", {})
        self.assertEqual(code, 1)
        self.assertEqual(result["outcome"], "unsupported")

    def test_actual_comparison_preserves_negative_outcome_and_diagnostics(self):
        example = subprocess.run(
            [sys.executable, str(ROOT / "examples/inspection/compare.py")],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        value = json.loads(example.stdout)["input"]
        code, result = self.run_action("observation-compare", value)
        self.assertEqual(code, 0, result)
        self.assertEqual(result["data"]["accepted_deltas"], 1)
        value["permitted_deltas"] = []
        code, result = self.run_action("observation-compare", value)
        self.assertEqual(code, 1)
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["diagnostics"][0]["code"], "unexpected-delta")

    def test_core_timeout_cancellation_and_completion_stop_ordinary_descendants(self):
        for scenario in ("timeout", "cancel", "complete"):
            with self.subTest(scenario=scenario):
                marker = self.base / (scenario + ".json")
                tool = self.base / (scenario + ".py")
                sleep_code = f"import time;time.sleep(30) # {self.base}"
                code = (
                    f"#!{sys.executable}\nimport os,sys,json,time,subprocess\nfrom pathlib import Path\n"
                    f"child=subprocess.Popen([sys.executable,'-c',{sleep_code!r}])\n"
                    "pids=[os.getpid(),child.pid]\n"
                    f"Path({str(marker)!r}).write_text(json.dumps({{'pids':pids,'group':os.getpgrp(),'parent':os.getppid(),"
                    "'birth':[Path('/proc/'+str(p)+'/stat').read_text().split()[21] for p in pids]}))\n"
                )
                code += (
                    "print('Python 3.12.3')\n"
                    if scenario == "complete"
                    else "child.wait()\n"
                )
                tool.write_text(code)
                tool.chmod(0o700)
                self.config["controller"] = {
                    "scratch_root": str(self.base),
                    "tools": {"python3": str(tool)},
                }
                value = {
                    "required_tools": {
                        "python3": {"minimum": "3.12.0", "maximum_exclusive": "3.13.0"}
                    },
                    "minimum_free_bytes": 0,
                }
                command = self.command(
                    "controller-diagnose", value, 2 if scenario == "timeout" else 10
                )
                process = subprocess.Popen(
                    command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                record = None
                try:
                    for _ in range(200):
                        if marker.exists():
                            record = json.loads(marker.read_text())
                            break
                        time.sleep(0.01)
                    self.assertIsNotNone(record, "synthetic tool did not start")
                    if scenario == "cancel":
                        process.send_signal(signal.SIGTERM)
                    output, error = process.communicate(timeout=5)
                    self.assertEqual(
                        process.returncode,
                        0 if scenario == "complete" else 1,
                        error.decode(),
                    )
                    if scenario == "complete":
                        self.assertEqual(
                            json.loads(output)["result"]["outcome"], "observed"
                        )
                    else:
                        self.assertFalse(output)
                    self.assertEqual(record["group"], record["parent"])
                    for _ in range(50):
                        states = []
                        for pid in record["pids"]:
                            try:
                                states.append(
                                    Path(f"/proc/{pid}/stat").read_text().split()[2]
                                )
                            except FileNotFoundError:
                                states.append("gone")
                        if all(state in ("Z", "gone") for state in states):
                            break
                        time.sleep(0.01)
                    self.assertTrue(
                        all(state in ("Z", "gone") for state in states), states
                    )
                finally:
                    if process.poll() is None:
                        process.send_signal(signal.SIGTERM)
                        try:
                            process.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=3)
                    process.stdout.close()
                    process.stderr.close()
                    if record:
                        for pid, birth in zip(record["pids"], record["birth"]):
                            try:
                                state = Path(f"/proc/{pid}/stat").read_text().split()
                                command_line = Path(f"/proc/{pid}/cmdline").read_bytes()
                                if (
                                    state[21] == birth
                                    and str(self.base).encode() in command_line
                                ):
                                    os.killpg(os.getpgid(pid), signal.SIGKILL)
                            except (ProcessLookupError, FileNotFoundError):
                                pass


if __name__ == "__main__":
    unittest.main()
