"""Controller and access probes use synthetic tools and disposable loopback only."""

import contextlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import signal
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = ROOT / ".generated/probe-tests"
SCRATCH.mkdir(parents=True, exist_ok=True, mode=0o700)


class InspectionProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(dir=SCRATCH)
        cls.root = Path(cls.work.name)
        cls.bundle = cls.root / "inspect.pyz"
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/build_inspector.py"),
                "--out",
                str(cls.bundle),
            ],
            check=True,
            capture_output=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)

    def tool(self, code):
        path = self.base / "tool"
        path.write_text(f"#!{sys.executable}\n" + code)
        path.chmod(0o700)
        return str(path)

    def inspect(self, operation, value, config, env=None):
        request = {
            "document_type": "cmdmesh.inspection.request",
            "schema_version": 1,
            "operation": operation,
            "input": value,
            "config": config,
        }
        result = subprocess.run(
            [str(self.bundle)],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            timeout=8,
            env=env,
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout)

    def controller(self, code="print('ansible-playbook [core 2.20.4]')"):
        config = {
            "schema_version": 1,
            "controller": {
                "scratch_root": str(self.base),
                "tools": {"ansible-playbook": self.tool(code)},
            },
        }
        value = {
            "required_tools": {
                "ansible-playbook": {"minimum": "2.19.4", "maximum_exclusive": "2.21.0"}
            },
            "minimum_free_bytes": 0,
        }
        return value, config

    def test_controller_runs_fixed_version_probe_in_isolated_private_scratch(self):
        value, config = self.controller(
            "import os,sys\nfrom pathlib import Path\n"
            "assert sys.argv[1:] == ['--version']\n"
            "assert os.environ['ANSIBLE_CONFIG'] != '/dev/null'\n"
            "assert Path(os.environ['ANSIBLE_CONFIG']).is_file()\n"
            "assert Path.cwd().stat().st_mode & 0o77 == 0\n"
            "assert 'PRIVATE_MARKER' not in os.environ\n"
            "print('ansible-playbook [core 2.20.4]')"
        )
        env = {
            **os.environ,
            "PRIVATE_MARKER": "SECRET_SYNTHETIC",
            "ANSIBLE_CONFIG": "/dev/null",
        }
        result = self.inspect("controller-diagnose", value, config, env)
        self.assertEqual(result["outcome"], "observed", result)
        self.assertEqual(
            result["data"]["tools"]["ansible-playbook"]["version"], "2.20.4"
        )
        self.assertFalse(result["data"]["remote_access_tested"])
        self.assertNotIn("SECRET_SYNTHETIC", json.dumps(result))
        self.assertEqual(sorted(path.name for path in self.base.iterdir()), ["tool"])

    def test_missing_and_unsupported_tools_are_not_certified(self):
        value, config = self.controller("print('ansible-playbook [core 2.18.0]')")
        self.assertEqual(
            self.inspect("controller-diagnose", value, config)["outcome"], "unsupported"
        )
        Path(config["controller"]["tools"]["ansible-playbook"]).unlink()
        result = self.inspect("controller-diagnose", value, config)
        self.assertEqual(
            result["diagnostics"][0]["code"], "controller-tool-unavailable"
        )

    def test_zero_exit_with_unknown_version_is_not_success(self):
        value, config = self.controller("print('SYNTHETIC_PRIVATE_RESPONSE')")
        result = self.inspect("controller-diagnose", value, config)
        self.assertEqual(result["outcome"], "unsupported")
        self.assertNotIn("SYNTHETIC_PRIVATE_RESPONSE", json.dumps(result))

    def test_each_fixed_tool_has_a_supported_version_parser_and_argument(self):
        for name, argument, output, expected in (
            ("python3", "--version", "Python 3.12.3", "3.12.3"),
            ("terraform", "version", "Terraform v1.14.2", "1.14.2"),
            ("ssh", "-V", "OpenSSH_9.6p1 Ubuntu-3ubuntu13.14, OpenSSL 3.0.13", "9.6.1"),
        ):
            stream = ",file=sys.stderr" if name == "ssh" else ""
            executable = self.tool(
                f"import sys\nassert sys.argv[1:] == [{argument!r}]\nprint({output!r}{stream})"
            )
            config = {
                "schema_version": 1,
                "controller": {
                    "scratch_root": str(self.base),
                    "tools": {name: executable},
                },
            }
            value = {
                "required_tools": {
                    name: {"minimum": "0.0.0", "maximum_exclusive": "100.0.0"}
                },
                "minimum_free_bytes": 0,
            }
            result = self.inspect("controller-diagnose", value, config)
            self.assertEqual(result["outcome"], "observed", result)
            self.assertEqual(result["data"]["tools"][name]["version"], expected)

    def test_probe_output_and_deadline_are_bounded(self):
        for code, expected in (
            ("print('x'*70000)", "probe-output-limit"),
            ("import time\ntime.sleep(30)", "probe-deadline"),
        ):
            value, config = self.controller(code)
            result = self.inspect("controller-diagnose", value, config)
            self.assertEqual(result["outcome"], "unavailable")
            self.assertEqual(result["diagnostics"][0]["code"], expected)

    def test_supervised_group_cleanup_stops_a_tool_and_its_ordinary_child(self):
        marker = self.base / "processes.json"
        code = (
            "import os,sys,json,time,subprocess\nfrom pathlib import Path\n"
            f"child=subprocess.Popen([sys.executable,'-c',{('import time;time.sleep(30) # ' + str(self.base))!r}])\n"
            "pids=[os.getpid(),child.pid]\n"
            f"Path({str(marker)!r}).write_text(json.dumps({{'pids':pids,'group':os.getpgrp(),"
            "'birth':[Path('/proc/'+str(p)+'/stat').read_text().split()[21] for p in pids]}))\n"
            "child.wait()\n"
        )
        value, config = self.controller(code)
        request = {
            "document_type": "cmdmesh.inspection.request",
            "schema_version": 1,
            "operation": "controller-diagnose",
            "input": value,
            "config": config,
        }
        process = subprocess.Popen(
            [str(self.bundle)],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env={**os.environ, "CMDMESH_INSPECTION_PROCESS_GROUP": "1"},
        )
        record = None
        try:
            process.stdin.write(json.dumps(request).encode())
            process.stdin.close()
            for _ in range(200):
                if marker.exists():
                    record = json.loads(marker.read_text())
                    break
                time.sleep(0.01)
            self.assertIsNotNone(record, "synthetic tool did not start")
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
            for _ in range(50):
                states = []
                for pid in record["pids"]:
                    try:
                        states.append(Path(f"/proc/{pid}/stat").read_text().split()[2])
                    except FileNotFoundError:
                        states.append("gone")
                if all(state in ("Z", "gone") for state in states):
                    break
                time.sleep(0.01)
            self.assertTrue(all(state in ("Z", "gone") for state in states), states)
            self.assertEqual(record["group"], process.pid)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
            if record:
                for pid, birth in zip(record["pids"], record["birth"]):
                    try:
                        state = Path(f"/proc/{pid}/stat").read_text().split()
                        command = Path(f"/proc/{pid}/cmdline").read_bytes()
                        if state[21] == birth and str(self.base).encode() in command:
                            os.killpg(os.getpgid(pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except FileNotFoundError:
                        pass

    def test_scratch_permissions_free_space_and_tool_selection_are_explicit(self):
        value, config = self.controller()
        self.base.chmod(0o755)
        self.assertEqual(
            self.inspect("controller-diagnose", value, config)["outcome"], "rejected"
        )
        self.base.chmod(0o700)
        value["minimum_free_bytes"] = 2**63 - 1
        self.assertEqual(
            self.inspect("controller-diagnose", value, config)["outcome"], "unavailable"
        )
        value["required_tools"] = {
            "shell": {"minimum": "1.0.0", "maximum_exclusive": "2.0.0"}
        }
        self.assertEqual(
            self.inspect("controller-diagnose", value, config)["outcome"], "rejected"
        )

    def test_invalid_supervision_marker_cannot_select_an_unowned_process_group(self):
        value, config = self.controller()
        result = self.inspect(
            "controller-diagnose",
            value,
            config,
            {**os.environ, "CMDMESH_INSPECTION_PROCESS_GROUP": "invalid"},
        )
        self.assertEqual(result["outcome"], "rejected", result)
        self.assertEqual(
            result["diagnostics"][0]["code"], "invalid-supervision-context"
        )

    @contextlib.contextmanager
    def tcp(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(16)
            yield listener.getsockname()[1]

    def ssh(self, port, code="print('1000')"):
        key, known = self.base / "identity", self.base / "known_hosts"
        key.write_text("SYNTHETIC_PRIVATE_KEY")
        key.chmod(0o600)
        known.write_text("SYNTHETIC_HOST_KEY")
        return {"origin": "example", "expected_uid": 1000}, {
            "schema_version": 1,
            "origin": "example",
            "controller": {"scratch_root": str(self.base)},
            "ssh": {
                "executable": self.tool(code),
                "host": "127.0.0.1",
                "port": port,
                "user": "operator",
                "identity_file": str(key),
                "known_hosts_file": str(known),
            },
        }

    def test_ssh_uses_exact_explicit_identity_without_config_agent_or_multiplexing(
        self,
    ):
        code = "import sys\na=sys.argv[1:]\n"
        code += "assert a[:2] == ['-F', 'none']\n"
        code += "assert a[-1] == 'id -u'\n"
        code += "assert all(x in a for x in ['StrictHostKeyChecking=yes','IdentitiesOnly=yes','IdentityAgent=none','CertificateFile=none','PreferredAuthentications=publickey','ForwardAgent=no','ControlMaster=no','ControlPath=none','ControlPersist=no','BatchMode=yes','GlobalKnownHostsFile=/dev/null','UpdateHostKeys=no'])\nprint('1000')"
        with self.tcp() as port:
            value, config = self.ssh(port, code)
            result = self.inspect("ssh-diagnose", value, config)
        self.assertEqual(result["outcome"], "observed", result)
        self.assertEqual(result["data"]["uid"], 1000)
        self.assertFalse(result["data"]["application_health_tested"])
        self.assertNotIn("SYNTHETIC_PRIVATE_KEY", json.dumps(result))

    def test_ssh_wrong_uid_host_key_auth_and_unknown_output_are_distinct(self):
        cases = [
            ("print('0')", "ssh-identity-mismatch"),
            (
                "import sys\nprint('Host key verification failed',file=sys.stderr)\nsys.exit(255)",
                "ssh-host-key-unverified",
            ),
            (
                "import sys\nprint('Permission denied (publickey)',file=sys.stderr)\nsys.exit(255)",
                "ssh-authentication-failed",
            ),
            (
                "print('SYNTHETIC_PRIVATE_REMOTE_OUTPUT')",
                "ssh-invalid-identity-evidence",
            ),
        ]
        for code, expected in cases:
            with self.tcp() as port:
                value, config = self.ssh(port, code)
                result = self.inspect("ssh-diagnose", value, config)
            self.assertEqual(result["diagnostics"][0]["code"], expected, result)
            self.assertNotIn("SYNTHETIC_PRIVATE_REMOTE_OUTPUT", json.dumps(result))

    def test_ssh_wrong_origin_unsafe_host_and_arbitrary_commands_stop_before_tool_execution(
        self,
    ):
        marker = self.base / "executed"
        with self.tcp() as port:
            value, config = self.ssh(
                port,
                f"from pathlib import Path\nPath({str(marker)!r}).touch()\nprint('1000')",
            )
            value["origin"] = "wrong"
            self.assertEqual(
                self.inspect("ssh-diagnose", value, config)["outcome"], "rejected"
            )
            value["origin"] = "example"
            value["command"] = "anything"
            self.assertEqual(
                self.inspect("ssh-diagnose", value, config)["outcome"], "rejected"
            )
            del value["command"]
            config["ssh"]["host"] = "-oProxyCommand=anything"
            self.assertEqual(
                self.inspect("ssh-diagnose", value, config)["outcome"], "rejected"
            )
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
