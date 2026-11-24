"""The Ansible boundary cannot dispatch a backup from check or disabled mode."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
MODULE = (
    ROOT
    / "ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence.py"
)


class DriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("persistence_driver", MODULE)
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def frozen(self):
        return {
            "document_type": "test-prepared",
            "request": {"source": "metadata"},
            "observation_sha256": "a" * 64,
        }

    def test_inspect_does_not_mutate_in_either_mode(self):
        for check in (True, False):
            with mock.patch.object(
                self.driver.observe,
                "observe",
                return_value={"quiesced": False, "backup_verified": False},
            ) as inspect, mock.patch.object(
                self.driver.backup, "execute_backup"
            ) as execute:
                result = self.driver.execute(
                    "inspect", source_request={"example": "request"}, check_mode=check
                )
            inspect.assert_called_once_with({"example": "request"})
            execute.assert_not_called()
            self.assertFalse(result["changed"])
            self.assertFalse(result["mutation_attempted"])

    def test_prepare_returns_exact_canonical_bytes_and_hash(self):
        frozen = self.frozen()
        with mock.patch.object(
            self.driver.backup, "prepare_backup", return_value=frozen
        ) as prepare, mock.patch.object(
            self.driver.backup, "execute_backup"
        ) as execute:
            result = self.driver.execute(
                "prepare_backup", backup_request={"request": "example"}
            )
        prepare.assert_called_once_with({"request": "example"})
        execute.assert_not_called()
        raw = self.driver.state.canonical(frozen)
        self.assertEqual(result["prepared_json"].encode(), raw)
        self.assertEqual(result["prepared_sha256"], self.driver.state.sha256(raw))
        self.assertFalse(result["changed"])

    def test_check_mode_preflights_without_runtime_or_backup_dispatch(self):
        frozen = self.frozen()
        raw = self.driver.state.canonical(frozen).decode()
        trusted = self.driver.state.sha256(raw.encode())
        with mock.patch.object(
            self.driver.backup, "load_prepared", return_value=frozen
        ), mock.patch.object(
            self.driver.backup, "prepare_backup", return_value=frozen
        ) as prepare, mock.patch.object(
            self.driver.backup, "execute_backup"
        ) as execute:
            result = self.driver.execute(
                "backup", prepared_json=raw, prepared_sha256=trusted, check_mode=True
            )
        prepare.assert_called_once_with(frozen["request"])
        execute.assert_not_called()
        self.assertTrue(result["changed"] and result["would_change"])
        self.assertFalse(result["mutation_attempted"] or result["backup_verified"])
        self.assertEqual(result["assessment"], "source-preflight-only")

    def test_disabled_backup_never_calls_prepare_or_execute(self):
        with mock.patch.object(
            self.driver.backup, "load_prepared", return_value=self.frozen()
        ), mock.patch.object(
            self.driver.backup, "prepare_backup"
        ) as prepare, mock.patch.object(
            self.driver.backup, "execute_backup"
        ) as execute:
            with self.assertRaisesRegex(
                self.driver.state.PersistenceError, "change-disabled"
            ):
                self.driver.execute(
                    "backup", prepared_json="{}", prepared_sha256="a" * 64
                )
        prepare.assert_not_called()
        execute.assert_not_called()

    def test_changed_check_observation_refuses(self):
        frozen = self.frozen()
        changed = copy.deepcopy(frozen)
        changed["observation_sha256"] = "b" * 64
        with mock.patch.object(
            self.driver.backup, "load_prepared", return_value=frozen
        ), mock.patch.object(
            self.driver.backup, "prepare_backup", return_value=changed
        ), mock.patch.object(
            self.driver.backup, "execute_backup"
        ) as execute:
            with self.assertRaisesRegex(
                self.driver.state.PersistenceError, "source-changed"
            ):
                self.driver.execute(
                    "backup",
                    prepared_json="{}",
                    prepared_sha256="a" * 64,
                    check_mode=True,
                )
        execute.assert_not_called()

    def test_actual_backup_forwards_exact_frozen_bytes(self):
        frozen = self.frozen()
        raw = self.driver.state.canonical(frozen).decode()
        trusted = self.driver.state.sha256(raw.encode())
        with mock.patch.object(
            self.driver.backup, "load_prepared", return_value=frozen
        ), mock.patch.object(
            self.driver.backup,
            "execute_backup",
            return_value={"backup_verified": True, "manifest_sha256": "b" * 64},
        ) as execute:
            result = self.driver.execute(
                "backup", prepared_json=raw, prepared_sha256=trusted, allow_changes=True
            )
        execute.assert_called_once_with(raw.encode(), trusted)
        self.assertTrue(
            result["changed"]
            and result["mutation_attempted"]
            and result["backup_verified"]
        )

    def test_failure_response_is_sanitised_and_conservative(self):
        error = OSError("sensitive-example-not-for-output")
        for check, allow, expected in (
            (False, True, True),
            (True, True, False),
            (False, False, False),
        ):
            result = self.driver.failure(error, "backup", check, allow)
            self.assertNotIn("sensitive-example", json.dumps(result))
            self.assertEqual(result["effects_may_exist"], expected)
            self.assertFalse(result["backup_verified"])

    @unittest.skipUnless(shutil.which("ansible-playbook"), "requires Ansible")
    def test_actual_ansible_argument_boundary_rejects_unknown_action(self):
        scratch = ROOT / ".generated"
        scratch.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(
            dir=scratch, prefix="persistence-module-"
        ) as work:
            env = {
                **os.environ,
                "PYTHONPATH": str(ROOT / "ansible"),
                "TMPDIR": work,
                "ANSIBLE_LOCAL_TEMP": work,
            }
            result = subprocess.run(
                [sys.executable, str(MODULE)],
                input=json.dumps(
                    {
                        "ANSIBLE_MODULE_ARGS": {
                            "action": "unknown",
                            "source_request": {
                                "private_marker": "INPUT_PRIVATE_SENTINEL"
                            },
                        }
                    }
                ).encode(),
                capture_output=True,
                env=env,
                timeout=20,
            )
        self.assertNotEqual(result.returncode, 0)
        body = json.loads(result.stdout)
        self.assertTrue(body["failed"])
        self.assertIn("action", body["msg"])
        self.assertNotIn("INPUT_PRIVATE_SENTINEL", result.stdout.decode())

    @unittest.skipUnless(shutil.which("ansible-playbook"), "requires Ansible")
    def test_real_ansible_traceback_cannot_echo_runtime_exception_text(self):
        program = """import builtins,importlib.util,sys
from pathlib import Path
from ansible.module_utils import basic
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'ansible'))
basic._ANSIBLE_PROFILE='legacy';basic._ANSIBLE_ARGS=sys.stdin.buffer.read()
path=root/'ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence.py'
spec=importlib.util.spec_from_file_location('actual_driver',path);driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
def failed(unused):raise getattr(builtins,sys.argv[2])('RUNTIME_PRIVATE_SENTINEL')
driver.observe.observe=failed;driver.main()
"""
        body = {
            "ANSIBLE_MODULE_ARGS": {
                "action": "inspect",
                "source_request": {},
                "_ansible_tracebacks_for": ["error"],
            }
        }
        for kind in ("OSError", "RuntimeError", "TypeError"):
            with self.subTest(kind=kind):
                result = subprocess.run(
                    [sys.executable, "-B", "-c", program, str(ROOT), kind],
                    input=json.dumps(body).encode(),
                    capture_output=True,
                    timeout=20,
                )
                self.assertNotEqual(result.returncode, 0)
                actual = json.loads(result.stdout)
                self.assertFalse(actual["mutation_attempted"])
                self.assertNotIn(
                    "RUNTIME_PRIVATE_SENTINEL",
                    result.stdout.decode() + result.stderr.decode(),
                )

    @unittest.skipUnless(shutil.which("ansible-playbook"), "requires Ansible")
    def test_real_ansible_failure_withholds_input_invocation(self):
        body = {
            "ANSIBLE_MODULE_ARGS": {
                "action": "inspect",
                "source_request": {
                    "reference_guard": {
                        "path": "/nonexistent-reference-guard",
                        "sha256": "a" * 64,
                    },
                    "private_marker": "INPUT_PRIVATE_SENTINEL",
                },
                "_ansible_tracebacks_for": ["error"],
            }
        }
        result = subprocess.run(
            [sys.executable, "-B", str(MODULE)],
            input=json.dumps(body).encode(),
            capture_output=True,
            env={**os.environ, "PYTHONPATH": str(ROOT / "ansible")},
            timeout=20,
        )
        self.assertNotEqual(result.returncode, 0)
        actual = json.loads(result.stdout)
        self.assertEqual(actual["error_code"], "persistence-guard-unsupported")
        self.assertEqual(
            actual["invocation"]["module_args"]["source_request"], "withheld"
        )
        self.assertNotIn("INPUT_PRIVATE_SENTINEL", result.stdout.decode())

    @unittest.skipUnless(shutil.which("ansible-playbook"), "requires Ansible")
    def test_real_ansible_keeps_safe_prepared_hashes_uncensored(self):
        program = """import importlib.util,sys
from pathlib import Path
from ansible.module_utils import basic
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'ansible'))
basic._ANSIBLE_PROFILE='legacy';basic._ANSIBLE_ARGS=sys.stdin.buffer.read()
path=root/'ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence.py'
spec=importlib.util.spec_from_file_location('actual_driver',path);driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
driver.backup.prepare_backup=lambda request:{'document_type':'test-prepared','request':request}
driver.main()
"""
        request = {"safe_hash": "e" * 64}
        body = {
            "ANSIBLE_MODULE_ARGS": {
                "action": "prepare_backup",
                "backup_request": request,
            }
        }
        result = subprocess.run(
            [sys.executable, "-B", "-c", program, str(ROOT)],
            input=json.dumps(body).encode(),
            capture_output=True,
            timeout=20,
        )
        self.assertEqual(
            result.returncode, 0, result.stdout.decode() + result.stderr.decode()
        )
        actual = json.loads(result.stdout)
        expected = self.driver.state.canonical(
            {"document_type": "test-prepared", "request": request}
        )
        self.assertEqual(actual["prepared_json"].encode(), expected)
        self.assertEqual(actual["prepared_sha256"], self.driver.state.sha256(expected))
        self.assertEqual(
            actual["invocation"]["module_args"]["backup_request"], "withheld"
        )

    @unittest.skipUnless(shutil.which("ansible-playbook"), "requires Ansible")
    def test_actual_ansible_packages_the_helpers_and_refuses_before_file_access(self):
        scratch = ROOT / ".generated"
        scratch.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(
            dir=scratch, prefix="persistence-playbook-"
        ) as work:
            path = Path(work)
            for name in ("local", "remote", "tmp"):
                (path / name).mkdir(mode=0o700)
            play = [
                {
                    "hosts": "all",
                    "gather_facts": False,
                    "tasks": [
                        {
                            "name": "Refuse an unsupported guard without accessing its path",
                            "cmdmesh.proxmox.lxc_persistence": {
                                "action": "inspect",
                                "source_request": {
                                    "reference_guard": {
                                        "path": "/nonexistent-reference-guard",
                                        "sha256": "a" * 64,
                                    }
                                },
                            },
                            "check_mode": True,
                            "register": "probe",
                            "failed_when": False,
                        },
                        {
                            "name": "Check the packaged module response",
                            "ansible.builtin.assert": {
                                "that": [
                                    "probe.error_code == 'persistence-guard-unsupported'",
                                    "not probe.changed",
                                    "not probe.backup_verified",
                                    "not probe.mutation_attempted",
                                ]
                            },
                        },
                    ],
                }
            ]
            target = path / "playbook.json"
            target.write_text(json.dumps(play))
            env = {
                **os.environ,
                "ANSIBLE_COLLECTIONS_PATH": str(ROOT / "ansible/ansible_collections"),
                "ANSIBLE_LOCAL_TEMP": str(path / "local"),
                "ANSIBLE_REMOTE_TEMP": str(path / "remote"),
                "TMPDIR": str(path / "tmp"),
                "ANSIBLE_PYTHON_INTERPRETER": sys.executable,
            }
            result = subprocess.run(
                [
                    shutil.which("ansible-playbook"),
                    "-i",
                    "localhost,",
                    "-c",
                    "local",
                    str(target),
                ],
                capture_output=True,
                env=env,
                timeout=30,
            )
        self.assertEqual(
            result.returncode, 0, result.stdout.decode() + result.stderr.decode()
        )


if __name__ == "__main__":
    unittest.main()
