"""The application-trial boundary gates writes and redacts private invocation."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
MODULE = (
    ROOT
    / "ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_writer_trial.py"
)


class WriterTrialDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("writer_trial_driver", MODULE)
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def test_prepare_returns_canonical_bytes_and_safe_hash_without_change(self):
        prepared = {"trusted_hash": "a" * 64}
        with mock.patch.object(
            self.driver.trial, "prepare", return_value=prepared
        ) as prepare:
            value = self.driver.execute(
                "prepare",
                boot_json="{}",
                boot_sha256="a" * 64,
                boot_completion_sha256="b" * 64,
                nonce="c" * 32,
            )
        prepare.assert_called_once_with(b"{}", "a" * 64, "b" * 64, "c" * 32)
        self.assertEqual(
            value["prepared_json"].encode(), self.driver.state.canonical(prepared)
        )
        self.assertEqual(
            value["prepared_sha256"],
            self.driver.state.sha256(value["prepared_json"].encode()),
        )
        self.assertFalse(value["changed"] or value["mutation_attempted"])

    def test_normal_run_requires_explicit_permission_before_backend(self):
        with mock.patch.object(self.driver.execution, "run") as run:
            for allow in (False, None, "yes", 1):
                with self.subTest(allow=allow), self.assertRaises(ValueError):
                    self.driver.execute(
                        "run",
                        prepared_json="{}",
                        prepared_sha256="a" * 64,
                        allow_changes=allow,
                    )
        run.assert_not_called()

    def test_check_mode_runs_only_fresh_read_only_preflight(self):
        with mock.patch.object(
            self.driver.execution, "preflight", return_value={}
        ) as check, mock.patch.object(
            self.driver.execution, "run", side_effect=AssertionError("no mutation")
        ):
            value = self.driver.execute(
                "run", prepared_json="{}", prepared_sha256="a" * 64, check_mode=True
            )
        check.assert_called_once_with(b"{}", "a" * 64)
        self.assertTrue(value["changed"] and value["proposed"])
        self.assertFalse(any(value[name] for name in self.driver.FLAGS))

    def test_status_requires_external_completion_hash_and_preserves_safe_result(self):
        result = {
            **self.driver.FLAGS,
            "rebuild_verified": True,
            "application_write_verified": True,
            "application_quiesced": True,
            "completion_sha256": "b" * 64,
        }
        with mock.patch.object(
            self.driver.execution, "status", return_value=result
        ) as status:
            value = self.driver.execute(
                "status",
                prepared_json="{}",
                prepared_sha256="a" * 64,
                completion_sha256="b" * 64,
            )
            with self.assertRaises(ValueError):
                self.driver.execute(
                    "status", prepared_json="{}", prepared_sha256="a" * 64
                )
        status.assert_called_once_with(b"{}", "a" * 64, "b" * 64)
        self.assertFalse(value["changed"] or value["mutation_attempted"])
        self.assertTrue(value["rebuild_verified"])

    def test_failure_never_exposes_private_error_or_claims_success(self):
        for action, check, allow in (
            ("prepare", False, False),
            ("run", True, True),
            ("run", False, False),
            ("run", False, True),
            ("status", False, True),
        ):
            value = self.driver.failure(
                RuntimeError("PRIVATE_RUNTIME_SENTINEL"), action, check, allow
            )
            self.assertNotIn("PRIVATE_", json.dumps(value))
            self.assertTrue(all(value[name] is False for name in self.driver.FLAGS))
            self.assertEqual(
                value["effects_may_exist"],
                action == "run" and not check and allow is True,
            )

    def test_actual_ansible_redacts_invocation_and_unknown_exception(self):
        program = """import importlib.util,sys
from pathlib import Path
from ansible.module_utils import basic
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'ansible'))
basic._ANSIBLE_PROFILE='legacy';basic._ANSIBLE_ARGS=sys.stdin.buffer.read()
spec=importlib.util.spec_from_file_location('actual',root/'ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_writer_trial.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
if sys.argv[2]=='error':
 def fail(*args):raise RuntimeError('PRIVATE_RUNTIME_SENTINEL')
 d.trial.prepare=fail
else:d.trial.prepare=lambda raw,sha,complete,nonce:{'safe_hash':sha}
d.main()
"""
        for mode in ("success", "error"):
            body = {
                "ANSIBLE_MODULE_ARGS": {
                    "action": "prepare",
                    "boot_json": "PRIVATE_INPUT_SENTINEL",
                    "boot_sha256": "a" * 64,
                    "boot_completion_sha256": "b" * 64,
                    "nonce": "c" * 32,
                    "_ansible_debug": True,
                }
            }
            with tempfile.TemporaryDirectory(
                dir=ROOT / ".generated", prefix="trial-boundary-"
            ) as scratch:
                result = subprocess.run(
                    [sys.executable, "-B", "-c", program, str(ROOT), mode],
                    input=json.dumps(body).encode(),
                    capture_output=True,
                    timeout=20,
                    env={
                        **os.environ,
                        "TMPDIR": scratch,
                        "ANSIBLE_LOCAL_TEMP": scratch,
                    },
                )
            value = json.loads(result.stdout)
            self.assertNotIn(
                "PRIVATE_", result.stdout.decode() + result.stderr.decode()
            )
            self.assertEqual(result.returncode, 0 if mode == "success" else 1)
            if mode == "success":
                self.assertEqual(
                    json.loads(value["prepared_json"])["safe_hash"], "a" * 64
                )


if __name__ == "__main__":
    unittest.main()
