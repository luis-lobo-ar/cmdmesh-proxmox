"""Receive approval, check mode and safe failure output at the Ansible boundary."""

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
    / "ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_receive.py"
)


class ReceiveDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("receive_driver", MODULE)
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def test_disabled_apply_does_not_read_or_dispatch(self):
        with mock.patch.object(
            self.driver.restore, "load_prepared"
        ) as load, mock.patch.object(self.driver.restore, "execute_restore") as receive:
            with self.assertRaises(self.driver.state.PersistenceError):
                self.driver.execute(
                    "receive", prepared_json="{}", prepared_sha256="a" * 64
                )
        load.assert_not_called()
        receive.assert_not_called()

    def test_prepare_preserves_canonical_bytes_and_does_not_receive(self):
        prepared = {"request": {}, "manifest": {}}
        with mock.patch.object(
            self.driver.restore, "prepare_restore", return_value=prepared
        ) as prepare, mock.patch.object(
            self.driver.restore, "execute_restore"
        ) as receive:
            result = self.driver.execute(
                "prepare", restore_request={"example": True}, manifest_json="{}"
            )
        prepare.assert_called_once_with({"example": True}, b"{}")
        receive.assert_not_called()
        raw = self.driver.state.canonical(prepared)
        self.assertEqual(result["prepared_json"], raw.decode())
        self.assertEqual(result["prepared_sha256"], self.driver.state.sha256(raw))
        self.assertFalse(result["changed"] or result["restore_verified"])

    def test_check_only_repeats_preflight_and_cannot_claim_received(self):
        prepared = {"request": {}, "manifest": {}}
        raw = self.driver.state.canonical(prepared)
        with mock.patch.object(
            self.driver.restore, "load_prepared", return_value=prepared
        ), mock.patch.object(
            self.driver.restore, "prepare_restore", return_value=prepared
        ), mock.patch.object(
            self.driver.restore, "execute_restore"
        ) as receive:
            result = self.driver.execute(
                "receive",
                prepared_json=raw.decode(),
                prepared_sha256=self.driver.state.sha256(raw),
                check_mode=True,
            )
        receive.assert_not_called()
        self.assertTrue(result["would_change"])
        self.assertFalse(
            result["mutation_attempted"]
            or result["received_verified"]
            or result["restore_verified"]
        )

    def test_changed_check_result_refuses_and_actual_apply_forwards_exact_bytes(self):
        prepared = {"request": {}, "manifest": {}}
        with mock.patch.object(
            self.driver.restore, "load_prepared", return_value=prepared
        ), mock.patch.object(
            self.driver.restore,
            "prepare_restore",
            return_value={**prepared, "changed": True},
        ), mock.patch.object(
            self.driver.restore, "execute_restore"
        ) as receive:
            with self.assertRaises(self.driver.state.PersistenceError):
                self.driver.execute(
                    "receive",
                    prepared_json="{}",
                    prepared_sha256="a" * 64,
                    check_mode=True,
                )
        receive.assert_not_called()
        with mock.patch.object(
            self.driver.restore,
            "execute_restore",
            return_value={"received_verified": True, "restore_verified": False},
        ) as receive:
            result = self.driver.execute(
                "receive",
                prepared_json="exact bytes",
                prepared_sha256="a" * 64,
                allow_changes=True,
            )
        receive.assert_called_once_with(b"exact bytes", "a" * 64)
        self.assertTrue(result["received_verified"] and result["mutation_attempted"])
        self.assertFalse(result["restore_verified"])

    def test_failure_never_echoes_input_or_claims_recovery(self):
        for check, allow in ((True, True), (False, False), (False, True)):
            result = self.driver.failure(
                OSError("SECRET_INPUT_SENTINEL"), "receive", check, allow
            )
            self.assertNotIn("SECRET_INPUT_SENTINEL", json.dumps(result))
            self.assertEqual(result["effects_may_exist"], not check and allow)
            self.assertFalse(result["received_verified"] or result["restore_verified"])

    def run_boundary(self, parameters, injection=""):
        program = """import importlib.util,sys
from pathlib import Path
from ansible.module_utils import basic
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'ansible'))
basic._ANSIBLE_PROFILE='legacy';basic._ANSIBLE_ARGS=sys.stdin.buffer.read()
path=root/'ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_receive.py'
spec=importlib.util.spec_from_file_location('actual_receive',path);driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
""" + injection + "\ndriver.main()\n"
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(
            dir=ROOT / ".generated", prefix="receive-boundary-"
        ) as work:
            return subprocess.run(
                [sys.executable, "-B", "-c", program, str(ROOT)],
                input=json.dumps({"ANSIBLE_MODULE_ARGS": parameters}).encode(),
                capture_output=True,
                timeout=20,
                env={**os.environ, "TMPDIR": work, "ANSIBLE_LOCAL_TEMP": work},
            )

    def test_real_ansible_rejects_unknown_action_without_echoing_private_values(self):
        result = self.run_boundary(
            {
                "action": "unknown",
                "restore_request": {"private": "INPUT_PRIVATE_SENTINEL"},
            }
        )
        self.assertNotEqual(result.returncode, 0)
        body = json.loads(result.stdout)
        self.assertTrue(body["failed"])
        self.assertNotIn(
            "INPUT_PRIVATE_SENTINEL", result.stdout.decode() + result.stderr.decode()
        )

    def test_real_ansible_suppresses_runtime_traceback_and_keeps_safe_hashes(self):
        for exception in ("OSError", "RuntimeError", "TypeError"):
            injection = (
                "def failed(*unused):raise "
                + exception
                + "('RUNTIME_PRIVATE_SENTINEL')\ndriver.restore.prepare_restore=failed\n"
            )
            result = self.run_boundary(
                {
                    "action": "prepare",
                    "restore_request": {"private": "INPUT_PRIVATE_SENTINEL"},
                    "manifest_json": "{}",
                    "_ansible_tracebacks_for": ["error"],
                },
                injection,
            )
            self.assertNotEqual(result.returncode, 0)
            body = json.loads(result.stdout)
            self.assertFalse(body["received_verified"] or body["restore_verified"])
            self.assertEqual(
                body["invocation"]["module_args"]["restore_request"], "withheld"
            )
            self.assertNotIn(
                "PRIVATE_SENTINEL", result.stdout.decode() + result.stderr.decode()
            )
        injection = "driver.restore.prepare_restore=lambda request,raw:{'request':request,'manifest_sha256':'e'*64}\n"
        request = {"safe_hash": "e" * 64}
        result = self.run_boundary(
            {"action": "prepare", "restore_request": request, "manifest_json": "{}"},
            injection,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        body = json.loads(result.stdout)
        raw = self.driver.state.canonical(
            {"request": request, "manifest_sha256": "e" * 64}
        )
        self.assertEqual(body["prepared_json"].encode(), raw)
        self.assertEqual(body["prepared_sha256"], self.driver.state.sha256(raw))


if __name__ == "__main__":
    unittest.main()
