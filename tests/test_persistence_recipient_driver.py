"""Recipient check/permission/status and actual Ansible packaging boundaries."""

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
    / "ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_recipient.py"
)


class RecipientDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("recipient_driver", MODULE)
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def test_disabled_provision_never_loads_or_dispatches(self):
        with mock.patch.object(
            self.driver.recipient, "load_prepared"
        ) as load, mock.patch.object(self.driver.recipient, "provision") as provision:
            with self.assertRaises(self.driver.state.PersistenceError):
                self.driver.execute(
                    "provision", prepared_json="{}", prepared_sha256="a" * 64
                )
        load.assert_not_called()
        provision.assert_not_called()

    def test_prepare_and_check_preserve_exact_bytes_without_dispatch(self):
        frozen = {"request": {"safe_hash": "a" * 64}}
        raw = self.driver.state.canonical(frozen)
        with mock.patch.object(
            self.driver.recipient, "prepare", return_value=frozen
        ), mock.patch.object(
            self.driver.recipient, "load_prepared", return_value=frozen
        ), mock.patch.object(
            self.driver.recipient, "provision"
        ) as provision:
            prepared = self.driver.execute(
                "prepare", recipient_request=frozen["request"]
            )
            checked = self.driver.execute(
                "provision",
                prepared_json=raw.decode(),
                prepared_sha256=self.driver.state.sha256(raw),
                check_mode=True,
            )
        provision.assert_not_called()
        self.assertEqual(prepared["prepared_json"].encode(), raw)
        self.assertEqual(prepared["prepared_sha256"], self.driver.state.sha256(raw))
        self.assertTrue(checked["would_change"])
        self.assertFalse(
            checked["mutation_attempted"]
            or checked["provisioned_verified"]
            or checked["rebuild_verified"]
        )

    def test_status_is_readonly_and_apply_forwards_exact_retained_bytes(self):
        result = {
            "provisioned_verified": True,
            "rebuild_verified": False,
            "restore_verified": False,
        }
        with mock.patch.object(
            self.driver.recipient, "status", return_value=result
        ) as status, mock.patch.object(
            self.driver.recipient, "provision", return_value=result
        ) as provision:
            observed = self.driver.execute(
                "status", prepared_json="exact", prepared_sha256="b" * 64
            )
            applied = self.driver.execute(
                "provision",
                prepared_json="exact",
                prepared_sha256="b" * 64,
                allow_changes=True,
            )
        status.assert_called_once_with(b"exact", "b" * 64)
        provision.assert_called_once_with(b"exact", "b" * 64)
        self.assertFalse(observed["changed"] or observed["mutation_attempted"])
        self.assertTrue(applied["changed"] and applied["provisioned_verified"])
        self.assertFalse(applied["rebuild_verified"] or applied["restore_verified"])

    def test_failure_is_static_and_conservative(self):
        for check, allow in ((True, True), (False, False), (False, True)):
            result = self.driver.failure(
                OSError("PRIVATE_INPUT_SENTINEL"), "provision", check, allow
            )
            self.assertNotIn("PRIVATE_INPUT_SENTINEL", json.dumps(result))
            self.assertEqual(result["effects_may_exist"], not check and allow)
            self.assertFalse(
                result["provisioned_verified"] or result["rebuild_verified"]
            )

    def test_real_ansible_redacts_arguments_runtime_exceptions_and_preserves_hashes(
        self,
    ):
        program = """import importlib.util,sys
from pathlib import Path
from ansible.module_utils import basic
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'ansible'))
basic._ANSIBLE_PROFILE='legacy';basic._ANSIBLE_ARGS=sys.stdin.buffer.read()
path=root/'ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_recipient.py'
spec=importlib.util.spec_from_file_location('actual_driver',path);driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
if sys.argv[2]=='error':
 def failed(*args):raise RuntimeError('PRIVATE_RUNTIME_SENTINEL')
 driver.recipient.prepare=failed
elif sys.argv[2]=='success':driver.recipient.prepare=lambda request:{'request':request}
driver.main()
"""
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        for mode in ("unknown", "error", "success"):
            request = (
                {"safe_hash": "a" * 64}
                if mode == "success"
                else {"private": "PRIVATE_INPUT_SENTINEL"}
            )
            body = {
                "ANSIBLE_MODULE_ARGS": {
                    "action": "unknown" if mode == "unknown" else "prepare",
                    "recipient_request": request,
                    "_ansible_tracebacks_for": ["error"],
                }
            }
            with tempfile.TemporaryDirectory(
                dir=ROOT / ".generated", prefix="recipient-render-"
            ) as work:
                result = subprocess.run(
                    [sys.executable, "-B", "-c", program, str(ROOT), mode],
                    input=json.dumps(body).encode(),
                    capture_output=True,
                    timeout=20,
                    env={**os.environ, "TMPDIR": work, "ANSIBLE_LOCAL_TEMP": work},
                )
            actual = json.loads(result.stdout)
            if mode == "success":
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                raw = self.driver.state.canonical({"request": request})
                self.assertEqual(actual["prepared_json"].encode(), raw)
                self.assertEqual(
                    actual["prepared_sha256"], self.driver.state.sha256(raw)
                )
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(
                    "PRIVATE_", result.stdout.decode() + result.stderr.decode()
                )


if __name__ == "__main__":
    unittest.main()
