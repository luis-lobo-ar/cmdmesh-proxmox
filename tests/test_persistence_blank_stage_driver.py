"""The native deny/generate stage uses the ordinary Ansible boundary."""

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
    / "ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_blank_stage.py"
)


class BlankStageDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("blank_stage_driver", MODULE)
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def test_disabled_stage_never_loads_or_dispatches(self):
        with mock.patch.object(
            self.driver.stage, "load_prepared"
        ) as load, mock.patch.object(self.driver.stage, "apply") as apply:
            with self.assertRaises(self.driver.state.PersistenceError):
                self.driver.execute(
                    "stage", prepared_json="{}", prepared_sha256="a" * 64
                )
        load.assert_not_called()
        apply.assert_not_called()

    def test_prepare_check_and_status_do_not_write(self):
        frozen = {"recipient_prepared": {"request": {}}, "recipient_sha256": "a" * 64}
        raw = self.driver.state.canonical(frozen)
        with mock.patch.object(
            self.driver.stage, "prepare", return_value=frozen
        ), mock.patch.object(
            self.driver.stage, "load_prepared", return_value=frozen
        ), mock.patch.object(
            self.driver.stage, "apply"
        ) as apply, mock.patch.object(
            self.driver.stage,
            "status",
            return_value={"denied_generation_verified": True},
        ) as status:
            prepared = self.driver.execute(
                "prepare",
                recipient_prepared_json="original",
                recipient_prepared_sha256="a" * 64,
            )
            checked = self.driver.execute(
                "stage",
                prepared_json=raw.decode(),
                prepared_sha256=self.driver.state.sha256(raw),
                check_mode=True,
            )
            observed = self.driver.execute(
                "status",
                prepared_json=raw.decode(),
                prepared_sha256=self.driver.state.sha256(raw),
            )
        apply.assert_not_called()
        status.assert_called_once_with(raw, self.driver.state.sha256(raw))
        self.assertEqual(prepared["prepared_json"].encode(), raw)
        self.assertTrue(checked["would_change"])
        for value in (prepared, checked, observed):
            self.assertFalse(
                value["mutation_attempted"]
                or value["boot_verified"]
                or value["rebuild_verified"]
                or value["restore_verified"]
            )
        self.assertTrue(observed["denied_generation_verified"])

    def test_apply_requires_permission_and_preserves_partial_failure_uncertainty(self):
        result = {
            "denied_generation_verified": True,
            "boot_verified": False,
            "rebuild_verified": False,
            "restore_verified": False,
        }
        with mock.patch.object(
            self.driver.stage, "apply", return_value=result
        ) as apply:
            actual = self.driver.execute(
                "stage",
                prepared_json="original",
                prepared_sha256="b" * 64,
                allow_changes=True,
            )
        apply.assert_called_once_with(b"original", "b" * 64)
        self.assertTrue(actual["changed"] and actual["mutation_attempted"])
        for check, allow in ((True, True), (False, False), (False, True)):
            failed = self.driver.failure(
                RuntimeError("PRIVATE_RUNTIME_SENTINEL"), "stage", check, allow
            )
            self.assertNotIn("PRIVATE_", json.dumps(failed))
            self.assertEqual(failed["effects_may_exist"], not check and allow)
            self.assertFalse(
                failed["denied_generation_verified"] or failed["boot_verified"]
            )

    def test_actual_ansible_boundary_keeps_errors_private_and_hashes_exact(self):
        program = """import importlib.util,sys
from pathlib import Path
from ansible.module_utils import basic
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'ansible'))
basic._ANSIBLE_PROFILE='legacy';basic._ANSIBLE_ARGS=sys.stdin.buffer.read()
path=root/'ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_blank_stage.py'
spec=importlib.util.spec_from_file_location('actual_driver',path);driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
if sys.argv[2]=='error':
 def failed(*args):raise RuntimeError('PRIVATE_RUNTIME_SENTINEL')
 driver.stage.prepare=failed
elif sys.argv[2]=='success':driver.stage.prepare=lambda raw,trusted:{'source_hash':trusted}
driver.main()
"""
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        for mode in ("unknown", "error", "success"):
            body = {
                "ANSIBLE_MODULE_ARGS": {
                    "action": "unknown" if mode == "unknown" else "prepare",
                    "recipient_prepared_json": "PRIVATE_INPUT_SENTINEL",
                    "recipient_prepared_sha256": "a" * 64,
                    "_ansible_tracebacks_for": ["error"],
                }
            }
            with tempfile.TemporaryDirectory(
                dir=ROOT / ".generated", prefix="blank-stage-boundary-"
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
                raw = self.driver.state.canonical({"source_hash": "a" * 64})
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
