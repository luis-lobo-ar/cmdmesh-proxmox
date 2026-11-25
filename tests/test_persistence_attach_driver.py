"""The attachment boundary keeps checks read-only and failures conservative."""

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


class AttachmentDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = (
            ROOT
            / "ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_attach.py"
        )
        spec = importlib.util.spec_from_file_location("attachment_driver", path)
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def test_disabled_mutation_does_not_parse_or_call_backend(self):
        with mock.patch.object(
            self.driver.attach, "load_prepared"
        ) as load, mock.patch.object(self.driver.attach, "apply") as apply:
            with self.assertRaises(self.driver.state.PersistenceError):
                self.driver.execute(
                    "attach", prepared_json="{}", prepared_sha256="a" * 64
                )
        load.assert_not_called()
        apply.assert_not_called()

    def test_prepare_check_status_are_read_only_and_preserve_exact_hash(self):
        frozen = {"recipient_prepared": {}, "recipient_sha256": "a" * 64}
        raw = self.driver.state.canonical(frozen)
        sha = self.driver.state.sha256(raw)
        with mock.patch.object(
            self.driver.attach, "prepare", return_value=frozen
        ), mock.patch.object(
            self.driver.attach, "load_prepared", return_value=frozen
        ), mock.patch.object(
            self.driver.attach, "status", return_value={"attachment_verified": True}
        ), mock.patch.object(
            self.driver.attach, "apply"
        ) as apply:
            prepared = self.driver.execute(
                "prepare",
                recipient_prepared_json="original",
                recipient_prepared_sha256="a" * 64,
            )
            checked = self.driver.execute(
                "attach",
                prepared_json=raw.decode(),
                prepared_sha256=sha,
                check_mode=True,
            )
            status = self.driver.execute(
                "status", prepared_json=raw.decode(), prepared_sha256=sha
            )
        apply.assert_not_called()
        self.assertEqual(prepared["prepared_json"].encode(), raw)
        self.assertEqual(prepared["prepared_sha256"], sha)
        self.assertTrue(checked["would_change"])
        self.assertTrue(status["attachment_verified"])
        for result in (prepared, checked, status):
            self.assertFalse(
                result["mutation_attempted"]
                or result["boot_verified"]
                or result["rebuild_verified"]
                or result["restore_verified"]
            )

    def test_changed_check_refuses_without_dispatch(self):
        with mock.patch.object(
            self.driver.attach,
            "load_prepared",
            return_value={"recipient_prepared": {}, "recipient_sha256": "a" * 64},
        ), mock.patch.object(
            self.driver.attach, "prepare", return_value={"changed": True}
        ), mock.patch.object(
            self.driver.attach, "apply"
        ) as apply:
            with self.assertRaises(self.driver.state.PersistenceError):
                self.driver.execute(
                    "attach",
                    prepared_json="{}",
                    prepared_sha256="a" * 64,
                    check_mode=True,
                )
        apply.assert_not_called()

    def test_apply_is_explicit_and_failure_never_exposes_exception_text(self):
        with mock.patch.object(
            self.driver.attach, "apply", return_value={"attachment_verified": True}
        ) as apply:
            result = self.driver.execute(
                "attach",
                prepared_json="original",
                prepared_sha256="a" * 64,
                allow_changes=True,
            )
        apply.assert_called_once_with(b"original", "a" * 64)
        self.assertTrue(result["mutation_attempted"] and result["changed"])
        for check, allow in ((True, True), (False, False), (False, True)):
            failed = self.driver.failure(
                RuntimeError("PRIVATE_SENTINEL"), "attach", check, allow
            )
            self.assertNotIn("PRIVATE_", json.dumps(failed))
            self.assertEqual(failed["effects_may_exist"], not check and allow)
            self.assertFalse(failed["attachment_verified"])

    def test_actual_ansible_boundary_redacts_errors_without_censoring_hashes(self):
        program = """import importlib.util,sys
from pathlib import Path
from ansible.module_utils import basic
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'ansible'))
basic._ANSIBLE_PROFILE='legacy';basic._ANSIBLE_ARGS=sys.stdin.buffer.read()
path=root/'ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_attach.py'
spec=importlib.util.spec_from_file_location('actual_driver',path);driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
if sys.argv[2]=='error':
 def failed(*args):raise RuntimeError('PRIVATE_RUNTIME_SENTINEL')
 driver.attach.prepare=failed
elif sys.argv[2]=='success':driver.attach.prepare=lambda raw,trusted:{'source_hash':trusted}
driver.main()
"""
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        for mode in ("unknown", "error", "success"):
            body = {
                "ANSIBLE_MODULE_ARGS": {
                    "action": "unknown" if mode == "unknown" else "prepare",
                    "recipient_prepared_json": "PRIVATE_INPUT_SENTINEL",
                    "recipient_prepared_sha256": "a" * 64,
                    "_ansible_debug": True,
                }
            }
            with tempfile.TemporaryDirectory(
                dir=ROOT / ".generated", prefix="attachment-boundary-"
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
            actual = json.loads(result.stdout)
            if mode == "success":
                self.assertEqual(result.returncode, 0, json.dumps(actual))
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
