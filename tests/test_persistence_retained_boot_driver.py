"""The retained startup boundary separates preparation, CHECK, mutation and status."""

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
    / "ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_retained_boot.py"
)


class RetainedBootDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("retained_boot_driver", MODULE)
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def test_mutation_requires_explicit_boolean_permission_before_loading(self):
        with mock.patch.object(self.driver.boot, "boot") as run, mock.patch.object(
            self.driver.boot, "decode_prepared"
        ) as load:
            for allowed in (False, "true", 1):
                with self.assertRaises(ValueError):
                    self.driver.execute(
                        "boot",
                        prepared_json="{}",
                        prepared_sha256="a" * 64,
                        allow_changes=allowed,
                    )
        run.assert_not_called()
        load.assert_not_called()

    def test_check_freshly_prepares_exact_inputs_without_claim_or_dispatch(self):
        value = {
            "reconciliation_prepared": {},
            "reconciliation_sha256": "a" * 64,
            "completion_sha256": "b" * 64,
            "source_sha256": "c" * 64,
            "image_profile": {"schema_version": 1},
        }
        raw = self.driver.state.canonical(value)
        with mock.patch.object(
            self.driver.boot, "decode_prepared", return_value=value
        ), mock.patch.object(
            self.driver.boot, "prepare", return_value=value
        ) as prepare, mock.patch.object(
            self.driver.boot, "boot"
        ) as run:
            result = self.driver.execute(
                "boot",
                prepared_json=raw.decode(),
                prepared_sha256="d" * 64,
                check_mode=True,
            )
        prepare.assert_called_once_with(
            b"{}", "a" * 64, "b" * 64, "c" * 64, value["image_profile"]
        )
        run.assert_not_called()
        self.assertTrue(result["would_change"])
        self.assertFalse(result["mutation_attempted"] or result["boot_verified"])

    def test_changed_check_cannot_dispatch(self):
        value = {
            "reconciliation_prepared": {},
            "reconciliation_sha256": "a" * 64,
            "completion_sha256": "b" * 64,
            "source_sha256": "c" * 64,
            "image_profile": {},
        }
        with mock.patch.object(
            self.driver.boot, "decode_prepared", return_value=value
        ), mock.patch.object(
            self.driver.boot, "prepare", return_value={}
        ), mock.patch.object(
            self.driver.boot, "boot"
        ) as run:
            with self.assertRaises(ValueError):
                self.driver.execute(
                    "boot",
                    prepared_json="different",
                    prepared_sha256="d" * 64,
                    check_mode=True,
                )
        run.assert_not_called()

    def test_apply_and_status_forward_original_bytes_with_distinct_effects(self):
        with mock.patch.object(
            self.driver.boot, "boot", return_value={"boot_verified": True}
        ) as run, mock.patch.object(
            self.driver.boot, "status", return_value={"boot_verified": True}
        ) as status:
            changed = self.driver.execute(
                "boot",
                prepared_json="original",
                prepared_sha256="a" * 64,
                allow_changes=True,
            )
            observed = self.driver.execute(
                "status", prepared_json="original", prepared_sha256="a" * 64
            )
        run.assert_called_once_with(b"original", "a" * 64)
        status.assert_called_once_with(b"original", "a" * 64)
        self.assertTrue(changed["changed"] and changed["mutation_attempted"])
        self.assertFalse(observed["changed"] or observed["mutation_attempted"])

    def test_errors_never_expose_private_details_or_verified_success(self):
        for action, check, allow in (
            ("boot", False, True),
            ("boot", True, True),
            ("status", False, True),
        ):
            value = self.driver.failure(
                RuntimeError("PRIVATE_ERROR_SENTINEL"), action, check, allow
            )
            self.assertNotIn("PRIVATE_", json.dumps(value))
            self.assertEqual(
                value["effects_may_exist"], action == "boot" and not check and allow
            )
            self.assertFalse(value["boot_verified"] or value["application_quiesced"])

    def test_actual_ansible_preserves_hashes_and_redacts_profile_and_exceptions(self):
        program = """import importlib.util,sys
from pathlib import Path
from ansible.module_utils import basic
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'ansible'))
basic._ANSIBLE_PROFILE='legacy';basic._ANSIBLE_ARGS=sys.stdin.buffer.read()
spec=importlib.util.spec_from_file_location('actual',root/'ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_retained_boot.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
if sys.argv[2]=='error':
 def failed(*args):raise RuntimeError('PRIVATE_RUNTIME_SENTINEL')
 d.boot.prepare=failed
else:d.boot.prepare=lambda raw,trusted,complete,source,profile:{'parent_hash':trusted}
d.main()
"""
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        for mode in ("error", "success"):
            body = {
                "ANSIBLE_MODULE_ARGS": {
                    "action": "prepare",
                    "reconciliation_json": "PRIVATE_INPUT_SENTINEL",
                    "reconciliation_sha256": "a" * 64,
                    "completion_sha256": "b" * 64,
                    "source_sha256": "c" * 64,
                    "image_profile": {"secret": "PRIVATE_PROFILE_SENTINEL"},
                    "_ansible_debug": True,
                }
            }
            with tempfile.TemporaryDirectory(
                dir=ROOT / ".generated", prefix="retained-boundary-"
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
            self.assertNotIn(
                "PRIVATE_", result.stdout.decode() + result.stderr.decode()
            )
            self.assertEqual(result.returncode, 0 if mode == "success" else 1)
            if mode == "success":
                raw = self.driver.state.canonical({"parent_hash": "a" * 64})
                self.assertEqual(actual["prepared_json"].encode(), raw)
                self.assertEqual(
                    actual["prepared_sha256"], self.driver.state.sha256(raw)
                )


if __name__ == "__main__":
    unittest.main()
