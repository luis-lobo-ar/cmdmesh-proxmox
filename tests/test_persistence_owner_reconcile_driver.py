"""Forward reconciliation has a bounded, redacted Ansible boundary."""

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
    / "ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_owner_reconcile.py"
)


class ReconciliationDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("reconcile_driver", MODULE)
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def test_changes_disabled_before_loading_or_dispatch(self):
        with mock.patch.object(
            self.driver.reconcile, "apply"
        ) as apply, mock.patch.object(
            self.driver.reconcile, "load_guard_source"
        ) as load:
            with self.assertRaises(self.driver.state.PersistenceError):
                self.driver.execute(
                    "reconcile", prepared_json="{}", prepared_sha256="a" * 64
                )
        apply.assert_not_called()
        load.assert_not_called()

    def test_check_reprepares_same_parent_without_mutation(self):
        value = {
            "parent_prepared": {},
            "parent_prepared_sha256": "a" * 64,
            "parent_failure_sha256": "b" * 64,
        }
        raw = self.driver.state.canonical(value)
        with mock.patch.object(
            self.driver.reconcile, "load_guard_source"
        ), mock.patch.object(
            self.driver.reconcile, "load_prepared", return_value=(value, None)
        ), mock.patch.object(
            self.driver.reconcile, "prepare", return_value=value
        ) as prepare, mock.patch.object(
            self.driver.reconcile, "apply"
        ) as apply:
            result = self.driver.execute(
                "reconcile",
                prepared_json=raw.decode(),
                prepared_sha256="c" * 64,
                guard_python="known",
                check_mode=True,
            )
        prepare.assert_called_once_with(b"{}", "a" * 64, "b" * 64, b"known")
        apply.assert_not_called()
        self.assertTrue(result["would_change"])
        self.assertFalse(
            result["mutation_attempted"]
            or result["owner_reconciliation_verified"]
            or result["boot_verified"]
        )

    def test_drifted_check_refuses(self):
        value = {
            "parent_prepared": {},
            "parent_prepared_sha256": "a" * 64,
            "parent_failure_sha256": "b" * 64,
        }
        with mock.patch.object(
            self.driver.reconcile, "load_guard_source"
        ), mock.patch.object(
            self.driver.reconcile, "load_prepared", return_value=(value, None)
        ), mock.patch.object(
            self.driver.reconcile, "prepare", return_value={}
        ), mock.patch.object(
            self.driver.reconcile, "apply"
        ) as apply:
            with self.assertRaises(self.driver.state.PersistenceError):
                self.driver.execute(
                    "reconcile",
                    prepared_json="different",
                    prepared_sha256="c" * 64,
                    guard_python="known",
                    check_mode=True,
                )
        apply.assert_not_called()

    def test_apply_and_status_forward_exact_bytes_with_distinct_outcomes(self):
        with mock.patch.object(
            self.driver.reconcile,
            "apply",
            return_value={"owner_reconciliation_verified": True},
        ) as apply, mock.patch.object(
            self.driver.reconcile,
            "status",
            return_value={"owner_reconciliation_verified": True},
        ) as status:
            changed = self.driver.execute(
                "reconcile",
                prepared_json="original",
                prepared_sha256="a" * 64,
                guard_python="known",
                allow_changes=True,
            )
            observed = self.driver.execute(
                "status", prepared_json="original", prepared_sha256="a" * 64
            )
        apply.assert_called_once_with(b"original", "a" * 64, b"known")
        status.assert_called_once_with(b"original", "a" * 64)
        self.assertTrue(changed["changed"] and changed["mutation_attempted"])
        self.assertFalse(observed["changed"] or observed["mutation_attempted"])

    def test_failures_redact_and_preserve_possible_effects(self):
        for action, check, allow in (
            ("reconcile", False, True),
            ("reconcile", True, True),
            ("status", False, True),
        ):
            result = self.driver.failure(
                RuntimeError("PRIVATE_SENTINEL"), action, check, allow
            )
            self.assertNotIn("PRIVATE_", json.dumps(result))
            self.assertEqual(
                result["effects_may_exist"],
                action == "reconcile" and not check and allow,
            )
            self.assertFalse(
                result["owner_reconciliation_verified"] or result["boot_verified"]
            )

    def test_actual_ansible_boundary_keeps_exact_hash_and_hides_inputs(self):
        program = """import importlib.util,sys
from pathlib import Path
from ansible.module_utils import basic
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'ansible'))
basic._ANSIBLE_PROFILE='legacy';basic._ANSIBLE_ARGS=sys.stdin.buffer.read()
spec=importlib.util.spec_from_file_location('actual',root/'ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_owner_reconcile.py')
driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
if sys.argv[2]=='error':
 def failed(*args):raise RuntimeError('PRIVATE_RUNTIME_SENTINEL')
 driver.reconcile.prepare=failed
else:driver.reconcile.prepare=lambda raw,trusted,failure,guard:{'parent_hash':trusted}
driver.main()
"""
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        for mode in ("error", "success"):
            body = {
                "ANSIBLE_MODULE_ARGS": {
                    "action": "prepare",
                    "parent_prepared_json": "PRIVATE_INPUT_SENTINEL",
                    "parent_prepared_sha256": "a" * 64,
                    "parent_failure_sha256": "b" * 64,
                    "guard_python": "PRIVATE_PROGRAM_SENTINEL",
                    "_ansible_debug": True,
                }
            }
            with tempfile.TemporaryDirectory(
                dir=ROOT / ".generated", prefix="reconcile-boundary-"
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
