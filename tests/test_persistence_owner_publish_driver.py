"""The owner boundary separates read-only preparation from a once-only write."""

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
    / "ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_owner_publish.py"
)


class OwnerPublicationDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("owner_driver", MODULE)
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def test_disabled_publish_does_not_load_guard_or_dispatch(self):
        with mock.patch.object(
            self.driver.publish, "apply"
        ) as apply, mock.patch.object(self.driver.publish, "load_guard_source") as load:
            with self.assertRaises(self.driver.state.PersistenceError):
                self.driver.execute(
                    "publish", prepared_json="{}", prepared_sha256="a" * 64
                )
        load.assert_not_called()
        apply.assert_not_called()

    def test_check_revalidates_exact_preparation_and_never_publishes(self):
        frozen = {
            "attachment_prepared": {},
            "attachment_sha256": "a" * 64,
            "attachment_completion_sha256": "b" * 64,
        }
        raw = self.driver.state.canonical(frozen)
        with mock.patch.object(
            self.driver.publish, "load_guard_source"
        ), mock.patch.object(
            self.driver.publish, "load_prepared", return_value=frozen
        ), mock.patch.object(
            self.driver.publish, "prepare", return_value=frozen
        ), mock.patch.object(
            self.driver.publish, "apply"
        ) as apply:
            result = self.driver.execute(
                "publish",
                prepared_json=raw.decode(),
                prepared_sha256="c" * 64,
                guard_python="pinned",
                check_mode=True,
            )
        apply.assert_not_called()
        self.assertTrue(result["would_change"])
        self.assertFalse(
            result["owner_publication_verified"]
            or result["mutation_attempted"]
            or result["boot_verified"]
        )

    def test_drifted_check_refuses_before_publish(self):
        frozen = {
            "attachment_prepared": {},
            "attachment_sha256": "a" * 64,
            "attachment_completion_sha256": "b" * 64,
        }
        with mock.patch.object(
            self.driver.publish, "load_guard_source"
        ), mock.patch.object(
            self.driver.publish, "load_prepared", return_value=frozen
        ), mock.patch.object(
            self.driver.publish, "prepare", return_value={}
        ), mock.patch.object(
            self.driver.publish, "apply"
        ) as apply:
            with self.assertRaises(self.driver.state.PersistenceError):
                self.driver.execute(
                    "publish",
                    prepared_json="{} ",
                    prepared_sha256="c" * 64,
                    guard_python="pinned",
                    check_mode=True,
                )
        apply.assert_not_called()

    def test_mutation_and_status_have_distinct_outcomes(self):
        with mock.patch.object(
            self.driver.publish,
            "apply",
            return_value={"owner_publication_verified": True},
        ) as apply, mock.patch.object(
            self.driver.publish,
            "status",
            return_value={"owner_publication_verified": True},
        ) as status:
            changed = self.driver.execute(
                "publish",
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

    def test_failure_redacts_details_and_retains_uncertainty(self):
        for check, allow in ((True, True), (False, False), (False, True)):
            failed = self.driver.failure(
                RuntimeError("PRIVATE_SENTINEL"), "publish", check, allow
            )
            self.assertNotIn("PRIVATE_", json.dumps(failed))
            self.assertEqual(failed["effects_may_exist"], not check and allow)
            self.assertFalse(
                failed["owner_publication_verified"] or failed["boot_verified"]
            )

    def test_actual_ansible_boundary_preserves_hash_and_redacts_error(self):
        program = """import importlib.util,sys
from pathlib import Path
from ansible.module_utils import basic
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'ansible'))
basic._ANSIBLE_PROFILE='legacy';basic._ANSIBLE_ARGS=sys.stdin.buffer.read()
path=root/'ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_owner_publish.py'
spec=importlib.util.spec_from_file_location('actual_driver',path);driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
if sys.argv[2]=='error':
 def failed(*args):raise RuntimeError('PRIVATE_RUNTIME_SENTINEL')
 driver.publish.prepare=failed
else:driver.publish.prepare=lambda raw,trusted,completion,guard:{'source_hash':trusted}
driver.main()
"""
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        for mode in ("error", "success"):
            body = {
                "ANSIBLE_MODULE_ARGS": {
                    "action": "prepare",
                    "attachment_prepared_json": "PRIVATE_INPUT_SENTINEL",
                    "attachment_prepared_sha256": "a" * 64,
                    "attachment_completion_sha256": "b" * 64,
                    "guard_python": "PRIVATE_PROGRAM_SENTINEL",
                    "_ansible_debug": True,
                }
            }
            with tempfile.TemporaryDirectory(
                dir=ROOT / ".generated", prefix="owner-boundary-"
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
                raw = self.driver.state.canonical({"source_hash": "a" * 64})
                self.assertEqual(actual["prepared_json"].encode(), raw)
                self.assertEqual(
                    actual["prepared_sha256"], self.driver.state.sha256(raw)
                )
