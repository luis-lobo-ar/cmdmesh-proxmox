"""Permission, privacy and real AnsiballZ source packaging for blank boot."""

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
    / "ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_blank_boot.py"
)


class BlankBootDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("blank_boot_driver", MODULE)
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def test_disabled_boot_never_loads_or_posts(self):
        with mock.patch.object(
            self.driver.boot, "load_prepared"
        ) as load, mock.patch.object(self.driver.boot, "boot") as boot:
            with self.assertRaises(self.driver.state.PersistenceError):
                self.driver.execute(
                    "boot", prepared_json="{}", prepared_sha256="a" * 64
                )
        load.assert_not_called()
        boot.assert_not_called()

    def test_prepare_and_check_preserve_bytes_without_boot_permission(self):
        frozen = {
            "stage_prepared": {},
            "stage_sha256": "a" * 64,
            "stage_completion_sha256": "b" * 64,
        }
        raw = self.driver.state.canonical(frozen)
        with mock.patch.object(
            self.driver.boot, "prepare", return_value=frozen
        ), mock.patch.object(
            self.driver.boot, "load_prepared", return_value=frozen
        ), mock.patch.object(
            self.driver.boot, "boot"
        ) as boot:
            prepared = self.driver.execute(
                "prepare",
                stage_prepared_json="original",
                stage_prepared_sha256="a" * 64,
                stage_completion_sha256="b" * 64,
            )
            checked = self.driver.execute(
                "boot",
                prepared_json=raw.decode(),
                prepared_sha256=self.driver.state.sha256(raw),
                check_mode=True,
            )
        boot.assert_not_called()
        self.assertEqual(prepared["prepared_json"].encode(), raw)
        self.assertTrue(checked["would_change"])
        self.assertFalse(checked["boot_verified"] or checked["mutation_attempted"])

    def test_status_is_readonly_and_failure_preserves_uncertainty(self):
        with mock.patch.object(
            self.driver.boot, "status", return_value={"boot_verified": True}
        ) as status, mock.patch.object(self.driver.boot, "boot") as boot:
            result = self.driver.execute(
                "status", prepared_json="original", prepared_sha256="b" * 64
            )
        status.assert_called_once_with(b"original", "b" * 64)
        boot.assert_not_called()
        self.assertTrue(result["boot_verified"])
        self.assertFalse(
            result["changed"]
            or result["mutation_attempted"]
            or result["rebuild_verified"]
            or result["restore_verified"]
        )
        result = self.driver.failure(
            RuntimeError("PRIVATE_RUNTIME_SENTINEL"), "boot", False, True
        )
        self.assertTrue(result["effects_may_exist"])
        self.assertFalse(result["boot_verified"])
        self.assertNotIn("PRIVATE_", json.dumps(result))

    def test_actual_module_argument_errors_are_private_and_hashes_exact(self):
        program = """import importlib.util,sys
from pathlib import Path
from ansible.module_utils import basic
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'ansible'))
basic._ANSIBLE_PROFILE='legacy';basic._ANSIBLE_ARGS=sys.stdin.buffer.read()
path=root/'ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_blank_boot.py'
spec=importlib.util.spec_from_file_location('actual_driver',path);driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
if sys.argv[2]=='error':
 def failed(*args):raise RuntimeError('PRIVATE_RUNTIME_SENTINEL')
 driver.boot.prepare=failed
elif sys.argv[2]=='success':driver.boot.prepare=lambda raw,trusted,completion:{'stage_hash':trusted}
driver.main()
"""
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        for mode in ("unknown", "error", "success"):
            body = {
                "ANSIBLE_MODULE_ARGS": {
                    "action": "unknown" if mode == "unknown" else "prepare",
                    "stage_prepared_json": "PRIVATE_INPUT_SENTINEL",
                    "stage_prepared_sha256": "a" * 64,
                    "stage_completion_sha256": "b" * 64,
                    "_ansible_tracebacks_for": ["error"],
                }
            }
            with tempfile.TemporaryDirectory(
                dir=ROOT / ".generated", prefix="blank-boot-boundary-"
            ) as work:
                result = subprocess.run(
                    [sys.executable, "-B", "-c", program, str(ROOT), mode],
                    input=json.dumps(body).encode(),
                    capture_output=True,
                    timeout=20,
                    env={**os.environ, "TMPDIR": work, "ANSIBLE_LOCAL_TEMP": work},
                )
            value = json.loads(result.stdout)
            if mode == "success":
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                raw = self.driver.state.canonical({"stage_hash": "a" * 64})
                self.assertEqual(value["prepared_json"].encode(), raw)
                self.assertEqual(
                    value["prepared_sha256"], self.driver.state.sha256(raw)
                )
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(
                    "PRIVATE_", result.stdout.decode() + result.stderr.decode()
                )

    def test_actual_ansible_zip_preserves_pinned_standalone_guard_source(self):
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(
            dir=ROOT / ".generated", prefix="guard-source-zip-"
        ) as work:
            directory = Path(work)
            library = directory / "library"
            library.mkdir(mode=0o700)
            (library / "guard_source_probe.py").write_text(
                """from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import persistence_blank_boot as boot
module=AnsibleModule(argument_spec={},supports_check_mode=True)
raw=boot.guard_source()
module.exit_json(changed=False,guard_sha256=boot.state.sha256(raw),byte_count=len(raw))
"""
            )
            (directory / "inventory.json").write_text(
                json.dumps(
                    {
                        "all": {
                            "hosts": {
                                "localhost": {
                                    "ansible_connection": "local",
                                    "ansible_python_interpreter": sys.executable,
                                }
                            }
                        }
                    }
                )
            )
            (directory / "playbook.json").write_text(
                json.dumps(
                    [
                        {
                            "hosts": "all",
                            "gather_facts": False,
                            "tasks": [
                                {
                                    "name": "Inspect packaged guard source only",
                                    "guard_source_probe": {},
                                    "register": "guard_result",
                                },
                                {
                                    "name": "Require exact independently pinned source",
                                    "ansible.builtin.assert": {
                                        "that": [
                                            "guard_result.guard_sha256 == 'baa0e36edb88720b8ff7a47e072864199435718aee40bc8895092d3fe57a4cfd'",
                                            "guard_result.byte_count > 1000",
                                            "not guard_result.changed",
                                        ]
                                    },
                                },
                            ],
                        }
                    ]
                )
            )
            (directory / "ansible.cfg").write_text(
                "[defaults]\nretry_files_enabled=False\n"
            )
            for name in ("local", "remote", "tmp"):
                (directory / name).mkdir(mode=0o700)
            env = {
                **os.environ,
                "ANSIBLE_CONFIG": str(directory / "ansible.cfg"),
                "ANSIBLE_LIBRARY": str(library),
                "ANSIBLE_COLLECTIONS_PATH": str(ROOT / "ansible/ansible_collections"),
                "ANSIBLE_LOCAL_TEMP": str(directory / "local"),
                "ANSIBLE_REMOTE_TEMP": str(directory / "remote"),
                "TMPDIR": str(directory / "tmp"),
            }
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ansible.cli.playbook",
                    "-i",
                    str(directory / "inventory.json"),
                    "--check",
                    str(directory / "playbook.json"),
                ],
                cwd=directory,
                capture_output=True,
                timeout=60,
                env=env,
            )
        self.assertEqual(
            result.returncode, 0, result.stdout.decode() + result.stderr.decode()
        )
        self.assertIn("changed=0", result.stdout.decode())


if __name__ == "__main__":
    unittest.main()
