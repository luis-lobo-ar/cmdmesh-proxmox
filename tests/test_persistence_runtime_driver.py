"""The runtime Ansible boundary exposes inspection only and hides private inputs."""

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
    / "ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_runtime.py"
)


class RuntimeDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("runtime_driver", MODULE)
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def test_observation_preserves_arguments_and_never_reports_a_change(self):
        source, profile = {"example": "source"}, {"example": "profile"}
        observed = {"os_runtime_verified": True, "application_quiesced": True}
        with mock.patch.object(
            self.driver.runtime, "collect", return_value=observed
        ) as collect:
            for check in (False, True):
                result = self.driver.execute(source, profile, check_mode=check)
                self.assertIs(result["observed"], observed)
                self.assertTrue(
                    result["os_runtime_verified"] and result["application_quiesced"]
                )
                self.assertFalse(
                    any(result[key] for key in ("changed", *self.driver.runtime.FLAGS))
                )
        collect.assert_called_with(source, profile, phase="os_quiesced")
        self.assertEqual(collect.call_count, 2)

    def test_unsupported_phase_refuses_before_collector(self):
        with mock.patch.object(self.driver.runtime, "collect") as collect:
            with self.assertRaises(ValueError):
                self.driver.execute({}, {}, phase="unknown_phase")
        collect.assert_not_called()

    def test_active_phase_routes_to_authenticated_read_only_collector(self):
        observed = {
            "os_runtime_verified": True,
            "application_quiesced": False,
            "application_read_verified": True,
        }
        with mock.patch.object(
            self.driver.active, "collect", return_value=observed
        ) as collect, mock.patch.object(
            self.driver.runtime,
            "collect",
            side_effect=AssertionError("no EX/SQL collector"),
        ):
            for check in (False, True):
                value = self.driver.execute(
                    {}, {}, phase="active_writer", check_mode=check
                )
                self.assertTrue(value["application_read_verified"])
                self.assertFalse(value["application_quiesced"])
                self.assertFalse(value["changed"])
                self.assertTrue(
                    all(value[key] is False for key in self.driver.runtime.FLAGS)
                )
        self.assertEqual(collect.call_count, 2)

    def test_error_payload_is_static_and_has_no_mutation_or_health_claim(self):
        for error in (
            RuntimeError("PRIVATE_RUNTIME_SENTINEL"),
            self.driver.runtime.state.PersistenceError("bad\nPRIVATE_CODE"),
        ):
            value = self.driver.failure(error)
            self.assertNotIn("PRIVATE_", json.dumps(value))
            self.assertFalse(
                any(
                    value[key]
                    for key in (
                        "changed",
                        "effects_may_exist",
                        "os_runtime_verified",
                        "application_quiesced",
                        *self.driver.runtime.FLAGS,
                    )
                )
            )

    def test_actual_ansible_preserves_safe_hash_and_redacts_inputs_and_exceptions(self):
        program = """import importlib.util,sys
from pathlib import Path
from ansible.module_utils import basic
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'ansible'))
basic._ANSIBLE_PROFILE='legacy';basic._ANSIBLE_ARGS=sys.stdin.buffer.read()
spec=importlib.util.spec_from_file_location('actual',root/'ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_persistence_runtime.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
if sys.argv[2] in ('error','active-error'):
 def failed(*args,**kwargs):raise RuntimeError('PRIVATE_RUNTIME_SENTINEL')
 d.runtime.collect=failed
 d.active.collect=failed
else:
 d.runtime.collect=lambda source,profile,**kw:{'safe_hash':source['trusted_hash'],'os_runtime_verified':True,'application_quiesced':True}
 if sys.argv[2]=='active':d.active.collect=lambda source,profile:{'safe_hash':source['trusted_hash'],'os_runtime_verified':True,'application_quiesced':False,'application_read_verified':True}
d.main()
"""
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        for mode in ("success", "error", "phase", "active", "active-error"):
            body = {
                "ANSIBLE_MODULE_ARGS": {
                    "source_request": {
                        "trusted_hash": "a" * 64,
                        "raw": "PRIVATE_INPUT_SENTINEL",
                    },
                    "image_profile": {"raw": "PRIVATE_PROGRAM_SENTINEL"},
                    "phase": (
                        "unknown_phase"
                        if mode == "phase"
                        else (
                            "active_writer"
                            if mode.startswith("active")
                            else "os_quiesced"
                        )
                    ),
                    "_ansible_debug": True,
                }
            }
            with tempfile.TemporaryDirectory(
                prefix="runtime-boundary-", dir=ROOT / ".generated"
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
            self.assertEqual(
                result.returncode, 0 if mode in ("success", "active") else 1
            )
            self.assertNotIn(
                "PRIVATE_", result.stdout.decode() + result.stderr.decode()
            )
            if mode in ("success", "active"):
                self.assertEqual(value["observed"]["safe_hash"], "a" * 64)
