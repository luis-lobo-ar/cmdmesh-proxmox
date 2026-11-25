"""The Ansible entry point reconstructs trusted evidence before read-only IO."""

import copy
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_writer_execution as writer,
)

NAME = (
    "ansible_collections.cmdmesh.proxmox.plugins.modules.lxc_persistence_owner_current"
)


def arguments():
    return dict(
        prepared_json="{}",
        prepared_sha256="a" * 64,
        completion_json="{}",
        completion_sha256="b" * 64,
        journal={name: "{}" for name in writer.NAMES | {"complete.json"}},
        phase="os_quiesced",
    )


class OwnerCurrentDriverTests(unittest.TestCase):
    def setUp(self):
        self.driver = importlib.import_module(NAME)

    def test_reconstructs_checkpoint_and_preserves_read_only_flags_in_both_modes(self):
        args = arguments()
        expected = {"trusted": "checkpoint"}
        for phase in ("os_quiesced", "stopped"):
            for check in (False, True):
                observed = {
                    "phase": phase,
                    "guest_image_verified": phase == "os_quiesced",
                }
                with self.subTest(phase=phase, check=check), mock.patch.object(
                    self.driver.current.checkpoint_codec,
                    "load_writer_checkpoint",
                    return_value=expected,
                ) as load, mock.patch.object(
                    self.driver.current, "collect", return_value=observed
                ) as collect:
                    value = self.driver.execute(
                        **dict(args, phase=phase), check_mode=check
                    )
                load.assert_called_once_with(
                    prepared_raw=b"{}",
                    prepared_sha256="a" * 64,
                    completion_raw=b"{}",
                    completion_sha256="b" * 64,
                    records={name: b"{}" for name in args["journal"]},
                )
                collect.assert_called_once_with(
                    expected, phase=phase, prior_runtime=None
                )
                self.assertTrue(value["owner_current_verified"])
                self.assertTrue(value["application_quiesced"])
                self.assertIs(value["guest_image_verified"], phase == "os_quiesced")
                self.assertEqual(json.loads(value["result_json"]), observed)
                self.assertEqual(
                    value["result_sha256"],
                    self.driver.state.sha256(value["result_json"].encode()),
                )
                self.assertTrue(
                    all(
                        value[key] is False
                        for key in ("changed", *self.driver.current.runtime.FLAGS)
                    )
                )

    def test_bad_phase_raw_types_or_bounds_refuse_before_codec_and_collection(self):
        for change in (
            {"phase": "PRIVATE_UNSUPPORTED"},
            {"prepared_json": {}},
            {"completion_json": "x" * (4194304 + 1)},
            {"journal": {"complete.json": {}}},
            {"journal": None},
            {"prior_runtime": "PRIVATE_RUNTIME"},
            {"prior_runtime": {"oversized": "x" * (4194304 + 1)}},
        ):
            with self.subTest(change=list(change)), mock.patch.object(
                self.driver.current.checkpoint_codec, "load_writer_checkpoint"
            ) as codec, mock.patch.object(
                self.driver.current, "collect"
            ) as collect, self.assertRaises(
                ValueError
            ):
                self.driver.execute(**dict(arguments(), **change))
            codec.assert_not_called()
            collect.assert_not_called()

    def test_errors_have_static_messages_and_no_success_or_mutation_claim(self):
        for error in (
            RuntimeError("PRIVATE_EXCEPTION"),
            self.driver.state.PersistenceError("PRIVATE\nCODE"),
        ):
            value = self.driver.failure(error)
            self.assertNotIn("PRIVATE", json.dumps(value))
            self.assertFalse(
                any(
                    value[key]
                    for key in (
                        "changed",
                        "effects_may_exist",
                        "owner_current_verified",
                        "application_quiesced",
                        "guest_image_verified",
                        *self.driver.current.runtime.FLAGS,
                    )
                )
            )

    def test_actual_ansible_serialization_withholds_private_inputs_and_exceptions(self):
        script = """import importlib,json,sys
sys.path.insert(0,sys.argv[1]+'/ansible')
from ansible.module_utils import basic
basic._ANSIBLE_PROFILE='legacy';basic._ANSIBLE_ARGS=sys.stdin.buffer.read()
d=importlib.import_module(sys.argv[2])
if sys.argv[3]=='success':
 d.current.checkpoint_codec.load_writer_checkpoint=lambda **kw:{'accepted':True}
 d.current.collect=lambda *a,**kw:{'phase':'os_quiesced','guest_image_verified':True,'safe_hash':'c'*64}
elif sys.argv[3]=='exception':
 def fail(**kw):raise RuntimeError('PRIVATE_EXCEPTION_SENTINEL')
 d.current.checkpoint_codec.load_writer_checkpoint=fail
d.main()
"""
        scratch = ROOT / ".generated"
        scratch.mkdir(mode=0o700, exist_ok=True)
        for mode in ("success", "exception", "real-refusal", "bad-phase", "bad-type"):
            args = dict(
                arguments(),
                prepared_json="PRIVATE_PREPARATION_SENTINEL",
                completion_json="PRIVATE_COMPLETION_SENTINEL",
                journal={
                    name: "PRIVATE_JOURNAL_SENTINEL"
                    for name in writer.NAMES | {"complete.json"}
                },
            )
            if mode == "bad-phase":
                args["phase"] = "PRIVATE_PHASE_SENTINEL"
            if mode == "bad-type":
                args["journal"] = "PRIVATE_TYPE_SENTINEL"
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(
                dir=scratch
            ) as directory:
                proc = subprocess.run(
                    [sys.executable, "-B", "-c", script, str(ROOT), NAME, mode],
                    input=json.dumps(
                        {"ANSIBLE_MODULE_ARGS": dict(args, _ansible_debug=True)}
                    ).encode(),
                    capture_output=True,
                    timeout=20,
                    env={
                        **os.environ,
                        "TMPDIR": directory,
                        "ANSIBLE_LOCAL_TEMP": directory,
                    },
                )
            value = json.loads(proc.stdout)
            self.assertEqual(proc.returncode, 0 if mode == "success" else 1)
            self.assertNotIn("PRIVATE_", (proc.stdout + proc.stderr).decode())
            if mode == "success":
                self.assertEqual(
                    json.loads(value["result_json"])["safe_hash"], "c" * 64
                )
                self.assertTrue(value["owner_current_verified"])
            else:
                self.assertTrue(value["failed"])

    @unittest.skipUnless(
        os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
    )
    def test_real_checkpoint_codec_precedes_collection_and_rejects_raw_record_drift(
        self,
    ):
        import test_persistence_owner_checkpoint as fixtures

        case = fixtures.OwnerCheckpointTests("runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        args = dict(
            prepared_json=case.base.raw.decode(),
            prepared_sha256=case.base.sha,
            completion_json=case.raw.decode(),
            completion_sha256=case.sha,
            journal={name: raw.decode() for name, raw in case.records.items()},
            phase="os_quiesced",
        )
        expected = case.load()
        with mock.patch.object(
            self.driver.current,
            "collect",
            return_value={"phase": "os_quiesced", "guest_image_verified": True},
        ) as collect:
            self.driver.execute(**args)
        self.assertEqual(collect.call_args.args[0], expected)
        changed = copy.deepcopy(args)
        changed["journal"]["before-read.json"] = "{}"
        with mock.patch.object(
            self.driver.current, "collect"
        ) as collect, self.assertRaises(ValueError):
            self.driver.execute(**changed)
        collect.assert_not_called()


@unittest.skipUnless(
    shutil.which("ansible-playbook") and shutil.which("ansible-galaxy"),
    "provide Ansible",
)
class OwnerCurrentPackagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(dir=ROOT / ".generated")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.root = Path(cls.scratch.name)
        cls.installed = cls.root / "installed"
        cls.env = {
            **os.environ,
            "ANSIBLE_HOME": str(cls.root / "home"),
            "ANSIBLE_LOCAL_TEMP": str(cls.root / "controller"),
            "ANSIBLE_REMOTE_TEMP": str(cls.root / "remote"),
            "ANSIBLE_NOCOLOR": "1",
        }
        cls.env.pop("ANSIBLE_COLLECTIONS_PATH", None)
        for argv in (
            [
                "ansible-galaxy",
                "collection",
                "build",
                str(ROOT / "ansible/ansible_collections/cmdmesh/proxmox"),
                "--output-path",
                str(cls.root),
            ],
            [
                "ansible-galaxy",
                "collection",
                "install",
                str(cls.root / "cmdmesh-proxmox-0.2.2.tar.gz"),
                "-p",
                str(cls.installed),
                "--no-deps",
            ],
        ):
            subprocess.run(
                argv, check=True, capture_output=True, timeout=30, env=cls.env
            )

    def test_actual_packaged_module_refuses_before_any_current_host_observation(self):
        variables = dict(arguments(), prepared_json="PRIVATE_UNQUALIFIED_PREPARATION")
        (self.root / "vars.json").write_text(json.dumps(variables))
        play = self.root / "play.yml"
        play.write_text(
            "- hosts: localhost\n  gather_facts: false\n  tasks:\n    - name: Refuse unqualified authority\n      cmdmesh.proxmox.lxc_persistence_owner_current:\n        prepared_json: '{{ prepared_json }}'\n        prepared_sha256: '{{ prepared_sha256 }}'\n        completion_json: '{{ completion_json }}'\n        completion_sha256: '{{ completion_sha256 }}'\n        journal: '{{ journal }}'\n        phase: os_quiesced\n"
        )
        for check in (False, True):
            argv = [
                "ansible-playbook",
                "-i",
                "localhost,",
                "-c",
                "local",
                str(play),
                "-e",
                "@" + str(self.root / "vars.json"),
            ]
            if check:
                argv.append("--check")
            with self.subTest(check=check):
                proc = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=45,
                    env={**self.env, "ANSIBLE_COLLECTIONS_PATH": str(self.installed)},
                )
                self.assertNotEqual(proc.returncode, 0)
                text = proc.stdout + proc.stderr
                self.assertIn('"owner_current_verified": false', text)
                self.assertIn('"mutation_attempted": false', text)
                self.assertNotIn("PRIVATE_", text)
                self.assertNotIn("Traceback", text)
                self.assertNotIn("couldn't resolve module", text)


if __name__ == "__main__":
    unittest.main()
