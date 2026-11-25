"""Exercise real Ansible serialization and the installed collection boundary."""

import ast
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

from test_persistence_owner_os_driver import args, NAME

ROOT = Path(__file__).resolve().parents[1]
COLLECTION = ROOT / "ansible/ansible_collections/cmdmesh/proxmox"
MAIN = r"""
import importlib,json,sys
sys.path.insert(0,sys.argv[1]+'/ansible')
from ansible.module_utils import basic
basic._ANSIBLE_PROFILE='legacy'
basic._ANSIBLE_ARGS=sys.stdin.buffer.read()
driver=importlib.import_module(sys.argv[2]);mode=sys.argv[3]
def forbidden(*a,**kw):raise AssertionError('UNEXPECTED_NATIVE_OR_WRITE')
driver.sdk.observe.native=forbidden
driver.sdk.api.post_guest_action=forbidden
if mode not in {'codec-refusal','bad-action','bad-type','bad-bool','missing-pair','disabled'}:
 driver.sdk.current.checkpoint_codec.load_writer_checkpoint=lambda **kw:{'trusted':True}
 driver.sdk.initialize=forbidden;driver.sdk.operate=forbidden
 if mode=='prepare':driver.sdk.prepare=lambda *a,**kw:{'safe_hash':'c'*64}
 elif mode=='status':driver.sdk.status=lambda *a,**kw:{'os_transition_verified':True,'mutation_attempted':False,'safe_hash':'c'*64}
 elif mode in {'initialize-check','transition-check'}:
  driver.sdk.inspect_initialization=lambda *a,**kw:{'would_change':True}
  driver.sdk.inspect_transition=lambda *a,**kw:{'would_change':True}
 elif mode.startswith('exception-'):
  kind={'RuntimeError':RuntimeError,'TypeError':TypeError,'OSError':OSError}[mode.split('-')[1]]
  def fail(*a,**kw):raise kind('PRIVATE_EXCEPTION_SENTINEL')
  driver.sdk.operate=fail
driver.main()
"""


@unittest.skipUnless(importlib.util.find_spec("ansible"), "provide Ansible")
class OwnerOsSerializationTests(unittest.TestCase):
    def test_real_main_preserves_safe_receipts_and_suppresses_private_inputs(self):
        successful = {"prepare", "status", "initialize-check", "transition-check"}
        for mode in (
            *sorted(successful),
            "disabled",
            "codec-refusal",
            "bad-action",
            "bad-type",
            "bad-bool",
            "missing-pair",
            "exception-RuntimeError",
            "exception-TypeError",
            "exception-OSError",
        ):
            action = (
                "prepare"
                if mode == "prepare"
                else (
                    "status"
                    if mode == "status"
                    else ("initialize" if mode == "initialize-check" else "transition")
                )
            )
            values = args(action)
            values.update(
                prepared_json="PRIVATE_PREPARATION_SENTINEL",
                completion_json="PRIVATE_COMPLETION_SENTINEL",
                journal={
                    name: "PRIVATE_JOURNAL_SENTINEL" for name in values["journal"]
                },
                _ansible_debug=True,
            )
            if mode == "bad-action":
                values["action"] = "PRIVATE_ACTION_SENTINEL"
            if mode == "bad-type":
                values["journal"] = "PRIVATE_TYPE_SENTINEL"
            if mode == "bad-bool":
                values["allow_mutation"] = "PRIVATE_BOOLEAN_SENTINEL"
            if mode == "missing-pair":
                values.pop("transition_prepared_sha256")
            if mode.endswith("-check"):
                values["_ansible_check_mode"] = True
            if mode.startswith("exception-") or mode == "codec-refusal":
                values["allow_mutation"] = True
            with self.subTest(mode=mode):
                process = subprocess.run(
                    [sys.executable, "-B", "-c", MAIN, str(ROOT), NAME, mode],
                    input=json.dumps({"ANSIBLE_MODULE_ARGS": values}).encode(),
                    capture_output=True,
                    timeout=20,
                )
                text = (process.stdout + process.stderr).decode()
                self.assertEqual(
                    process.returncode, 0 if mode in successful else 1, text
                )
                self.assertNotIn("PRIVATE_", text)
                self.assertNotIn("Traceback", text)
                value = json.loads(process.stdout)
                if mode in successful:
                    self.assertEqual(
                        value["invocation"]["module_args"]["prepared_sha256"],
                        "withheld",
                    )
                    if mode in {"prepare", "status"}:
                        key = (
                            "transition_prepared_json"
                            if mode == "prepare"
                            else "result_json"
                        )
                        self.assertEqual(json.loads(value[key])["safe_hash"], "c" * 64)
                    else:
                        for flag in (
                            "os_transition_verified",
                            "metadata_initialized",
                            "mutation_attempted",
                        ):
                            self.assertIs(value[flag], False)
                elif mode.startswith("exception-"):
                    self.assertIs(value["effects_may_exist"], True)
                    self.assertIs(value["os_transition_verified"], False)
                elif mode in {"disabled", "codec-refusal"}:
                    self.assertIs(value["effects_may_exist"], False)


@unittest.skipUnless(
    shutil.which("ansible-playbook") and shutil.which("ansible-galaxy"),
    "provide Ansible",
)
class OwnerOsInstalledTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(dir=ROOT / ".generated")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.root = Path(cls.scratch.name)
        cls.installed = cls.root / "installed"
        config = cls.root / "ansible.cfg"
        config.write_text(
            "[defaults]\nstdout_callback=default\nretry_files_enabled=False\n"
        )
        cls.environment = {
            **os.environ,
            "ANSIBLE_CONFIG": str(config),
            "ANSIBLE_HOME": str(cls.root / "home"),
            "ANSIBLE_LOCAL_TEMP": str(cls.root / "controller"),
            "ANSIBLE_REMOTE_TEMP": str(cls.root / "remote"),
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_KEEP_REMOTE_FILES": "1",
        }
        cls.environment.pop("ANSIBLE_COLLECTIONS_PATH", None)
        subprocess.run(
            [
                "ansible-galaxy",
                "collection",
                "build",
                str(COLLECTION),
                "--output-path",
                str(cls.root),
            ],
            check=True,
            capture_output=True,
            timeout=45,
            env=cls.environment,
        )
        archives = list(cls.root.glob("cmdmesh-proxmox-*.tar.gz"))
        if len(archives) != 1:
            raise AssertionError("expected one freshly built collection archive")
        subprocess.run(
            [
                "ansible-galaxy",
                "collection",
                "install",
                str(archives[0]),
                "-p",
                str(cls.installed),
                "--no-deps",
            ],
            check=True,
            capture_output=True,
            timeout=45,
            env=cls.environment,
        )

    def test_installed_normal_and_check_refuse_before_host_access_with_exact_zip(self):
        values = dict(
            args("transition"),
            allow_mutation=True,
            prepared_json="PRIVATE_UNQUALIFIED_WRITER",
            completion_json="PRIVATE_COMPLETION",
        )
        (self.root / "vars.json").write_text(json.dumps(values))
        parameters = {name: "{{ " + name + " }}" for name in values}
        play = [
            {
                "hosts": "localhost",
                "gather_facts": False,
                "tasks": [
                    {
                        "name": "Refuse unqualified writer evidence",
                        "cmdmesh.proxmox.lxc_persistence_owner_os": parameters,
                    }
                ],
            }
        ]
        path = self.root / "play.json"
        path.write_text(json.dumps(play))
        environment = {
            **self.environment,
            "ANSIBLE_COLLECTIONS_PATH": str(self.installed),
        }
        before = set(
            (self.root / "remote").rglob("AnsiballZ_lxc_persistence_owner_os.py")
        )
        for check in (False, True):
            command = [
                "ansible-playbook",
                "-i",
                "localhost,",
                "-c",
                "local",
                str(path),
                "-e",
                "@" + str(self.root / "vars.json"),
            ]
            if check:
                command.append("--check")
            with self.subTest(check=check):
                process = subprocess.run(
                    command, capture_output=True, text=True, timeout=60, env=environment
                )
                text = process.stdout + process.stderr
                self.assertNotEqual(process.returncode, 0)
                self.assertIn('"mutation_attempted": false', text)
                self.assertIn('"os_transition_verified": false', text)
                self.assertNotIn("PRIVATE_", text)
                self.assertNotIn("Traceback", text)
                self.assertNotIn("couldn't resolve module", text)
        wrappers = (
            set((self.root / "remote").rglob("AnsiballZ_lxc_persistence_owner_os.py"))
            - before
        )
        self.assertEqual(len(wrappers), 2)
        required = {
            "persistence_owner_transition",
            "persistence_owner_journal",
            "persistence_owner_checkpoint",
            "persistence_owner_current",
            "persistence_retained_runtime",
            "persistence_guest_api",
        }
        prefix = "ansible_collections/cmdmesh/proxmox/plugins/"
        for wrapper in wrappers:
            tree = ast.parse(wrapper.read_text())
            call = next(
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_ansiballz_main"
            )
            encoded = next(
                keyword.value.value
                for keyword in call.keywords
                if keyword.arg == "zip_data"
            )
            with zipfile.ZipFile(io.BytesIO(base64.b64decode(encoded))) as archive:
                names = {
                    name
                    for name in archive.namelist()
                    if name.startswith(prefix)
                    and name.endswith(".py")
                    and not name.endswith("/__init__.py")
                }
                self.assertTrue(
                    {prefix + "module_utils/" + name + ".py" for name in required}
                    <= names
                )
                self.assertIn(prefix + "modules/lxc_persistence_owner_os.py", names)
                for name in names:
                    self.assertEqual(
                        archive.read(name), (ROOT / "ansible" / name).read_bytes(), name
                    )


if __name__ == "__main__":
    unittest.main()
