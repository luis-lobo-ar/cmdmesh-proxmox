"""Guarded driver tests use mocked native reads or real local Ansible refusal."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from test_memory_state import expected, observation

ROOT = Path(__file__).resolve().parents[1]
COLLECTION = ROOT / "ansible/ansible_collections/cmdmesh/proxmox"
SCRATCH = ROOT / ".generated/memory-driver-tests"
SCRATCH.mkdir(parents=True, exist_ok=True, mode=0o700)
sys.path.insert(0, str(ROOT / "ansible"))
ANSIBLE = shutil.which("ansible-playbook")
GALAXY = shutil.which("ansible-galaxy")


def prepared(desired=512):
    from ansible_collections.cmdmesh.proxmox.plugins.module_utils import memory_state

    return memory_state.prepare(
        expected(),
        observation(),
        desired,
        {"mode": "observed-available-headroom", "minimum_remaining_bytes": 1024**3},
        now_ms=200000,
    )


class MemoryDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "memory_driver", COLLECTION / "plugins/modules/lxc_memory.py"
        )
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def run_driver(
        self,
        wanted=None,
        before=None,
        after=None,
        *,
        check=False,
        allow=True,
        command_error=None
    ):
        wanted = prepared() if wanted is None else wanted
        before = observation() if before is None else before
        if after is None:
            after = observation()
            after["configuration"].update(memory_mb=512, digest="a" * 40)
            after["runtime"]["memory_limit_bytes"] = 512 * 1024**2
        frames = iter((before, after))

        def collect(_request, *, observed_at_unix_ms):
            frame = copy.deepcopy(next(frames))
            frame["observed_at_unix_ms"] = observed_at_unix_ms
            return frame

        with mock.patch.object(
            self.driver.memory_remote, "collect", side_effect=collect
        ) as reads, mock.patch.object(
            self.driver.memory_remote,
            "command",
            side_effect=command_error,
            return_value="",
        ) as command, mock.patch.object(
            self.driver.time, "time_ns", return_value=210000 * 1000000
        ):
            try:
                result = self.driver.execute(
                    wanted, check_mode=check, allow_changes=allow
                )
            except self.driver.MemoryChangeError as error:
                result = error
            return result, reads.call_count, command.call_args_list

    def test_growth_guards_then_runs_one_fixed_digest_protected_memory_command(self):
        result, reads, calls = self.run_driver()
        self.assertIsInstance(result, dict)
        self.assertTrue(result["changed"])
        self.assertTrue(result["mutation_attempted"])
        self.assertEqual(result["command_outcome"], "succeeded")
        self.assertEqual(result["assessment"], "postchecked")
        self.assertEqual(reads, 2)
        self.assertEqual(
            [call.args[0] for call in calls],
            [["/usr/sbin/pct", "set", "101", "--memory", "512", "--digest", "d" * 40]],
        )

    def test_check_mode_reads_but_never_dispatches(self):
        result, reads, calls = self.run_driver(check=True, allow=False)
        self.assertTrue(result["would_change"])
        self.assertFalse(result["mutation_attempted"])
        self.assertEqual(result["command_outcome"], "not-dispatched")
        self.assertEqual(reads, 1)
        self.assertEqual(calls, [])

    def test_noop_needs_no_change_permission_and_never_dispatches(self):
        result, reads, calls = self.run_driver(wanted=prepared(256), allow=False)
        self.assertFalse(result["changed"])
        self.assertFalse(result["would_change"])
        self.assertEqual(reads, 1)
        self.assertEqual(calls, [])

    def test_unapproved_growth_is_refused_before_native_access(self):
        result, reads, calls = self.run_driver(allow=False)
        self.assertIsInstance(result, self.driver.MemoryChangeError)
        self.assertEqual(result.code, "memory-change-disabled")
        self.assertFalse(result.mutation_attempted)
        self.assertEqual(reads, 0)
        self.assertEqual(calls, [])

    def test_wrong_host_owner_generation_digest_or_boot_refuses_before_mutation(self):
        for path, value in [
            (("host_profile", "machine_id_sha256"), "f" * 64),
            (("tags",), ["cmdmesh-ansible"]),
            (("configuration", "digest"), "a" * 40),
            (("host_boot_id_sha256",), "a" * 64),
            (("runtime", "init_start_ticks"), 101),
        ]:
            with self.subTest(path=path):
                before = observation()
                target = before
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                result, _, calls = self.run_driver(before=before)
                self.assertIsInstance(result, self.driver.MemoryChangeError)
                self.assertFalse(result.mutation_attempted)
                self.assertEqual(calls, [])

    def test_zero_exit_without_actual_change_cannot_report_postchecked(self):
        result, reads, calls = self.run_driver(after=observation())
        self.assertIsInstance(result, self.driver.MemoryChangeError)
        self.assertEqual(result.code, "memory-postcondition-failed")
        self.assertEqual(result.command_outcome, "succeeded")
        self.assertTrue(result.mutation_attempted)
        self.assertEqual((reads, len(calls)), (2, 1))

    def test_nonzero_and_deadline_preserve_uncertainty_without_retry(self):
        for code, outcome in (
            ("remote-memory-command-failed", "failed"),
            ("remote-memory-command-deadline", "unknown"),
        ):
            with self.subTest(code=code):
                error = self.driver.memory_remote.RemoteObservationError(code)
                result, reads, calls = self.run_driver(command_error=error)
                self.assertIsInstance(result, self.driver.MemoryChangeError)
                self.assertEqual(result.command_outcome, outcome)
                self.assertTrue(result.mutation_attempted)
                self.assertEqual((reads, len(calls)), (1, 1))

    def test_real_timeout_supervisor_preserves_unknown_command_outcome(self):
        command = self.driver.memory_remote.command
        processes = []
        launch = self.driver.memory_remote.subprocess.Popen

        def observed_launch(*args, **kwargs):
            process = launch(*args, **kwargs)
            processes.append(process)
            return process

        with mock.patch.object(
            self.driver.memory_remote, "COMMAND_TIMEOUT_SECONDS", 0.1
        ):
            with mock.patch.object(
                self.driver.memory_remote,
                "collect",
                return_value={**observation(), "observed_at_unix_ms": 210000},
            ), mock.patch.object(
                self.driver.time, "time_ns", return_value=210000 * 1000000
            ), mock.patch.object(
                self.driver.memory_remote,
                "command",
                side_effect=lambda _args: command(
                    [sys.executable, "-I", "-c", "import time;time.sleep(30)"]
                ),
            ) as dispatched:
                with mock.patch.object(
                    self.driver.memory_remote.subprocess,
                    "Popen",
                    side_effect=observed_launch,
                ):
                    with self.assertRaises(self.driver.MemoryChangeError) as raised:
                        self.driver.execute(
                            prepared(), check_mode=False, allow_changes=True
                        )
        self.assertTrue(raised.exception.mutation_attempted)
        self.assertEqual(
            raised.exception.command_outcome,
            "unknown",
            {
                "aggregate_statuses": [p.returncode for p in processes],
                "code": raised.exception.code,
            },
        )
        self.assertEqual(dispatched.call_count, 1)

    def test_reserved_timeout_exit_status_preserves_unknown_outcome(self):
        command = self.driver.memory_remote.command
        with mock.patch.object(
            self.driver.memory_remote,
            "collect",
            return_value={**observation(), "observed_at_unix_ms": 210000},
        ), mock.patch.object(
            self.driver.time, "time_ns", return_value=210000 * 1000000
        ), mock.patch.object(
            self.driver.memory_remote,
            "command",
            side_effect=lambda _args: command(
                ["/usr/bin/python3", "-I", "-c", "raise SystemExit(124)"]
            ),
        ):
            with self.assertRaises(self.driver.MemoryChangeError) as raised:
                self.driver.execute(prepared(), check_mode=False, allow_changes=True)
        self.assertTrue(raised.exception.mutation_attempted)
        self.assertEqual(raised.exception.command_outcome, "unknown")


@unittest.skipUnless(
    ANSIBLE and GALAXY,
    "Ansible and Galaxy are required for real module packaging tests",
)
class MemoryDriverPackagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(dir=SCRATCH)
        cls.addClassCleanup(cls.work.cleanup)
        cls.packaged = Path(cls.work.name)
        cls.installed = cls.packaged / "installed"
        config = cls.packaged / "ansible.cfg"
        config.write_text("[defaults]\nretry_files_enabled = False\n")
        environment = {
            **os.environ,
            "ANSIBLE_CONFIG": str(config),
            "ANSIBLE_HOME": str(cls.packaged / "home"),
        }
        subprocess.run(
            [
                GALAXY,
                "collection",
                "build",
                str(COLLECTION),
                "--output-path",
                str(cls.packaged),
            ],
            check=True,
            capture_output=True,
            timeout=30,
            env=environment,
        )
        archives = list(cls.packaged.glob("*.tar.gz"))
        if len(archives) != 1:
            raise AssertionError("one local collection archive required")
        with tarfile.open(archives[0]) as archive:
            for relative in (
                "plugins/module_utils/memory_state.py",
                "plugins/module_utils/memory_remote.py",
                "plugins/modules/lxc_memory.py",
            ):
                if (
                    archive.extractfile(relative).read()
                    != (COLLECTION / relative).read_bytes()
                ):
                    raise AssertionError(
                        "packaged helper bytes differ from canonical source"
                    )
        subprocess.run(
            [
                GALAXY,
                "collection",
                "install",
                str(archives[0]),
                "-p",
                str(cls.installed),
                "--no-deps",
            ],
            check=True,
            capture_output=True,
            timeout=30,
            env=environment,
        )

    def test_actual_ansible_serialization_retains_safe_subject_key_and_withholds_input(
        self,
    ):
        interpreter = shlex.split(Path(ANSIBLE).read_text().splitlines()[0][2:])
        wanted = prepared()
        code = """
import json,sys
from unittest import mock
sys.path.insert(0,sys.argv[1])
from ansible.module_utils import basic
from ansible_collections.cmdmesh.proxmox.plugins.modules import lxc_memory
params=json.loads(sys.stdin.read())
basic._ANSIBLE_ARGS=json.dumps({'ANSIBLE_MODULE_ARGS':{'prepared':params,'allow_changes':True}}).encode()
if hasattr(basic,'_ANSIBLE_PROFILE'): basic._ANSIBLE_PROFILE='legacy'
with mock.patch.object(lxc_memory,'execute',return_value={'changed':True,'subject_key':params['subject_key'],'mutation_attempted':True,'command_outcome':'succeeded','assessment':'postchecked','checks':{}}):
    lxc_memory.main()
"""
        result = subprocess.run(
            [*interpreter, "-c", code, str(ROOT / "ansible")],
            input=json.dumps(wanted),
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["subject_key"], wanted["subject_key"])
        self.assertEqual(report["invocation"]["module_args"]["prepared"], "withheld")

    def test_framework_argument_rejection_does_not_echo_prepared_values(self):
        interpreter = shlex.split(Path(ANSIBLE).read_text().splitlines()[0][2:])
        valid = prepared()
        valid["baseline"]["tags"].append("SYNTHETIC_PRIVATE_RAW")
        for arguments in (
            {"prepared": "SYNTHETIC_PRIVATE_RAW"},
            {"prepared": valid, "allow_changes": "not-a-boolean"},
        ):
            code = """
import json,sys
sys.path.insert(0,sys.argv[1])
from ansible.module_utils import basic
from ansible_collections.cmdmesh.proxmox.plugins.modules import lxc_memory
basic._ANSIBLE_ARGS=json.dumps({'ANSIBLE_MODULE_ARGS':json.loads(sys.stdin.read())}).encode()
if hasattr(basic,'_ANSIBLE_PROFILE'): basic._ANSIBLE_PROFILE='legacy'
lxc_memory.main()
"""
            result = subprocess.run(
                [*interpreter, "-c", code, str(ROOT / "ansible")],
                input=json.dumps(arguments),
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("SYNTHETIC_PRIVATE_RAW", result.stdout + result.stderr)
            self.assertTrue(json.loads(result.stdout)["failed"])

    def run_module(self, check=False):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            work = Path(directory)
            inventory = work / "inventory.json"
            inventory.write_text(
                json.dumps(
                    {
                        "all": {
                            "hosts": {
                                "disposable-local": {
                                    "ansible_connection": "local",
                                    "ansible_python_interpreter": sys.executable,
                                    "ansible_become": False,
                                }
                            }
                        }
                    }
                )
            )
            variables = work / "vars.json"
            variables.write_text(json.dumps({"memory_prepared": prepared()}))
            play = work / "play.yml"
            play.write_text(
                "- name: Prove packaged refusal locally\n  hosts: all\n  gather_facts: false\n  tasks:\n    - name: Refuse a synthetic nonowned target\n      cmdmesh.proxmox.lxc_memory:\n        prepared: '{{ memory_prepared }}'\n        allow_changes: false\n"
            )
            config = work / "ansible.cfg"
            config.write_text(
                "[defaults]\nhost_key_checking = True\nretry_files_enabled = False\n"
            )
            args = [
                ANSIBLE,
                "-i",
                str(inventory),
                str(play),
                "-e",
                "@" + str(variables),
            ]
            if check:
                args.append("--check")
            return subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=45,
                env={
                    **os.environ,
                    "ANSIBLE_CONFIG": str(config),
                    "ANSIBLE_COLLECTIONS_PATH": str(self.installed),
                    "ANSIBLE_LOCAL_TEMP": str(work / "controller"),
                    "ANSIBLE_REMOTE_TEMP": str(work / "remote"),
                    "ANSIBLE_NOCOLOR": "1",
                },
            )

    def test_actual_ansiballz_imports_canonical_helpers_and_refuses_unapproved_growth(
        self,
    ):
        result = self.run_module()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "memory-change-disabled", result.stdout, result.stdout + result.stderr
        )
        self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_actual_check_mode_refuses_non_proxmox_identity_without_native_mutation(
        self,
    ):
        result = self.run_module(check=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(
            any(
                code in result.stdout
                for code in (
                    "remote-memory-root-required",
                    "remote-memory-host-mismatch",
                )
            ),
            result.stdout + result.stderr,
        )
        self.assertNotIn("Traceback", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
