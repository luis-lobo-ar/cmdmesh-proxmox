"""Execute the rendered Bash wrapper against synthetic vzdump/qm/pct binaries."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

try:
    import jinja2
    import yaml
except ImportError:
    jinja2 = None

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/ansible_collections/cmdmesh/proxmox/roles/proxmox_vm_backup"


@unittest.skipUnless(jinja2, "Install development requirements for template tests")
class BackupWrapperTests(unittest.TestCase):
    def execute(self, exit_code=0):
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            for command in ("vzdump", "qm", "pct"):
                (work / command).symlink_to(ROOT / "tests/fixtures/fake_backup_tool.py")
            env = jinja2.Environment(undefined=jinja2.StrictUndefined)
            env.filters["quote"] = shlex.quote
            variables = {"proxmox_vm_backup_storage": "", "proxmox_vm_backup_tmpdir": "",
                         "proxmox_vm_backup_dir": "/var/lib/vz/demo backup",
                         "proxmox_vm_backup_metrics_dir": str(work), "proxmox_vm_backup_mode": "snapshot",
                         "inventory_hostname": "node-a",
                         "proxmox_vm_backup_jobs": [{"name": "demo", "exclude_paths": ["/data/cache/*"]}]}
            script = work / "backup.sh"
            script.write_text(env.from_string((ROLE / "templates/backup-vm.sh.j2").read_text()).render(variables))
            subprocess.run(["bash", "-n", str(script)], check=True, capture_output=True)
            log = work / "calls.jsonl"
            result = subprocess.run(["bash", str(script), "101", "3", "demo", "lxc"],
                                    text=True, capture_output=True, timeout=5,
                                    env={**os.environ, "PATH": str(work) + os.pathsep + os.environ["PATH"],
                                         "FAKE_BACKUP_LOG": str(log), "FAKE_BACKUP_EXIT": str(exit_code)})
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            metrics = (work / "proxmox_vm_backup_demo.prom").read_text()
            return result, calls, metrics

    def test_success_records_metrics_and_preserves_argument_boundaries(self):
        result, calls, metrics = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[0], ["pct", "config", "101"])
        args = calls[1]
        self.assertEqual(args[0:2], ["vzdump", "101"])
        self.assertEqual(args[args.index("--dumpdir") + 1], "/var/lib/vz/demo backup")
        self.assertEqual(args[args.index("--exclude-path") + 1], "/data/cache/*")
        self.assertIn('backup_job="demo",vmid="101"} 0', metrics)
        self.assertIn("proxmox_vm_backup_last_success_timestamp_seconds", metrics)

    def test_failed_backup_preserves_exit_code_and_does_not_report_success(self):
        result, _, metrics = self.execute(23)
        self.assertEqual(result.returncode, 23)
        self.assertIn('backup_job="demo",vmid="101"} 23', metrics)
        self.assertNotIn("proxmox_vm_backup_last_success_timestamp_seconds", metrics)

    def test_schedules_are_disabled_until_explicit_opt_in(self):
        defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
        self.assertIs(defaults["proxmox_vm_backup_schedule_enabled"], False)
        tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
        start = next(task for task in tasks if task["name"] == "Enable Proxmox VM backup timers")
        self.assertIn("proxmox_vm_backup_schedule_enabled | bool", start["when"])
        self.assertIn("not ansible_check_mode", start["when"])


if __name__ == "__main__":
    unittest.main()
