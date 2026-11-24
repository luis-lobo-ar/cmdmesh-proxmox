"""Run actual Ansible locally against a synthetic pct executable, never SSH."""
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
COLLECTIONS = ROOT / "ansible/ansible_collections"
ANSIBLE = shutil.which("ansible-playbook")


@unittest.skipUnless(ANSIBLE, "ansible-playbook is required for behavioral role tests")
class GuestRoleTests(unittest.TestCase):
    def run_role(self, role, variables, check=False, initial=None):
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            (work / "pct").symlink_to(ROOT / "tests/fixtures/fake_pct.py")
            for tool in ("pvesh", "pvesm"):
                (work / tool).symlink_to(ROOT / "tests/fixtures/fake_nfs_tool.py")
            state = work / "state.json"
            state.write_text(json.dumps(initial or {"memory": 1024, "swap": 512, "disk": 8}))
            log = work / "calls.jsonl"
            inventory = work / "inventory.json"
            inventory.write_text(json.dumps({"all": {"hosts": {
                "pve-test": {"ansible_connection": "local", "ansible_python_interpreter": sys.executable, "ansible_become": False,
                             "proxmox_node": "node-a", "lifecycle_owner": "ansible"},
                "guest-demo": {"proxmox_node": "node-a", "proxmox_vmid": 101,
                               "proxmox_lxc_memory_mb": 2048, "proxmox_lxc_swap_mb": 512,
                               "proxmox_lxc_rootfs_size_gb": 16}},
                "children": {"cmdmesh_targets": {"hosts": {"pve-test": {}}}}}}))
            varfile = work / "vars.json"
            varfile.write_text(json.dumps(variables))
            command = [ANSIBLE, "-i", str(inventory), str(ROOT / "ansible/ansible_collections/cmdmesh/proxmox/playbooks" / (role + ".yml")),
                       "-e", "@" + str(varfile), "--limit", "pve-test"]
            if check:
                command.append("--check")
            result = subprocess.run(command, capture_output=True, text=True, timeout=45,
                                    env={**os.environ, "ANSIBLE_COLLECTIONS_PATH": str(COLLECTIONS),
                                         "PATH": str(work) + os.pathsep + os.environ["PATH"],
                                         "FAKE_PCT_STATE": str(state), "FAKE_PCT_LOG": str(log),
                                         "ANSIBLE_NOCOLOR": "1", "ANSIBLE_LOCAL_TEMP": str(work / "ansible")})
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result, json.loads(state.read_text()), calls

    def test_unapproved_apply_fails_before_pct(self):
        result, state, calls = self.run_role("lxc_resources", {"proxmox_lxc_resources_guests": ["guest-demo"]})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])
        self.assertEqual(state["memory"], 1024)

    def test_terraform_owned_guest_fails_before_pct(self):
        result, _, calls = self.run_role("lxc_resources", {"lifecycle_owner": "terraform", "proxmox_lxc_resources_guests": ["guest-demo"]}, check=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_empty_guest_selection_fails(self):
        result, _, calls = self.run_role("lxc_resources", {}, check=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_resource_check_reads_but_never_writes(self):
        result, state, calls = self.run_role("lxc_resources", {"proxmox_lxc_resources_guests": ["guest-demo"]}, check=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["memory"], 1024)
        self.assertEqual(calls, [["config", "101"]])

    def test_approved_resource_growth(self):
        result, state, calls = self.run_role("lxc_resources", {"cmdmesh_allow_changes": True, "proxmox_lxc_resources_guests": ["guest-demo"]})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["memory"], 2048)
        self.assertIn(["set", "101", "--memory", "2048"], calls)

    def test_memory_shrink_is_rejected(self):
        result, state, calls = self.run_role("lxc_resources", {"cmdmesh_allow_changes": True, "proxmox_lxc_resources_guests": ["guest-demo"]}, initial={"memory": 4096, "swap": 512, "disk": 8})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state["memory"], 4096)
        self.assertEqual(calls, [["config", "101"]])

    def test_storage_check_never_resizes(self):
        result, state, calls = self.run_role("lxc_storage", {"proxmox_lxc_storage_guests": ["guest-demo"]}, check=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["disk"], 8)
        self.assertEqual(calls, [["config", "101"]])

    def test_storage_growth(self):
        result, state, calls = self.run_role("lxc_storage", {"cmdmesh_allow_changes": True, "proxmox_lxc_storage_guests": ["guest-demo"]})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["disk"], 16)
        self.assertIn(["resize", "101", "rootfs", "16G"], calls)

    def test_disk_shrink_is_rejected(self):
        result, state, calls = self.run_role("lxc_storage", {"cmdmesh_allow_changes": True, "proxmox_lxc_storage_guests": ["guest-demo"]}, initial={"memory": 1024, "swap": 512, "disk": 32})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state["disk"], 32)
        self.assertEqual(calls, [["config", "101"]])

    def test_backup_accepts_a_safe_explicit_staging_directory(self):
        result, _, _ = self.run_role("backup", {
            "proxmox_vm_backup_tmpdir": "/var/tmp/backup-staging",
            "proxmox_vm_backup_jobs": [{"name": "demo", "vmid": 101, "keep_last": 3,
                                         "on_calendar": "*-*-* 03:00:00", "guest_type": "lxc"}],
        }, check=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_duplicate_backup_job_names_are_rejected(self):
        job = {"name": "demo", "vmid": 101, "keep_last": 3, "on_calendar": "daily"}
        result, _, _ = self.run_role("backup", {"proxmox_vm_backup_jobs": [job, job]}, check=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unique", result.stdout)

    def test_inactive_nfs_storage_is_not_accepted_as_active(self):
        result, _, _ = self.run_role("nfs_backup_storage", {
            "proxmox_nfs_backup_storage_enabled": True,
            "proxmox_nfs_backup_storage_id": "demo-backup",
            "proxmox_nfs_backup_storage_server": "backup.example.invalid",
            "proxmox_nfs_backup_storage_export": "/backups",
            "proxmox_nfs_backup_storage_status_retries": 1,
            "proxmox_nfs_backup_storage_status_delay": 0,
        }, check=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Wait for Proxmox NFS backup storage to become active", result.stdout)

    def test_active_nfs_storage_passes_read_only_assessment(self):
        with mock.patch.dict(os.environ, {"FAKE_NFS_STATUS": "active"}):
            result, _, _ = self.run_role("nfs_backup_storage", {
                "proxmox_nfs_backup_storage_enabled": True,
                "proxmox_nfs_backup_storage_id": "demo-backup",
                "proxmox_nfs_backup_storage_server": "backup.example.invalid",
                "proxmox_nfs_backup_storage_export": "/backups",
                "proxmox_nfs_backup_storage_status_retries": 1,
                "proxmox_nfs_backup_storage_status_delay": 0,
            }, check=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_create_only_refuses_an_existing_storage_before_package_changes(self):
        with mock.patch.dict(os.environ, {"FAKE_NFS_STATUS": "active"}):
            result, _, _ = self.run_role("nfs_backup_storage", {
                "proxmox_nfs_backup_storage_enabled": True,
                "proxmox_nfs_backup_storage_create_only": True,
                "proxmox_nfs_backup_storage_id": "demo-backup",
                "proxmox_nfs_backup_storage_server": "backup.example.invalid",
                "proxmox_nfs_backup_storage_export": "/backups",
            }, check=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Create-only NFS storage already exists", result.stdout)
        self.assertNotIn("TASK [cmdmesh.proxmox.proxmox_nfs_backup_storage : Install NFS client support]", result.stdout)

    def test_new_storage_check_does_not_create_or_claim_mount_readiness(self):
        with mock.patch.dict(os.environ, {"FAKE_NFS_EXISTING": "false"}):
            result, _, _ = self.run_role("nfs_backup_storage", {
                "proxmox_nfs_backup_storage_enabled": True,
                "proxmox_nfs_backup_storage_create_only": True,
                "proxmox_nfs_backup_storage_id": "demo-backup",
                "proxmox_nfs_backup_storage_server": "backup.example.invalid",
                "proxmox_nfs_backup_storage_export": "/backups",
            }, check=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Require the new mountpoint to remain absent", result.stdout)
        self.assertIn("skipping: [pve-test]", result.stdout)


if __name__ == "__main__":
    unittest.main()
