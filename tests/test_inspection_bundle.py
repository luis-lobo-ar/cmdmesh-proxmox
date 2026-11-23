"""Run only synthetic source trees and the standalone inspection artifact."""

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = ROOT / ".generated/inspection-tests"
SCRATCH.mkdir(parents=True, exist_ok=True, mode=0o700)


class InspectionBundleTests(unittest.TestCase):
    def test_nonfinite_exponent_input_is_rejected_before_unused_config_can_pass(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            bundle = Path(directory) / "finite.pyz"
            self.assertEqual(self.build(bundle).returncode, 0)
            for number in ("1e999", "-1e999"):
                request = (
                    '{"document_type":"cmdmesh.inspection.request","schema_version":1,"operation":"describe","input":{},"config":{"unused":'
                    + number
                    + "}}"
                )
                result = subprocess.run(
                    [str(bundle)],
                    input=request,
                    text=True,
                    capture_output=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, "")
                response = json.loads(result.stdout)
                self.assertEqual(response["outcome"], "rejected")
                self.assertEqual(response["diagnostics"][0]["code"], "invalid-json")

    def build(self, output):
        return subprocess.run(
            ["python3", str(ROOT / "tools/build_inspector.py"), "--out", str(output)],
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_bundle_is_repeatable_executable_and_contains_only_public_code(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            root = Path(directory)
            first, second = root / "first.pyz", root / "second.pyz"
            for output in (first, second):
                result = self.build(output)
                self.assertEqual(result.returncode, 0, result.stderr)
                receipt = json.loads(result.stdout)
                self.assertEqual(
                    receipt["sha256"], hashlib.sha256(output.read_bytes()).hexdigest()
                )
                self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(
                    set(archive.namelist()),
                    {
                        "__main__.py",
                        "inspection.py",
                        "inventory.py",
                        "probes.py",
                        "memory_state.py",
                        "memory_remote.py",
                        "memory_collect.py",
                        "memory_phase.py",
                        "driver-profile.json",
                    },
                )
                self.assertEqual(
                    archive.read("inventory.py"),
                    (ROOT / "bin/cmdmesh-proxmox").read_bytes(),
                )
                for name in ("memory_state.py", "memory_remote.py"):
                    self.assertEqual(
                        archive.read(name),
                        (
                            ROOT
                            / "ansible/ansible_collections/cmdmesh/proxmox/plugins/module_utils"
                            / name
                        ).read_bytes(),
                    )
            result = subprocess.run(
                [str(first)],
                input=json.dumps(
                    {
                        "document_type": "cmdmesh.inspection.request",
                        "schema_version": 1,
                        "operation": "describe",
                        "input": {},
                        "config": {},
                    }
                ),
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["document_type"], "cmdmesh.inspection.result")
            self.assertEqual(report["operation"], "describe")
            self.assertIn(
                "target-resolve", {action["id"] for action in report["data"]["actions"]}
            )

    def test_build_refuses_existing_output_and_symlinks(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            root = Path(directory)
            existing = root / "existing.pyz"
            existing.write_bytes(b"keep this")
            self.assertNotEqual(self.build(existing).returncode, 0)
            self.assertEqual(existing.read_bytes(), b"keep this")
            link = root / "link.pyz"
            link.symlink_to(existing)
            self.assertNotEqual(self.build(link).returncode, 0)
            self.assertEqual(existing.read_bytes(), b"keep this")

    def test_bundle_pin_covers_both_reused_and_new_code_without_private_files(self):
        spec = importlib.util.spec_from_file_location(
            "builder", ROOT / "tools/build_inspector.py"
        )
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            root = Path(directory)
            for relative in set(builder.SOURCES.values()) | {
                "ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_memory.py"
            }:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                shutil.copyfile(ROOT / relative, target)
            (root / "private-config.json").write_text(
                "SYNTHETIC_PRIVATE_MUST_NOT_BUNDLE"
            )
            first = root / "first.pyz"
            first_receipt = builder.build(root, first)
            source = root / "bin/cmdmesh-proxmox"
            source.write_bytes(
                source.read_bytes() + b"\n# Synthetic dependency change\n"
            )
            second_receipt = builder.build(root, root / "second.pyz")
            self.assertNotEqual(first_receipt["sha256"], second_receipt["sha256"])
            self.assertNotIn(b"SYNTHETIC_PRIVATE_MUST_NOT_BUNDLE", first.read_bytes())
            self.assertEqual(
                hashlib.sha256(first.read_bytes()).hexdigest(), first_receipt["sha256"]
            )

    def test_symlink_source_cannot_copy_unintended_data_into_a_bundle(self):
        spec = importlib.util.spec_from_file_location(
            "builder", ROOT / "tools/build_inspector.py"
        )
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            root = Path(directory)
            for relative in set(builder.SOURCES.values()) | {
                "ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_memory.py"
            }:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                shutil.copyfile(ROOT / relative, target)
            source = root / "bin/cmdmesh-proxmox"
            source.unlink()
            source.symlink_to(ROOT / "bin/cmdmesh-proxmox")
            with self.assertRaises(ValueError):
                builder.build(root, root / "inspector.pyz")
            self.assertFalse((root / "inspector.pyz").exists())

    def test_hash_only_driver_profile_matches_canonical_code_and_bundled_helpers(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            output = Path(directory) / "profile.pyz"
            result = self.build(output)
            self.assertEqual(result.returncode, 0, result.stderr)
            with zipfile.ZipFile(output) as archive:
                profile = json.loads(archive.read("driver-profile.json"))
                self.assertEqual(
                    profile["document_type"], "cmdmesh.proxmox.driver-profile"
                )
                self.assertEqual(profile["schema_version"], 1)
                self.assertEqual(profile["profile_id"], "proxmox-lxc-memory")
                self.assertEqual(profile["profile_version"], 1)
                expected = {
                    f"ansible/ansible_collections/cmdmesh/proxmox/plugins/{kind}/{name}": hashlib.sha256(
                        (
                            ROOT
                            / f"ansible/ansible_collections/cmdmesh/proxmox/plugins/{kind}/{name}"
                        ).read_bytes()
                    ).hexdigest()
                    for kind, name in (
                        ("modules", "lxc_memory.py"),
                        ("module_utils", "memory_state.py"),
                        ("module_utils", "memory_remote.py"),
                    )
                }
                self.assertEqual(profile["files"], expected)
                for name in ("memory_state.py", "memory_remote.py"):
                    self.assertEqual(
                        profile["files"][
                            f"ansible/ansible_collections/cmdmesh/proxmox/plugins/module_utils/{name}"
                        ],
                        hashlib.sha256(archive.read(name)).hexdigest(),
                    )
                self.assertNotIn("lxc_memory.py", archive.namelist())

    def test_driver_change_changes_bundle_pin_without_copying_or_executing_driver(self):
        spec = importlib.util.spec_from_file_location(
            "builder", ROOT / "tools/build_inspector.py"
        )
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        driver = (
            "ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_memory.py"
        )
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            root = Path(directory)
            for relative in set(builder.SOURCES.values()) | {driver}:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                shutil.copyfile(ROOT / relative, target)
            first = builder.build(root, root / "first.pyz")
            (root / driver).write_text(
                "raise SystemExit('SYNTHETIC_DRIVER_MUST_NOT_EXECUTE_OR_BUNDLE')\n"
            )
            second = builder.build(root, root / "second.pyz")
            self.assertNotEqual(first["sha256"], second["sha256"])
            self.assertNotIn(
                b"SYNTHETIC_DRIVER_MUST_NOT_EXECUTE_OR_BUNDLE",
                (root / "second.pyz").read_bytes(),
            )
            (root / driver).unlink()
            (root / driver).symlink_to(ROOT / driver)
            with self.assertRaises(ValueError):
                builder.build(root, root / "symlink.pyz")

    def test_profile_uses_the_same_captured_helper_bytes_if_source_changes_during_build(
        self,
    ):
        spec = importlib.util.spec_from_file_location(
            "builder", ROOT / "tools/build_inspector.py"
        )
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            root = Path(directory)
            for relative in set(builder.SOURCES.values()) | {builder.DRIVER_SOURCE}:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                shutil.copyfile(ROOT / relative, target)
            original = Path.read_bytes
            changed = [False]
            helper = root / builder.SOURCES["memory_state.py"]

            def read(path):
                if path == root / builder.DRIVER_SOURCE and not changed[0]:
                    helper.write_bytes(
                        original(helper) + b"\n# synthetic concurrent change\n"
                    )
                    changed[0] = True
                return original(path)

            with mock.patch.object(Path, "read_bytes", read):
                builder.build(root, root / "captured.pyz")
            self.assertTrue(changed[0])
            with zipfile.ZipFile(root / "captured.pyz") as archive:
                profile = json.loads(archive.read("driver-profile.json"))
                self.assertEqual(
                    profile["files"][builder.SOURCES["memory_state.py"]],
                    hashlib.sha256(archive.read("memory_state.py")).hexdigest(),
                )


if __name__ == "__main__":
    unittest.main()
