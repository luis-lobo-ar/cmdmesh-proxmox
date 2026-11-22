"""Run only synthetic source trees and the standalone inspection artifact."""

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
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
                    {"__main__.py", "inspection.py", "inventory.py", "probes.py"},
                )
                self.assertEqual(
                    archive.read("inventory.py"),
                    (ROOT / "bin/cmdmesh-proxmox").read_bytes(),
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
            for relative in builder.SOURCES.values():
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
            for relative in builder.SOURCES.values():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                shutil.copyfile(ROOT / relative, target)
            source = root / "bin/cmdmesh-proxmox"
            source.unlink()
            source.symlink_to(ROOT / "bin/cmdmesh-proxmox")
            with self.assertRaises(ValueError):
                builder.build(root, root / "inspector.pyz")
            self.assertFalse((root / "inspector.pyz").exists())


if __name__ == "__main__":
    unittest.main()
