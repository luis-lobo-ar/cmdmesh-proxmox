"""Actual bundled phase calls use disposable TLS and explicit synthetic tools."""

import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
import zipapp
import zipfile
import os

import test_memory_collect as fixtures
from test_memory_state import observation


class MemoryPhaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.MemoryCollectTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        fixtures.MemoryCollectTests.tearDownClass.__func__(cls)

    setUp = fixtures.MemoryCollectTests.setUp
    transports = fixtures.MemoryCollectTests.transports
    settings = fixtures.MemoryCollectTests.settings

    def configured(self, tls_port, ssh_port, frame=None):
        wanted, config = self.settings(tls_port, ssh_port, frame)
        tool = Path(config["ssh"]["executable"])
        first, code = tool.read_text().split("\n", 1)
        tool.write_text(
            first
            + "\nimport sys\nif sys.argv[1:]==['-V']:\n print('OpenSSH_9.6p1',file=sys.stderr);sys.exit(0)\n"
            + code
        )
        ansible = self.base / "ansible-playbook"
        ansible.write_text(
            f"#!{sys.executable}\nimport sys\nassert sys.argv[1:]==['--version']\nprint('ansible-playbook [core 2.19.4]')\n"
        )
        ansible.chmod(0o700)
        config["controller"]["tools"] = {"ansible-playbook": str(ansible)}
        return {
            "phase": "prepare",
            "request": wanted,
            "desired_memory_mb": 512,
            "capacity_policy": {
                "mode": "observed-available-headroom",
                "minimum_remaining_bytes": 1024**3,
            },
        }, config

    def inspect(self, value, config):
        result = subprocess.run(
            [str(self.bundle)],
            input=json.dumps(
                {
                    "document_type": "cmdmesh.inspection.request",
                    "schema_version": 1,
                    "operation": "lxc-memory-procedure",
                    "input": value,
                    "config": config,
                }
            ),
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertNotIn("SYNTHETIC_PRIVATE", result.stdout)
        return result.returncode, json.loads(result.stdout)

    def test_prepare_freezes_live_intent_and_emits_exact_bounded_driver_context(self):
        with self.transports() as (tls_port, ssh_port, requests):
            value, config = self.configured(tls_port, ssh_port)
            status, response = self.inspect(value, config)
        self.assertEqual((status, response["outcome"]), (0, "observed"), response)
        data = response["data"]
        self.assertEqual(data["document_type"], "cmdmesh.procedure.assessment")
        self.assertEqual(
            (data["profile_id"], data["profile_version"], data["phase"]),
            ("proxmox-lxc-memory", 1, "prepare"),
        )
        self.assertTrue(data["evidence"]["authenticated_current"])
        self.assertFalse(data["mutation_authorized"])
        self.assertTrue(all(data["checks"].values()))
        self.assertEqual(data["prepared"]["desired_memory_mb"], 512)
        self.assertEqual(
            data["prepared_sha256"],
            hashlib.sha256(
                json.dumps(
                    data["prepared"],
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode()
            ).hexdigest(),
        )
        self.assertEqual(data["driver"]["transport"]["policy"], "strict-direct-ssh-v1")
        self.assertEqual(
            data["driver"]["transport"]["python_executable"], "/usr/bin/python3"
        )
        self.assertEqual(data["driver"]["version"], "2.19.4")
        self.assertEqual(len(data["profile_files"]), 3)
        self.assertEqual(
            set(data["references"]),
            {
                "tls-ca",
                "ssh-identity",
                "ssh-known-hosts",
                "ssh-executable",
                "ansible-executable",
            },
        )
        self.assertEqual(requests, [])

    def test_preflight_recollects_without_rewriting_prepared_or_its_hash(self):
        with self.transports() as (tls_port, ssh_port, _):
            value, config = self.configured(tls_port, ssh_port)
            _, response = self.inspect(value, config)
            prepared = response["data"]["prepared"]
            old = copy.deepcopy(prepared)
            status, checked = self.inspect(
                {"phase": "preflight", "prepared": prepared}, config
            )
        self.assertEqual(status, 0, checked)
        self.assertEqual(checked["data"]["prepared"], old)
        self.assertEqual(
            checked["data"]["prepared_sha256"], response["data"]["prepared_sha256"]
        )
        self.assertNotEqual(
            checked["data"]["evidence"]["observation"]["observed_at_unix_ms"],
            old["baseline"]["observed_at_unix_ms"],
        )

    def test_verify_collects_without_the_ansible_tool_and_preserves_failed_checks(self):
        with self.transports() as (tls_port, ssh_port, _):
            value, config = self.configured(tls_port, ssh_port)
            _, response = self.inspect(value, config)
            prepared = response["data"]["prepared"]
            del config["controller"]["tools"]
            status, checked = self.inspect(
                {"phase": "verify", "prepared": prepared}, config
            )
        self.assertEqual((status, checked["outcome"]), (1, "incomplete"), checked)
        self.assertTrue(checked["data"]["evidence"]["authenticated_current"])
        self.assertFalse(checked["data"]["checks"]["configuration-target"])
        self.assertFalse(checked["data"]["checks"]["enforced-memory-target"])
        self.assertIsNone(checked["data"]["driver"])

    def test_verify_reads_actual_success_or_unenforced_failure(self):
        with self.transports() as (tls_port, ssh_port, _):
            value, config = self.configured(tls_port, ssh_port)
            _, response = self.inspect(value, config)
            prepared = response["data"]["prepared"]
            frame = json.loads((self.base / "frame.json").read_text())
            frame["configuration"].update(memory_mb=512, digest="a" * 40)
            frame["runtime"]["memory_limit_bytes"] = 512 * 1024**2
            (self.base / "frame.json").write_text(json.dumps(frame))
            status, checked = self.inspect(
                {"phase": "verify", "prepared": prepared}, config
            )
            self.assertEqual(status, 0, checked)
            self.assertTrue(all(checked["data"]["checks"].values()))
            frame["runtime"]["memory_limit_bytes"] = 256 * 1024**2
            (self.base / "frame.json").write_text(json.dumps(frame))
            status, checked = self.inspect(
                {"phase": "verify", "prepared": prepared}, config
            )
            self.assertEqual(status, 1, checked)
            self.assertTrue(checked["data"]["checks"]["configuration-target"])
            self.assertFalse(checked["data"]["checks"]["enforced-memory-target"])

    def test_supplied_after_evidence_and_invalid_requests_stop_before_ssh(self):
        for mode in ("after", "origin", "capacity", "phase"):
            with self.subTest(mode=mode), self.transports() as (tls_port, ssh_port, _):
                value, config = self.configured(tls_port, ssh_port)
                if mode == "after":
                    value["after"] = observation()
                elif mode == "origin":
                    config["origin"] = "wrong"
                elif mode == "capacity":
                    value["capacity_policy"]["minimum_remaining_bytes"] = True
                else:
                    value["phase"] = "apply"
                status, response = self.inspect(value, config)
                self.assertEqual(status, 1, response)
                self.assertEqual(response["outcome"], "rejected", response)
                self.assertFalse(self.called.exists())

    def test_prepared_digest_uses_compact_sorted_utf8_json(self):
        with self.transports() as (tls_port, ssh_port, _):
            frame = observation()
            frame["tags"].append("mémoire")
            value, config = self.configured(tls_port, ssh_port, frame)
            status, response = self.inspect(value, config)
        self.assertEqual(status, 0, response)
        expected = hashlib.sha256(
            json.dumps(
                response["data"]["prepared"],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest()
        self.assertEqual(response["data"]["prepared_sha256"], expected)

    def test_changed_referenced_input_during_collection_cannot_prepare_a_plan(self):
        with self.transports() as (tls_port, ssh_port, _):
            value, config = self.configured(tls_port, ssh_port)
            tool = Path(config["ssh"]["executable"])
            code = tool.read_text().replace(
                "else: print(json.dumps(f))",
                f"else:\n Path({config['ssh']['identity_file']!r}).write_text('changed')\n print(json.dumps(f))",
            )
            tool.write_text(code)
            status, response = self.inspect(value, config)
        self.assertEqual(status, 1, response)
        self.assertEqual(response["diagnostics"][0]["code"], "memory-reference-changed")

    def test_bad_profile_metadata_cannot_fall_back_to_mutable_or_supplied_state(self):
        original = self.bundle
        for mode in ("version", "helper", "unknown-path", "missing"):
            with self.subTest(mode=mode), self.transports() as (tls_port, ssh_port, _):
                value, config = self.configured(tls_port, ssh_port)
                archive = io.BytesIO()
                with zipfile.ZipFile(original) as source, zipfile.ZipFile(
                    archive, "w"
                ) as target:
                    for name in source.namelist():
                        if name == "driver-profile.json" and mode == "missing":
                            continue
                        raw = source.read(name)
                        if name == "driver-profile.json":
                            profile = json.loads(raw)
                            if mode == "version":
                                profile["profile_version"] = 2
                            elif mode == "helper":
                                profile["files"][
                                    "ansible/ansible_collections/cmdmesh/proxmox/plugins/module_utils/memory_state.py"
                                ] = ("0" * 64)
                            else:
                                profile["files"]["/private/unapproved"] = "0" * 64
                            raw = json.dumps(profile).encode()
                        target.writestr(name, raw)
                archive.seek(0)
                changed = self.base / (mode + ".pyz")
                zipapp.create_archive(
                    archive, target=changed, interpreter="/usr/bin/env python3"
                )
                changed.chmod(0o700)
                self.bundle = changed
                try:
                    status, response = self.inspect(value, config)
                finally:
                    self.bundle = original
                self.assertEqual(status, 1, response)
                self.assertFalse(self.called.exists())

    def test_fifo_reference_and_unsupported_driver_are_bounded_refusals(self):
        with self.transports() as (tls_port, ssh_port, _):
            value, config = self.configured(tls_port, ssh_port)
            fifo = self.base / "ca-fifo"
            os.mkfifo(fifo)
            config["tls"]["ca_file"] = str(fifo)
            status, response = self.inspect(value, config)
            self.assertEqual(status, 1, response)
            self.assertFalse(self.called.exists())
            config["tls"]["ca_file"] = str(self.ca)
            ansible = Path(config["controller"]["tools"]["ansible-playbook"])
            ansible.write_text(
                f"#!{sys.executable}\nprint('ansible-playbook [core 2.18.0]')\n"
            )
            status, response = self.inspect(value, config)
            self.assertEqual(response["outcome"], "unsupported", response)
            self.assertFalse(self.called.exists())


if __name__ == "__main__":
    unittest.main()
