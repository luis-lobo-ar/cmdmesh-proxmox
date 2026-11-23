"""Fixed remote reads must guard the host before querying a selected LXC."""

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(
    0, str(ROOT / "ansible/ansible_collections/cmdmesh/proxmox/plugins/module_utils")
)
import test_memory_state as fixtures


class MemoryRemoteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import memory_remote

        cls.remote = memory_remote

    def setUp(self):
        self.expected = fixtures.expected()
        self.expected["host_profile"]["machine_id_sha256"] = hashlib.sha256(
            ("1234567890abcdef" * 2).encode()
        ).hexdigest()
        self.reads, self.calls = [], []
        self.config = {
            "memory": 256,
            "swap": 0,
            "digest": "d" * 40,
            "tags": ";".join(fixtures.observation()["tags"]),
            "rootfs": "local:vm-101-disk-0",
        }
        self.lxc = [{"vmid": 101, "status": "running"}]
        self.qemu = []
        self.pending = None
        self.pid = 500

    def read(self, path):
        self.reads.append(str(path))
        data = {
            "/proc/sys/kernel/hostname": "node-a\n",
            "/etc/machine-id": "1234567890abcdef" * 2 + "\n",
            "/proc/sys/kernel/random/boot_id": "12345678-1234-5678-9abc-def012345678\n",
            "/proc/meminfo": "MemTotal: 16777216 kB\nMemAvailable: 8388608 kB\n",
            "/proc/500/stat": "500 (init with ) spaces) S "
            + "0 " * 18
            + "100 "
            + "0 " * 10,
            "/proc/500/cgroup": "0::/lxc/101/ns/init.scope\n",
            "/sys/fs/cgroup/lxc/101/ns/init.scope/memory.max": "max\n",
            "/sys/fs/cgroup/lxc/101/ns/memory.max": "max\n",
            "/sys/fs/cgroup/lxc/101/memory.max": str(256 * 1024**2),
            "/sys/fs/cgroup/lxc/memory.max": "max\n",
            "/sys/fs/cgroup/memory.max": "max\n",
        }
        return data[str(path)]

    def command(self, argv):
        self.calls.append(list(argv))
        if argv[0] == "/usr/bin/dpkg-query":
            return "pve-manager\t9.2.21\npve-container\t6.1.14\n"
        if argv[0] == "/usr/bin/lxc-info":
            return str(self.pid) + "\n"
        if argv[:3] == ["/usr/sbin/pct", "help", "set"]:
            return "--digest: Prevent concurrent config modification\n"
        if argv[:2] == ["/usr/bin/pvesh", "get"]:
            path = argv[2]
            if path.endswith("/lxc"):
                return json.dumps(self.lxc)
            if path.endswith("/qemu"):
                return json.dumps(self.qemu)
            if path.endswith("/config"):
                return json.dumps(self.config)
            if path.endswith("/pending"):
                return json.dumps(
                    self.pending_rows() if self.pending is None else self.pending
                )
        raise AssertionError(argv)

    def pending_rows(self):
        return [
            {"key": key, "value": value}
            for key, value in self.config.items()
            if not isinstance(value, (list, dict))
        ]

    def collect(self):
        with mock.patch.object(
            self.remote.os, "geteuid", return_value=0
        ), mock.patch.object(
            self.remote, "read_text", side_effect=self.read
        ), mock.patch.object(
            self.remote, "command", side_effect=self.command
        ), mock.patch.object(
            self.remote,
            "certificate_digest",
            side_effect=lambda path: (
                "b" * 64 if str(path).endswith("pve-root-ca.pem") else "c" * 64
            ),
        ), mock.patch.object(
            self.remote, "custom_certificate_exists", return_value=False
        ), mock.patch.object(
            self.remote, "local_node_path", return_value=Path("/etc/pve/nodes/node-a")
        ), mock.patch.object(
            self.remote, "namespace_inode", return_value=200
        ):
            return self.remote.collect(self.expected, observed_at_unix_ms=199000)

    def test_collects_real_read_results_instead_of_copying_expected_memory(self):
        value = self.collect()
        import memory_state

        result = memory_state.validate_observation(value, self.expected, now_ms=200000)
        self.assertEqual(result["configuration"]["memory_mb"], 256)
        self.assertEqual(result["runtime"]["memory_limit_bytes"], 256 * 1024**2)
        self.assertEqual(result["runtime"]["init_start_ticks"], 100)
        self.assertEqual(
            result["host_boot_id_sha256"],
            hashlib.sha256(b"12345678-1234-5678-9abc-def012345678").hexdigest(),
        )
        self.assertEqual(result["host_capacity"]["available_bytes"], 8 * 1024**3)
        self.assertTrue(
            all(
                not (call[0] == "/usr/sbin/pct" and call[1] != "help")
                for call in self.calls
            )
        )
        self.assertFalse(any(path.endswith(".key") for path in self.reads))

    def test_missing_malformed_or_changing_host_boot_identity_is_rejected(self):
        original = self.read
        for invalid in ("", "not-a-uuid", "00000000-0000-0000-0000-000000000000"):
            with self.subTest(invalid=invalid), mock.patch.object(
                self,
                "read",
                side_effect=lambda path: (
                    invalid
                    if str(path) == "/proc/sys/kernel/random/boot_id"
                    else original(path)
                ),
            ):
                with self.assertRaises(self.remote.RemoteObservationError):
                    self.collect()
        reads = iter(
            (
                "12345678-1234-5678-9abc-def012345678",
                "22345678-1234-5678-9abc-def012345678",
            )
        )
        with mock.patch.object(
            self,
            "read",
            side_effect=lambda path: (
                next(reads)
                if str(path) == "/proc/sys/kernel/random/boot_id"
                else original(path)
            ),
        ):
            with self.assertRaises(self.remote.RemoteObservationError) as raised:
                self.collect()
        self.assertEqual(raised.exception.code, "remote-memory-host-boot-changed")

    def test_wrong_host_is_rejected_before_any_native_command(self):
        self.expected["selector"]["node"] = "node-b"
        with self.assertRaises(self.remote.RemoteObservationError):
            self.collect()
        self.assertEqual(self.calls, [])

    def test_duplicate_wrong_kind_or_missing_guest_evidence_is_not_selected(self):
        for lxc, qemu in (([], []), (self.lxc * 2, []), (self.lxc, [{"vmid": 101}])):
            self.lxc, self.qemu = lxc, qemu
            with self.assertRaises(self.remote.RemoteObservationError):
                self.collect()
            self.assertFalse(any(call[0] == "/usr/bin/lxc-info" for call in self.calls))

    def test_readable_pending_or_locked_state_remains_evidence_but_cannot_be_ready(
        self,
    ):
        for change in ("pending", "lock"):
            self.config.pop("lock", None)
            self.pending = self.pending_rows() if change == "pending" else None
            if change == "pending":
                next(row for row in self.pending if row["key"] == "memory")[
                    "pending"
                ] = 512
            if change == "lock":
                self.config["lock"] = "backup"
            value = self.collect()
            self.assertTrue(value["complete"])
            self.assertTrue(
                value["configuration"]["pending" if change == "pending" else "locked"]
            )
            import memory_state

            with self.assertRaises(memory_state.MemoryEvidenceError):
                memory_state.validate_observation(value, self.expected, now_ms=200000)

    def test_other_config_digest_excludes_only_memory_and_proxmox_digest(self):
        first = self.collect()["configuration"]["other_sha256"]
        self.config["memory"] = 512
        self.config["digest"] = "f" * 40
        self.assertEqual(self.collect()["configuration"]["other_sha256"], first)
        self.config["rootfs"] = "local:other-owned-volume"
        self.assertNotEqual(self.collect()["configuration"]["other_sha256"], first)

    def test_delete_markers_are_typed_and_false_is_not_pending(self):
        import memory_state

        for marker in (0, 1, 2):
            self.pending = self.pending_rows()
            next(row for row in self.pending if row["key"] == "memory")[
                "delete"
            ] = marker
            value = self.collect()
            self.assertEqual(value["configuration"]["pending"], bool(marker))
            if not marker:
                memory_state.validate_observation(value, self.expected, now_ms=200000)
        for marker in ("0", "1", 3, None, [], False, True):
            self.pending = [{"key": "memory", "delete": marker}]
            with self.assertRaises(self.remote.RemoteObservationError):
                self.collect()

    def test_invalid_lock_shape_is_not_reported_as_unlocked(self):
        for invalid in (None, "", True, 1):
            self.config["lock"] = invalid
            with self.assertRaises(self.remote.RemoteObservationError):
                self.collect()

    def test_malformed_pending_rows_do_not_establish_a_complete_ready_view(self):
        for row in (
            {"key": ""},
            {"key": "memory"},
            {"key": "memory", "value": []},
            {"key": "memory", "value": {}},
            {"key": "memory", "pending": {}},
            {"key": "memory", "value": None},
            {"key": "bad\nkey", "value": "x"},
        ):
            with self.subTest(row=row):
                self.pending = [row]
                with self.assertRaises(self.remote.RemoteObservationError):
                    self.collect()

    def test_native_forced_delete_marker_is_observed_as_pending(self):
        self.pending = self.pending_rows() + [{"key": "unused0", "delete": 2}]
        value = self.collect()
        self.assertTrue(value["configuration"]["pending"])

    def test_native_state_changed_during_collection_cannot_be_complete(self):
        for kind in ("configuration", "pending", "limit", "version"):
            with self.subTest(kind=kind):
                self.setUp()
                original_read, original_command = self.read, self.command
                changed = [False]

                def read(path):
                    if str(path) == "/proc/meminfo":
                        changed[0] = True
                        if kind == "configuration":
                            self.config.update(
                                rootfs="local:other-volume", digest="e" * 40
                            )
                        elif kind == "pending":
                            self.pending = self.pending_rows()
                            next(row for row in self.pending if row["key"] == "memory")[
                                "pending"
                            ] = 512
                    if (
                        kind == "limit"
                        and changed[0]
                        and str(path) == "/sys/fs/cgroup/lxc/101/memory.max"
                    ):
                        return str(128 * 1024**2)
                    return original_read(path)

                def command(argv):
                    if (
                        kind == "version"
                        and changed[0]
                        and argv[0] == "/usr/bin/dpkg-query"
                    ):
                        return "pve-manager\t9.2.22\npve-container\t6.1.14\n"
                    return original_command(argv)

                with mock.patch.object(
                    self, "read", side_effect=read
                ), mock.patch.object(self, "command", side_effect=command):
                    with self.assertRaises(self.remote.RemoteObservationError):
                        self.collect()

    def test_pending_current_view_must_match_complete_typed_scalar_config(self):
        rows = self.pending_rows()
        for pending in ([], rows[:-1], rows + [{"key": "unknown", "value": "x"}]):
            self.pending = pending
            with self.assertRaises(self.remote.RemoteObservationError):
                self.collect()
        for changed in (128, "256"):
            self.pending = self.pending_rows()
            next(row for row in self.pending if row["key"] == "memory")[
                "value"
            ] = changed
            with self.assertRaises(self.remote.RemoteObservationError):
                self.collect()
        self.config["lxc"] = [["lxc.example", "value"]]
        self.pending = None
        self.assertTrue(self.collect()["complete"])

    def test_lxc_ancestor_limits_and_init_identity_are_not_ignored(self):
        original = self.read

        def constrained(path):
            if str(path) == "/sys/fs/cgroup/lxc/memory.max":
                return str(128 * 1024**2)
            return original(path)

        self.read = constrained
        self.assertEqual(self.collect()["runtime"]["memory_limit_bytes"], 128 * 1024**2)
        original_command = self.command
        count = 0

        def restarted(argv):
            nonlocal count
            if argv[0] == "/usr/bin/lxc-info":
                count += 1
                return "500\n" if count == 1 else "501\n"
            return original_command(argv)

        self.command = restarted
        with self.assertRaises(self.remote.RemoteObservationError):
            self.collect()

    def test_missing_config_values_duplicate_json_and_untrusted_input_fail(self):
        del self.config["memory"]
        with self.assertRaises(self.remote.RemoteObservationError):
            self.collect()
        for raw in (
            '{"memory":256,"memory":512}',
            '{"value":NaN}',
            '{"value":1e999}',
            '{"value":-1e999}',
        ):
            with self.assertRaises(self.remote.RemoteObservationError):
                self.remote.load_json(raw)
        self.expected["selector"]["vmid"] = "101; anything"
        with self.assertRaises(self.remote.RemoteObservationError):
            self.collect()

    def test_native_output_and_deadline_fail_without_exposing_raw_values(self):
        self.assertEqual(
            self.remote.command([sys.executable, "-I", "-c", "print('bounded')"]),
            "bounded\n",
        )
        for code in (
            "print('SYNTHETIC_PRIVATE_RESPONSE');raise SystemExit(1)",
            "print('x' * 3000000)",
        ):
            with self.assertRaises(self.remote.RemoteObservationError) as raised:
                self.remote.command([sys.executable, "-I", "-c", code])
            self.assertNotIn("SYNTHETIC_PRIVATE_RESPONSE", str(raised.exception))
        with mock.patch.object(self.remote, "COMMAND_TIMEOUT_SECONDS", 0.1):
            with self.assertRaises(self.remote.RemoteObservationError):
                self.remote.command(
                    [sys.executable, "-I", "-c", "import time;time.sleep(30)"]
                )

    def test_fifo_is_refused_and_missing_root_limit_inherits_known_ancestors(self):
        scratch = ROOT / ".generated/memory-remote-tests"
        scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            fifo = Path(directory) / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(self.remote.RemoteObservationError):
                self.remote.read_text(fifo)
        original = self.read

        def missing_root(path):
            if str(path) == "/sys/fs/cgroup/memory.max":
                raise FileNotFoundError()
            return original(path)

        self.read = missing_root
        self.assertEqual(self.collect()["runtime"]["memory_limit_bytes"], 256 * 1024**2)

    def test_decoder_and_remote_profile_version_contracts_match(self):
        import memory_state

        self.assertEqual(
            self.remote.SUPPORTED_VERSIONS, memory_state.SUPPORTED_VERSIONS
        )


if __name__ == "__main__":
    unittest.main()
