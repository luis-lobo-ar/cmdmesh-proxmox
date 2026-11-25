"""Host mount labels do not establish what the running guest actually sees."""

import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_retained_runtime as runtime,
)
from test_persistence_kernel import model


class RetainedBindTests(unittest.TestCase):
    def setUp(self):
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        tmp = tempfile.TemporaryDirectory(
            prefix="retained-bind-", dir=ROOT / ".generated"
        )
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.guest = self.root / "234/root"
        self.datasets = {}
        rows = []
        for index, (role, target) in enumerate(runtime.GUEST_BINDS.items(), 41):
            path = self.guest / target.lstrip("/")
            path.mkdir(parents=True)
            self.datasets[role] = {
                "name": "tank/reference/" + role,
                "mountpoint": str(path),
                "guid": str(index),
            }
            device = path.stat().st_dev
            rows.append(
                f"{index} 1 {os.major(device)}:{os.minor(device)} / {target} rw,nosuid,nodev - zfs tank/reference/{role} rw\n"
            )
        self.mountinfo = "".join(rows)
        self.binding, self.kernel = model()
        real_fstat = os.fstat
        root_inode = self.guest.stat().st_ino

        def fstat(fd):
            value = real_fstat(fd)
            if value.st_ino == root_inode:
                return SimpleNamespace(st_dev=os.makedev(7, 2))
            return value

        for patch in (
            mock.patch.object(runtime, "PROC_ROOT", self.root),
            mock.patch.object(
                runtime.kernel.reader.memory, "init_state", return_value=(500, 20)
            ),
            mock.patch.object(
                runtime.kernel.reader.memory,
                "read_text",
                side_effect=lambda path: self.mountinfo,
            ),
            mock.patch.object(runtime.os, "fstat", side_effect=fstat),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def test_real_directory_fds_match_both_host_and_guest_backing(self):
        before = len(list(Path("/proc/self/fd").iterdir()))
        value = runtime.collect_bindings(self.binding, self.kernel, self.datasets)
        self.assertEqual(set(value), {"data", "config"})
        for role, item in value.items():
            self.assertEqual(item["host"], item["guest"])
            self.assertEqual(
                item["host"]["inode"],
                Path(self.datasets[role]["mountpoint"]).stat().st_ino,
            )
        self.assertEqual(before, len(list(Path("/proc/self/fd").iterdir())))

    def test_host_path_can_exist_while_guest_bind_has_different_inode(self):
        original = self.guest / "var/lib/reference-ledger"
        old = self.root / "retained-data"
        original.rename(old)
        original.mkdir()
        self.datasets["data"]["mountpoint"] = str(old)
        with self.assertRaises(ValueError):
            runtime.collect_bindings(self.binding, self.kernel, self.datasets)

    def test_guest_path_symlink_is_not_a_bind_even_when_it_reaches_same_inode(self):
        original = self.guest / "var/lib/reference-ledger"
        old = self.root / "retained-data"
        original.rename(old)
        original.symlink_to(old, target_is_directory=True)
        self.datasets["data"]["mountpoint"] = str(old)
        before = len(list(Path("/proc/self/fd").iterdir()))
        with self.assertRaises((ValueError, OSError)):
            runtime.collect_bindings(self.binding, self.kernel, self.datasets)
        self.assertEqual(before, len(list(Path("/proc/self/fd").iterdir())))

    def test_duplicate_wrong_source_read_only_or_foreign_filesystem_refuses(self):
        original = self.mountinfo
        for fault in ("duplicate", "source", "ro", "filesystem", "root", "device"):
            self.mountinfo = original
            if fault == "duplicate":
                self.mountinfo += original.splitlines(keepends=True)[0]
            elif fault == "source":
                self.mountinfo = original.replace(
                    "tank/reference/data", "tank/foreign/data"
                )
            elif fault == "ro":
                self.mountinfo = original.replace(" rw,nosuid", " ro,nosuid")
            elif fault == "filesystem":
                self.mountinfo = original.replace(" - zfs ", " - tmpfs ")
            elif fault == "root":
                self.mountinfo = original.replace(" / /var/lib", " /subset /var/lib")
            else:
                fields = original.splitlines()[0].split()
                self.mountinfo = original.replace(fields[2], "1:9", 1)
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                runtime.collect_bindings(self.binding, self.kernel, self.datasets)

    def test_changed_init_or_mount_table_at_close_refuses(self):
        for fault in ("init", "mounts"):
            with self.subTest(fault=fault):
                if fault == "init":
                    patch = mock.patch.object(
                        runtime.kernel.reader.memory,
                        "init_state",
                        side_effect=[(500, 20), (501, 20)],
                    )
                else:
                    patch = mock.patch.object(
                        runtime.kernel.reader.memory,
                        "read_text",
                        side_effect=[
                            self.mountinfo,
                            self.mountinfo.replace("41 1", "91 1"),
                        ],
                    )
                with patch, self.assertRaises(ValueError):
                    runtime.collect_bindings(self.binding, self.kernel, self.datasets)

    def test_host_directory_replaced_during_closing_mount_read_refuses(self):
        calls = 0

        def table(path):
            nonlocal calls
            calls += 1
            if calls == 2:
                data = Path(self.datasets["data"]["mountpoint"])
                data.rename(self.root / "previous-data")
                data.mkdir()
            return self.mountinfo

        with mock.patch.object(
            runtime.kernel.reader.memory, "read_text", side_effect=table
        ):
            with self.assertRaises(ValueError):
                runtime.collect_bindings(self.binding, self.kernel, self.datasets)

    def test_init_change_during_last_root_fd_check_refuses(self):
        previous = runtime.os.fstat
        state = {"reads": 0, "birth": 500}

        def fstat(fd):
            value = previous(fd)
            if not hasattr(value, "st_ino"):
                state["reads"] += 1
                if state["reads"] == 2:
                    state["birth"] = 501
            return value

        with mock.patch.object(
            runtime.os, "fstat", side_effect=fstat
        ), mock.patch.object(
            runtime.kernel.reader.memory,
            "init_state",
            side_effect=lambda pid: (state["birth"], 20),
        ):
            with self.assertRaises(ValueError):
                runtime.collect_bindings(self.binding, self.kernel, self.datasets)
