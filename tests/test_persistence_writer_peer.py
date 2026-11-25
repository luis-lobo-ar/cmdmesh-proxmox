"""An application peer must belong to the admitted guest and systemd service."""

import copy
from dataclasses import replace
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_writer_peer as writer,
    unix_peer,
)
import test_persistence_retained_runtime as fixtures


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class WriterPeerTests(unittest.TestCase):
    def setUp(self):
        self.request, self.profile, self.value = fixtures.model()
        self.kernel = self.value["kernel"]
        init = self.kernel["init"]
        self.root = (os.makedev(*self.kernel["rootfs"]["device"]), 2)
        self.init = unix_peer.ProcessIdentity(
            pid=init["pid"],
            birth=init["pstart"],
            pid_namespace=init["pid_namespace_inode"],
            mount_namespace=800,
            uid=100000,
            gid=100000,
            nspid=(init["pid"], 1),
            root=self.root,
            executable=(7, 8),
            argv=("/sbin/init",),
            cgroup=self.kernel["cgroup"]["path"] + "\n",
        )
        self.pid = 321
        self.image = copy.deepcopy(self.value["image"])
        self.image["unit"].update(
            ActiveState="active", SubState="running", MainPID=str(self.pid)
        )
        self.image["accounts"].update(
            uid_processes=[self.pid], gid_processes=[self.pid]
        )
        self.python = (self.root[0], 99)
        self.peer = unix_peer.ProcessIdentity(
            pid=9999,
            birth=9000,
            pid_namespace=self.init.pid_namespace,
            mount_namespace=self.init.mount_namespace,
            uid=101100,
            gid=101100,
            nspid=(9999, self.pid),
            root=self.root,
            executable=self.python,
            argv=writer.ARGV,
            cgroup=self.init.cgroup.rstrip("\n").rsplit("/", 1)[0]
            + "/system.slice/reference-ledger.service\n",
        )

    def validate(self, peer=None, init=None, image=None, python=None):
        writer.validate(
            self.request,
            self.profile,
            self.kernel,
            self.image if image is None else image,
            self.init if init is None else init,
            self.peer if peer is None else peer,
            self.python if python is None else python,
        )

    def test_exact_guest_and_service_process_is_purely_accepted(self):
        with mock.patch(
            "subprocess.run", side_effect=AssertionError("pure validation")
        ), mock.patch("sqlite3.connect", side_effect=AssertionError("no host SQL")):
            self.validate()

    def test_wrong_namespace_root_mapping_command_or_service_refuses(self):
        for field, value in (
            ("birth", self.init.birth - 1),
            ("pid_namespace", self.init.pid_namespace + 1),
            ("mount_namespace", self.init.mount_namespace + 1),
            ("root", (7, 999)),
            ("uid", 1100),
            ("gid", 1100),
            ("nspid", (self.peer.pid, self.pid + 1)),
            ("executable", (7, 100)),
            ("argv", ("/wrong-program",)),
            ("cgroup", self.init.cgroup),
        ):
            with self.subTest(field=field):
                peer = replace(self.peer, **{field: value})
                with self.assertRaises(writer.state.PersistenceError):
                    self.validate(peer=peer)

    def test_init_binding_and_image_checks_are_required(self):
        for field, value in (
            ("birth", self.init.birth + 1),
            ("pid_namespace", self.init.pid_namespace + 1),
            ("root", (7, 99)),
            ("uid", 0),
            ("nspid", (self.init.pid, 2)),
            ("cgroup", "0::/wrong/init.scope\n"),
        ):
            with self.subTest(field=field), self.assertRaises(
                writer.state.PersistenceError
            ):
                self.validate(init=replace(self.init, **{field: value}))
        image = copy.deepcopy(self.image)
        image["unit"]["MainPID"] = "322"
        with self.assertRaises(writer.state.PersistenceError):
            self.validate(image=image)
        image = copy.deepcopy(self.image)
        image["accounts"]["uid_processes"].append(322)
        with self.assertRaises(writer.state.PersistenceError):
            self.validate(image=image)
        with self.assertRaises(writer.state.PersistenceError):
            self.validate(python=(True, 99))


if __name__ == "__main__":
    unittest.main()
