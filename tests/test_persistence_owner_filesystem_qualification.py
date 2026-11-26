"""Live local facts compared with modeled qualification, never genuine authority."""

import copy
import importlib
import os
from unittest import mock
import unittest

import test_persistence_owner_execution_admission as fixture


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class QualifiedFilesystemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = fixture.ExecutionAdmissionTests
        cls.fixture.setUpClass()
        cls.addClassCleanup(cls.fixture.doClassCleanups)
        cls.module = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_filesystem"
        )
        patch = mock.patch.object(
            cls.module.attempt, "_WALK_ROOT", fixture.storage.RUNTIME_ROOT.parent
        )
        patch.start()
        cls.addClassCleanup(patch.stop)

    def setUp(self):
        self.case = self.fixture("runTest")
        self.case.setUp()
        self.selection = self.case.selection
        with self.module.observe_subject(self.selection) as observed:
            facts = fixture.r.observe.decode(observed.raw)
        q = self.case.docs["filesystem_qualification"]
        q.update(
            subject=copy.deepcopy(facts["subject"]),
            mounts=copy.deepcopy(facts["mounts"]),
            procfs=copy.deepcopy(facts["procfs"]),
        )
        q["roles"] = {
            role: {**row, "probe_index": 0} for role, row in facts["roles"].items()
        }
        q["probes"][0]["mount_index"] = q["roles"]["intent"]["mount_index"]
        self.rehash()

    def rehash(self):
        self.case.docs["admission"]["execution"]["filesystem_qualification_sha256"] = (
            self.case.model.digest(self.case.docs["filesystem_qualification"])
        )

    def test_real_subject_matches_selected_model_and_all_resources_close(self):
        admission = self.case.load()
        count = len(os.listdir("/proc/self/fd"))
        with self.module.hold_qualified_subject(
            selection=self.selection, admission=admission
        ) as held:
            self.assertEqual(
                fixture.r.observe.decode(held.raw)["subject"],
                self.case.docs["filesystem_qualification"]["subject"],
            )
        self.assertTrue(held.closed)
        self.assertEqual(len(os.listdir("/proc/self/fd")), count)

    def test_rehashed_stale_epoch_or_filesystem_id_is_not_live_qualification(self):
        original = copy.deepcopy(self.case.docs)
        for fault in ("epoch", "fsid"):
            self.case.docs = copy.deepcopy(original)
            q = self.case.docs["filesystem_qualification"]
            if fault == "epoch":
                q["subject"]["host_epoch"][
                    "boot_id"
                ] = "00000000-0000-0000-0000-000000000000"
            else:
                q["mounts"][q["roles"]["intent"]["mount_index"]]["statfs_fsid"][0] ^= 1
            self.rehash()
            admission = self.case.load()
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                with self.module.hold_qualified_subject(
                    selection=self.selection, admission=admission
                ):
                    pass

    def test_new_private_parent_fd_still_requires_selected_mount_and_fixed_path(self):
        admission = self.case.load()
        root = fixture.storage.RUNTIME_ROOT
        with self.module.hold_qualified_subject(
            selection=self.selection, admission=admission
        ) as held:
            root.mkdir(mode=0o700)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            foreign = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                self.module.assert_destination_parent(
                    admission=admission, subject=held, role="runtime-profile", fd=fd
                )
                with self.assertRaises(ValueError):
                    self.module.assert_destination_parent(
                        admission=admission,
                        subject=held,
                        role="runtime-profile",
                        fd=foreign,
                    )
            finally:
                os.close(fd)
                os.close(foreign)
                root.rmdir()

    def test_readonly_action_never_enters_write_qualification_path(self):
        admission = self.case.load(action="requalify-complete")
        with mock.patch.object(
            self.module, "observe_subject", side_effect=AssertionError("write guard IO")
        ):
            with self.assertRaises(ValueError):
                with self.module.hold_qualified_subject(
                    selection=self.selection, admission=admission
                ):
                    pass
