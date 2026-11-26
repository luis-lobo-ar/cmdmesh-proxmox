"""Bounded real Linux facts and disposable fixed-role paths, not qualification."""

import importlib
import os
from pathlib import Path
import unittest
from unittest import mock

import test_persistence_owner_continuation_v2 as fixture


class MountInfoTests(unittest.TestCase):
    def setUp(self):
        self.module = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_filesystem"
        )

    def test_mountinfo_decodes_kernel_escapes_and_keeps_distinct_mount_ids(self):
        raw = b"31 20 8:1 / / rw,nosuid shared:1 - ext4 /dev/root rw\n32 31 8:1 /a\\040b /mnt/a\\040b rw - ext4 /dev/root rw\n"
        table = self.module.parse_mountinfo(raw)
        self.assertEqual(set(table), {31, 32})
        self.assertEqual(table[32]["root"], "/a b")
        self.assertEqual(table[32]["target"], "/mnt/a b")
        self.assertEqual(table[31]["options"], ["nosuid", "rw"])
        self.assertEqual(table[31]["device"], [8, 1])

    def test_duplicate_ids_bad_framing_escapes_and_limits_refuse(self):
        good = b"31 20 8:1 / / rw - ext4 /dev/root rw\n"
        for raw in (
            good + good,
            good[:-1],
            good.replace(b" - ", b" "),
            good.replace(b"/dev/root", b"/dev/\\999"),
            good.replace(b"31 20", b"True 20"),
            b"x" * (2097152 + 1),
        ):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                self.module.parse_mountinfo(raw)

    def test_long_bounded_overlay_option_is_preserved(self):
        option = b"lowerdir=" + b"a" * 647
        raw = b"31 20 0:7 / / rw - overlay overlay rw," + option + b"\n"
        self.assertIn(
            option.decode(), self.module.parse_mountinfo(raw)[31]["super_options"]
        )
        with self.assertRaises(ValueError):
            self.module.parse_mountinfo(raw.replace(option, b"a" * 4097))

    def test_unrelated_nsfs_handle_is_not_treated_as_a_directory_path(self):
        raw = b"31 20 0:7 net:[12345] /run/netns/example rw - nsfs nsfs rw\n"
        table = self.module.parse_mountinfo(raw)
        self.assertEqual(table[31]["root"], "net:[12345]")
        self.assertEqual(table[31]["filesystem"], "nsfs")

    def test_real_fd_mount_id_and_statfs_match_current_proc_table(self):
        fd = os.open(Path(__file__).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            mount = self.module.fd_mount_id(fd)
            table = self.module.parse_mountinfo(
                Path("/proc/self/mountinfo").read_bytes()
            )
            self.assertIn(mount, table)
            facts = self.module.statfs(fd)
            self.assertEqual(set(facts), {"statfs_type", "statfs_fsid"})
            self.assertEqual(len(facts["statfs_fsid"]), 2)
            self.assertGreater(facts["statfs_type"], 0)
        finally:
            os.close(fd)


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class FilesystemSubjectTests(unittest.TestCase):
    def setUp(self):
        self.module = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_filesystem"
        )
        self.fixture = fixture.ContinuationV2Tests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.case = self.fixture.case
        self.r = self.fixture.r
        self.selection = self.module.semantics.select(**self.case.arguments())

    def test_absent_root_has_real_nearest_ancestors_and_no_writes(self):
        count = len(os.listdir("/proc/self/fd"))
        with self.module.observe_subject(self.selection) as held:
            body = self.r.observe.decode(held.raw)
            self.assertEqual(len(body["roles"]), 7)
            self.assertEqual(
                body["roles"]["intent"]["missing_suffix"],
                [self.r.RUNTIME_ROOT.name, self.case.owner.pair_key],
            )
            self.assertEqual(body["roles"]["legacy-marker"]["missing_suffix"], [])
            self.assertEqual(
                body["subject"]["binding"]["pair_key"], self.case.owner.pair_key
            )
            self.assertEqual(body["procfs"]["type_magic"], 0x9FA0)
            self.assertFalse(self.r.RUNTIME_ROOT.exists())
        self.assertTrue(held.closed)
        held.release()
        self.assertEqual(len(os.listdir("/proc/self/fd")), count)

    def test_current_runtime_changes_nearest_parent_without_inventing_pair(self):
        self.r.RUNTIME_ROOT.mkdir(mode=0o700)
        with self.module.observe_subject(self.selection) as held:
            body = self.r.observe.decode(held.raw)
            self.assertEqual(
                body["roles"]["intent"]["missing_suffix"], [self.case.owner.pair_key]
            )
            self.assertEqual(
                body["roles"]["pair-directory"]["ancestor_path"],
                str(self.r.RUNTIME_ROOT),
            )
        self.assertFalse(self.case.old.path.exists())

    def test_initial_ancestor_capability_does_not_claim_future_absence(self):
        with self.module.observe_subject(self.selection) as held:
            body = self.r.observe.decode(held.raw)
            self.assertEqual(
                body["observation_scope"],
                "initial-nearest-ancestors-with-retained-identities",
            )
            self.r.RUNTIME_ROOT.mkdir(mode=0o700)
            self.assertEqual(self.r.observe.decode(held.raw), body)
        self.r.RUNTIME_ROOT.rmdir()

    def test_symlink_parent_is_not_absence_and_closes_all_fds(self):
        self.r.RUNTIME_ROOT.symlink_to(
            self.case.old.base.path(), target_is_directory=True
        )
        count = len(os.listdir("/proc/self/fd"))
        with self.assertRaises((OSError, ValueError)):
            with self.module.observe_subject(self.selection):
                pass
        self.assertEqual(len(os.listdir("/proc/self/fd")), count)

    def test_actual_parent_replacement_while_held_refuses(self):
        self.r.RUNTIME_ROOT.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            with self.module.observe_subject(self.selection):
                self.r.RUNTIME_ROOT.rename(self.r.RUNTIME_ROOT.with_name("moved"))
                self.r.RUNTIME_ROOT.mkdir(mode=0o700)

    def test_selection_refuses_before_opening_observers(self):
        with mock.patch.object(
            self.module.attempt, "_Reader", side_effect=AssertionError("early IO")
        ):
            with self.assertRaises(ValueError):
                with self.module.observe_subject(object()):
                    pass

    def test_cleanup_never_closes_a_substituted_foreign_descriptor(self):
        foreign = os.open(
            self.case.old.base.path(), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        original = None
        try:
            with self.assertRaises(ValueError):
                with self.module.observe_subject(self.selection) as held:
                    node = held._reader.nodes[str(self.r.RUNTIME_ROOT.parent)]
                    original = node["fd"]
                    node["fd"] = foreign
            self.assertTrue(os.fstat(foreign).st_mode)
        finally:
            for fd in (foreign, original):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
