"""Real local namespace/event/mount observations, no managed qualification."""

import os
import unittest
from unittest import mock

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_native_executor as candidate,
)
import test_persistence_owner_native_storage as fixture


class NativeNamespaceTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.NativeStorageTests("runTest")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.s, self.j, self.binding = self.f.s, self.f.j, self.f.binding
        self.root = self.j.RUNTIME_ROOT
        probe = self.s.probe_protocol(allow_mutation=True)
        self.mount = candidate.metadata.r.observe.decode(probe.raw)["mount"]

    def observe(self, fixed=True):
        return candidate._observe_native_namespace(
            self.binding, self.mount, fixed=fixed
        )

    def initialize(self):
        self.s._initialize_journal(self.binding)

    def test_absent_readonly_observation_creates_nothing(self):
        with self.observe() as held:
            self.assertIn(str(self.root), held.absent)
        self.assertFalse(self.root.exists())

    def test_parent_observer_survives_our_namespace_initialization(self):
        with self.observe(fixed=False):
            self.initialize()
        with self.observe():
            pass

    def test_fixed_native_head_same_byte_write_is_observed(self):
        self.initialize()
        with self.assertRaises(ValueError):
            with self.observe():
                path = self.root / self.binding.pair_key / "HEAD.json"
                raw = path.read_bytes()
                with path.open("r+b") as stream:
                    stream.write(raw)

    def test_absent_namespace_transient_creation_is_observed(self):
        with self.assertRaises(ValueError):
            with self.observe():
                self.root.mkdir(mode=0o700)
                self.root.rmdir()

    def test_unknown_transient_native_child_is_observed(self):
        self.initialize()
        with self.assertRaises(ValueError):
            with self.observe():
                path = self.root / self.binding.pair_key / "unexpected"
                path.touch(mode=0o600)
                path.unlink()

    def test_native_parent_mount_id_must_match_even_with_same_device_inode(self):
        self.initialize()
        original = candidate.metadata.filesystem.fd_mount_id

        def changed(fd):
            value = original(fd)
            return (
                value + 1
                if os.readlink(f"/proc/self/fd/{fd}") == str(self.root)
                else value
            )

        with mock.patch.object(
            candidate.metadata.filesystem, "fd_mount_id", side_effect=changed
        ):
            with self.assertRaises(ValueError):
                with self.observe(fixed=False):
                    self.fail("wrong mount admitted")

    def test_mount_change_after_entry_refuses_final_closure(self):
        self.initialize()
        original = candidate.metadata.filesystem.fd_mount_id
        changed = False

        def mount(fd):
            value = original(fd)
            return (
                value + 1
                if changed and os.readlink(f"/proc/self/fd/{fd}") == str(self.root)
                else value
            )

        with mock.patch.object(
            candidate.metadata.filesystem, "fd_mount_id", side_effect=mount
        ):
            with self.assertRaises(ValueError):
                with self.observe():
                    changed = True

    def test_unrelated_valid_pair_directory_can_change(self):
        self.initialize()
        with self.observe():
            path = self.root / ("c" * 64)
            path.mkdir(mode=0o700)
            path.rmdir()


if __name__ == "__main__":
    unittest.main(verbosity=2)
