"""Use real file locks shared with the unchanged backup journal."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_backup as backup,
)
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_pair_lock as pair,
)
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_state as state,
)

DATASETS = {"data": {"guid": "1"}, "config": {"guid": "2"}}


class PairLockTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".generated"
        scratch.mkdir(mode=0o700, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="pair-lock-", dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.runtime = self.root / "managed/persistence"
        patch = mock.patch.object(backup, "RUNTIME_ROOT", self.runtime)
        patch.start()
        self.addCleanup(patch.stop)

    def child(self, kind, datasets=DATASETS):
        program = """import json,pathlib,sys
sys.path.insert(0,str(pathlib.Path(sys.argv[1])/'ansible'))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import persistence_backup as b,persistence_pair_lock as p,persistence_state as s
b.RUNTIME_ROOT=pathlib.Path(sys.argv[2]);datasets=json.loads(sys.argv[4])
prepared={'request':{'source_request':{'policy':{'datasets':datasets}},'operation_id':'b'*64}}
try:
 context=b.journal(prepared,s.sha256(s.canonical(prepared))) if sys.argv[3]=='backup' else p.locked_pair(datasets)
 with context:result={'acquired':True}
except s.PersistenceError as error:result={'acquired':False,'code':error.code}
print(json.dumps(result))
"""
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                program,
                str(ROOT),
                str(self.runtime),
                kind,
                json.dumps(datasets),
            ],
            cwd=ROOT,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=10,
            umask=0o077,
            env={
                "PATH": os.environ["PATH"],
                "LANG": "C.UTF-8",
                "TMPDIR": str(self.root),
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return json.loads(result.stdout)

    def test_read_only_missing_runtime_does_not_initialize_anything(self):
        with self.assertRaises(state.PersistenceError):
            with pair.locked_pair(DATASETS):
                self.fail("missing runtime accepted")
        self.assertFalse(self.runtime.parent.exists())

    def test_initialize_refuses_foreign_profile_before_creating_a_lock(self):
        backup.runtime()
        profile = self.runtime / "profile.json"
        malformed = {**backup.PROFILE, "schema_version": True}
        profile.write_bytes(state.canonical(malformed))
        with self.assertRaises(state.PersistenceError):
            with pair.locked_pair(DATASETS, initialize=True):
                self.fail("foreign profile accepted")
        self.assertEqual(profile.read_bytes(), state.canonical(malformed))
        self.assertFalse(
            (self.runtime / "locks" / (state.pair_key(DATASETS) + ".json")).exists()
        )

    def test_new_lock_excludes_existing_backup_in_another_process(self):
        with pair.locked_pair(DATASETS, initialize=True) as scope:
            self.assertEqual(scope["pair_key"], state.pair_key(DATASETS))
            self.assertEqual(
                self.child("backup"),
                {"acquired": False, "code": "persistence-backup-pair-busy"},
            )

    def test_existing_backup_excludes_new_lock_in_another_process(self):
        # Only exercise the old journal's lock boundary. This synthetic payload
        # is not a qualified backup or an operation-admission test.
        prepared = {
            "request": {
                "source_request": {"policy": {"datasets": DATASETS}},
                "operation_id": "a" * 64,
            }
        }
        with backup.journal(prepared, state.sha256(state.canonical(prepared))):
            self.assertEqual(
                self.child("pair"), {"acquired": False, "code": "persistence-pair-busy"}
            )

    def test_release_and_error_release_preserve_the_same_marker(self):
        with pair.locked_pair(DATASETS, initialize=True) as first:
            path = Path(first["path"])
            before = path.read_bytes(), path.stat().st_ino
        with self.assertRaisesRegex(ValueError, "model failure"):
            with pair.locked_pair(DATASETS):
                raise ValueError("model failure")
        self.assertEqual(self.child("pair"), {"acquired": True})
        self.assertEqual((path.read_bytes(), path.stat().st_ino), before)

    def test_pair_identity_survives_role_order_and_distinct_pairs_do_not_conflict(self):
        with pair.locked_pair(DATASETS, initialize=True):
            reversed_roles = {"data": {"guid": "2"}, "config": {"guid": "1"}}
            self.assertEqual(
                self.child("pair", reversed_roles)["code"], "persistence-pair-busy"
            )
            other = {"data": {"guid": "3"}, "config": {"guid": "4"}}
            with pair.locked_pair(other, initialize=True):
                pass

    def test_foreign_marker_permissions_or_symlink_are_not_repaired(self):
        for index, fault in enumerate(("body", "mode", "symlink"), 10):
            with self.subTest(fault=fault):
                datasets = {"data": {"guid": str(index)}, "config": {"guid": "2"}}
                with pair.locked_pair(datasets, initialize=True) as scope:
                    path = Path(scope["path"])
                if fault == "body":
                    path.write_bytes(b"{}")
                if fault == "mode":
                    path.chmod(0o666)
                if fault == "symlink":
                    original = path.with_name("preserved-marker.json")
                    path.rename(original)
                    path.symlink_to(original)
                with self.assertRaises((state.PersistenceError, OSError)):
                    with pair.locked_pair(datasets, initialize=True):
                        self.fail("foreign lock accepted")
                if fault == "body":
                    self.assertEqual(path.read_bytes(), b"{}")
                if fault == "mode":
                    self.assertEqual(path.stat().st_mode & 0o777, 0o666)
                if fault == "symlink":
                    self.assertTrue(path.is_symlink())

    def test_replaced_marker_during_operation_refuses_without_deleting_it(self):
        with self.assertRaises(state.PersistenceError):
            with pair.locked_pair(DATASETS, initialize=True) as scope:
                path = Path(scope["path"])
                original = path.with_name("original-marker.json")
                path.rename(original)
                path.write_bytes(original.read_bytes())
                path.chmod(0o600)
        self.assertTrue(path.exists() and original.exists())


if __name__ == "__main__":
    unittest.main()
