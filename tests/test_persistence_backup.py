"""Real encryption/files/locks around a synthetic fixed ZFS command adapter.

The source observer and mount provider are mocked. These tests do not qualify
native ZFS, NFS or a real application backup.
"""

from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
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
    persistence_state as state,
)
from test_persistence_state import manifest

AGE = os.environ.get("CMDMESH_AGE") or shutil.which("age")
KEYGEN = os.environ.get("CMDMESH_AGE_KEYGEN") or shutil.which("age-keygen")


@unittest.skipUnless(AGE and KEYGEN, "provide standard age tools")
class BackupTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".generated"
        scratch.mkdir(mode=0o700, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=scratch, prefix="backup-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = self.root / "store"
        self.store.mkdir(mode=0o700)
        self.key = self.root / "identity.agekey"
        subprocess.run(
            [KEYGEN, "-o", str(self.key)],
            check=True,
            capture_output=True,
            timeout=10,
            umask=0o077,
        )
        self.recipient = (
            subprocess.run(
                [KEYGEN, "-y", str(self.key)],
                check=True,
                capture_output=True,
                timeout=10,
            )
            .stdout.decode()
            .strip()
        )
        self.model = manifest()
        info = self.store.stat()
        self.store_facts = {
            "mount": {"id": 42},
            "device": info.st_dev,
            "inode": info.st_ino,
            "uid": info.st_uid,
            "gid": info.st_gid,
            "mode": stat.S_IMODE(info.st_mode),
        }
        self.facts = {
            "source": self.model["source"],
            "quiesced": True,
            "application": self.model["application"],
            "backup_store": self.store_facts,
            "backup_verified": False,
        }
        self.running, self.closing_drift = False, False

        @contextmanager
        def source(request, require_stopped=False):
            self.assertTrue(require_stopped)
            if self.running:
                raise state.PersistenceError("persistence-source-not-stopped")
            yield copy.deepcopy(self.facts)
            if self.closing_drift and (self.root / "snapshot-events").exists():
                raise state.PersistenceError("persistence-source-changed")

        patches = [
            mock.patch.object(backup.observe, "source_state", side_effect=source),
            mock.patch.object(
                backup.observe,
                "mount_facts",
                side_effect=lambda unused: copy.deepcopy(self.store_facts),
            ),
            mock.patch.object(
                backup, "RUNTIME_ROOT", self.root / "managed/persistence"
            ),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.zfs = self.root / "zfs"
        self.zfs.write_text("#!" + sys.executable + "\n" + """import json,os,pathlib,sys
root=pathlib.Path(__file__).parent;a=sys.argv[1:];state=root/'zfs-state.json'
s=json.loads(state.read_text()) if state.exists() else {}
if a[0]=='list':
 assert a[1:-2]==['-H','-o','name','-t','snapshot','-d','1']
 for name in s:print(name)
elif a[0]=='snapshot':
 assert len(a)==3 and all(name not in s for name in a[1:])
 for i,name in enumerate(a[1:]):s[name]={'guid':str(3+i),'createtxg':'99'}
 state.write_text(json.dumps(s))
 with (root/'snapshot-events').open('a') as out:out.write(json.dumps(a)+'\\n')
elif a[0]=='get':
 assert a[1:6]==['-H','-p','-o','name,property,value','guid,createtxg']
 for name in a[6:]:
  for prop,value in s[name].items():print(name,prop,value,sep='\\t')
elif a[0]=='send':
 assert len(a)==3 and a[1]=='-p' and a[2] in s
 role=a[2].split('@')[0].split('/')[-1]
 os.write(1,('synthetic full stream:'+role).encode())
 if (root/'send-fail').exists():sys.exit(23)
else:raise RuntimeError('unsupported synthetic command')
""")
        self.zfs.chmod(0o700)

        def reference(path):
            path = Path(path).resolve()
            return {
                "path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }

        self.request = {
            "schema_version": 1,
            "operation_id": "a" * 64,
            "source_request": {
                "source": copy.deepcopy(self.model["source"]),
                "policy": {
                    "datasets": {
                        role: {"name": item["name"], "guid": item["guid"]}
                        for role, item in self.model["datasets"].items()
                    }
                },
                "backup_store": {
                    "mountpoint": str(self.store),
                    "source": "192.0.2.20:/backup",
                    "file_uid": os.getuid(),
                    "file_gid": os.getgid(),
                },
            },
            "tools": {"zfs": reference(self.zfs), "age": reference(AGE)},
            "recipient": self.recipient,
        }
        patch = mock.patch.object(
            backup,
            "TOOL_PATHS",
            {name: ref["path"] for name, ref in self.request["tools"].items()},
        )
        patch.start()
        self.addCleanup(patch.stop)

    def prepared(self):
        value = backup.prepare_backup(self.request)
        raw = state.canonical(value)
        return raw, state.sha256(raw)

    def decrypt(self, path):
        return subprocess.run(
            [AGE, "--decrypt", "--identity", str(self.key), str(path)],
            check=True,
            capture_output=True,
            timeout=10,
        ).stdout

    def test_prepare_is_read_only_and_rejects_running_source_or_bad_recipient(self):
        raw, trusted = self.prepared()
        self.assertEqual(
            json.loads(raw)["observation_sha256"],
            state.sha256(state.canonical(self.facts)),
        )
        self.assertFalse(backup.RUNTIME_ROOT.exists())
        self.assertEqual(list(self.store.iterdir()), [])
        self.assertFalse((self.root / "snapshot-events").exists())
        self.running = True
        with self.assertRaises(state.PersistenceError):
            backup.prepare_backup(self.request)
        self.running = False
        self.request["recipient"] = "age1" + "q" * 58
        with self.assertRaises(state.PersistenceError):
            backup.prepare_backup(self.request)
        self.assertFalse(backup.RUNTIME_ROOT.exists())

    def test_completed_backup_binds_atomic_pair_ciphertext_and_trusted_manifest(self):
        raw, trusted = self.prepared()
        result = backup.execute_backup(raw, trusted)
        self.assertTrue(result["backup_verified"])
        prefix = Path(result["backup_path"])
        self.assertEqual(stat.S_IMODE(prefix.stat().st_mode), 0o700)
        self.assertEqual(
            sorted(p.name for p in prefix.iterdir()),
            ["config.zfs.age", "data.zfs.age", "manifest.json.age"],
        )
        decrypted = self.decrypt(prefix / "manifest.json.age")
        value = state.load_manifest(decrypted, result["manifest_sha256"])
        for role in ("data", "config"):
            path = prefix / (role + ".zfs.age")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(
                self.decrypt(path), ("synthetic full stream:" + role).encode()
            )
            self.assertEqual(
                value["artifacts"][role]["sha256"], state.sha256(path.read_bytes())
            )
        self.assertEqual(
            len((self.root / "snapshot-events").read_text().splitlines()), 1
        )
        with self.assertRaises(state.PersistenceError):
            backup.execute_backup(raw, trusted)
        self.assertEqual(
            len((self.root / "snapshot-events").read_text().splitlines()), 1
        )

    def test_forged_prepared_hash_and_changed_observation_cannot_mutate(self):
        raw, trusted = self.prepared()
        with self.assertRaises(state.PersistenceError):
            backup.execute_backup(raw, "0" * 64)
        self.facts["application"]["record_count"] += 1
        with self.assertRaises(state.PersistenceError):
            backup.execute_backup(raw, trusted)
        self.assertFalse(backup.RUNTIME_ROOT.exists())
        self.assertEqual(list(self.store.iterdir()), [])

    def test_failed_sender_preserves_partial_and_blocks_another_operation(self):
        raw, trusted = self.prepared()
        (self.root / "send-fail").touch(mode=0o600)
        with self.assertRaises(backup.stream.StreamError) as failed:
            backup.execute_backup(raw, trusted)
        self.assertEqual(failed.exception.producer_exit_code, 23)
        self.assertEqual(failed.exception.command_outcome, "failed")
        prefixes = list(self.store.iterdir())
        self.assertEqual(len(prefixes), 1)
        self.assertTrue((prefixes[0] / "data.zfs.age").exists())
        self.assertFalse((prefixes[0] / "manifest.json.age").exists())
        self.request["operation_id"] = "b" * 64
        other, other_hash = self.prepared()
        with self.assertRaisesRegex(state.PersistenceError, "unfinished"):
            backup.execute_backup(other, other_hash)
        self.assertEqual(
            len((self.root / "snapshot-events").read_text().splitlines()), 1
        )

    def test_changed_ciphertext_is_not_accepted_from_its_readback_hash(self):
        raw, trusted = self.prepared()
        original = backup.stream.encrypt_snapshot

        def corrupt(snapshot, recipient, fd, tools, **kwargs):
            result = original(snapshot, recipient, fd, tools, **kwargs)
            os.pwrite(fd, b"X", 0)
            return result

        with mock.patch.object(
            backup.stream, "encrypt_snapshot", side_effect=corrupt
        ), self.assertRaisesRegex(state.PersistenceError, "ciphertext"):
            backup.execute_backup(raw, trusted)
        self.assertFalse(any(self.store.glob("*/manifest.json.age")))

    def test_source_closing_failure_cannot_publish_a_completed_receipt(self):
        raw, trusted = self.prepared()
        self.closing_drift = True
        with self.assertRaises(state.PersistenceError):
            backup.execute_backup(raw, trusted)
        self.assertTrue(any(self.store.glob("*/manifest.json.age")))
        self.assertFalse(any(backup.RUNTIME_ROOT.glob("operations/*/complete.json")))

    def test_earlier_artifacts_are_checked_again_before_completion(self):
        raw, trusted = self.prepared()
        original = backup.stream.encrypt_manifest

        def corrupt(*args, **kwargs):
            result = original(*args, **kwargs)
            path = next(self.store.glob("*/data.zfs.age"))
            with path.open("r+b") as out:
                out.write(b"X")
            return result

        with mock.patch.object(
            backup.stream, "encrypt_manifest", side_effect=corrupt
        ), self.assertRaisesRegex(state.PersistenceError, "ciphertext"):
            backup.execute_backup(raw, trusted)

    def test_snapshot_pair_is_reobserved_after_the_streams(self):
        raw, trusted = self.prepared()
        original = backup.stream.encrypt_manifest

        def replace_snapshot(*args, **kwargs):
            result = original(*args, **kwargs)
            path = self.root / "zfs-state.json"
            value = json.loads(path.read_bytes())
            name = next(name for name in value if "/config@" in name)
            value[name]["guid"] = "99"
            path.write_text(json.dumps(value))
            return result

        with mock.patch.object(
            backup.stream, "encrypt_manifest", side_effect=replace_snapshot
        ), self.assertRaisesRegex(state.PersistenceError, "snapshot"):
            backup.execute_backup(raw, trusted)

    def test_foreign_backup_prefix_refuses_before_creating_snapshots(self):
        raw, trusted = self.prepared()
        prefix = (
            "cmdmesh-"
            + self.model["source"]["owner_tag"].removeprefix("cmdmesh-own-")
            + "-"
            + self.request["operation_id"]
        )
        foreign = self.store / prefix
        foreign.mkdir(mode=0o700)
        (foreign / "keep").write_bytes(b"foreign")
        with self.assertRaises(state.PersistenceError):
            backup.execute_backup(raw, trusted)
        self.assertFalse((self.root / "snapshot-events").exists())
        self.assertEqual((foreign / "keep").read_bytes(), b"foreign")

    def test_malformed_nested_request_has_a_typed_refusal(self):
        for source in (
            {},
            {"source": None},
            {"source": self.model["source"], "policy": None},
        ):
            request = copy.deepcopy(self.request)
            request["source_request"] = source
            with self.subTest(source=source), self.assertRaises(state.PersistenceError):
                backup.prepare_backup(request)
        self.assertFalse(backup.RUNTIME_ROOT.exists())

    def test_backup_request_cannot_select_an_arbitrary_executable(self):
        request = copy.deepcopy(self.request)
        other = self.root / "other-zfs"
        other.write_bytes(self.zfs.read_bytes())
        other.chmod(0o700)
        request["tools"]["zfs"]["path"] = str(other)
        with self.assertRaises(state.PersistenceError):
            backup.prepare_backup(request)
        self.assertFalse(backup.RUNTIME_ROOT.exists())

    def test_prepared_bytes_are_not_silently_reformatted(self):
        raw, trusted = self.prepared()
        formatted = json.dumps(json.loads(raw), indent=2).encode()
        with self.assertRaises(state.PersistenceError):
            backup.execute_backup(formatted, state.sha256(formatted))
        self.assertFalse(backup.RUNTIME_ROOT.exists())

    def test_incomplete_completion_cannot_release_an_unfinished_pair(self):
        raw, trusted = self.prepared()
        backup.execute_backup(raw, trusted)
        complete = next(backup.RUNTIME_ROOT.glob("operations/*/complete.json"))
        value = json.loads(complete.read_bytes())
        del value["manifest"]
        complete.write_bytes(state.canonical(value))
        self.request["operation_id"] = "b" * 64
        other, other_hash = self.prepared()
        with self.assertRaises(state.PersistenceError):
            backup.execute_backup(other, other_hash)
        self.assertEqual(
            len((self.root / "snapshot-events").read_text().splitlines()), 1
        )

    def test_pair_lock_is_a_real_nonblocking_lock(self):
        import fcntl

        raw, trusted = self.prepared()
        backup.execute_backup(raw, trusted)
        self.request["operation_id"] = "b" * 64
        other, other_hash = self.prepared()
        lock = next((backup.RUNTIME_ROOT / "locks").iterdir())
        with lock.open("rb") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(state.PersistenceError, "pair-busy"):
                backup.execute_backup(other, other_hash)
        self.assertEqual(
            len((self.root / "snapshot-events").read_text().splitlines()), 1
        )

    def test_changed_store_refuses_before_snapshot_or_prefix_creation(self):
        raw, trusted = self.prepared()
        with mock.patch.object(
            backup.observe,
            "mount_facts",
            return_value=dict(self.store_facts, device=999999),
        ), self.assertRaises(state.PersistenceError):
            backup.execute_backup(raw, trusted)
        self.assertFalse((self.root / "snapshot-events").exists())
        self.assertEqual(list(self.store.iterdir()), [])

    def test_full_store_write_refuses_and_keeps_its_consumed_intent(self):
        raw, trusted = self.prepared()
        full = "import os\n_write=os.write\ndef full(fd,raw):\n if fd>2:raise OSError(28,'No space left')\n return _write(fd,raw)\nos.write=full\n"
        with mock.patch.object(
            backup.stream, "WORKER", full + backup.stream.WORKER
        ), self.assertRaises(backup.stream.StreamError) as failed:
            backup.execute_backup(raw, trusted)
        self.assertTrue(failed.exception.group_stopped)
        self.assertFalse(any(backup.RUNTIME_ROOT.glob("operations/*/complete.json")))
        self.assertTrue(any(backup.RUNTIME_ROOT.glob("operations/*/intent.json")))
        self.assertTrue(any(self.store.glob("*/data.zfs.age")))

    def test_ciphertext_changed_during_source_closure_cannot_complete(self):
        raw, trusted = self.prepared()
        original = backup.observe.source_state.side_effect

        @contextmanager
        def source(*args, **kwargs):
            with original(*args, **kwargs) as facts:
                yield facts
                if (self.root / "snapshot-events").exists():
                    with next(self.store.glob("*/data.zfs.age")).open("r+b") as out:
                        out.write(b"X")

        with mock.patch.object(
            backup.observe, "source_state", side_effect=source
        ), self.assertRaisesRegex(state.PersistenceError, "ciphertext"):
            backup.execute_backup(raw, trusted)
        self.assertFalse(any(backup.RUNTIME_ROOT.glob("operations/*/complete.json")))

    def test_prefix_renamed_during_final_snapshot_query_cannot_complete(self):
        raw, trusted = self.prepared()
        original = backup.read_snapshots
        calls = []

        def moved(request):
            result = original(request)
            calls.append(True)
            if len(calls) == 2:
                next(self.store.iterdir()).rename(self.store / "moved-output")
            return result

        with mock.patch.object(
            backup, "read_snapshots", side_effect=moved
        ), self.assertRaisesRegex(state.PersistenceError, "prefix"):
            backup.execute_backup(raw, trusted)
        self.assertFalse(any(backup.RUNTIME_ROOT.glob("operations/*/complete.json")))


if __name__ == "__main__":
    unittest.main()
