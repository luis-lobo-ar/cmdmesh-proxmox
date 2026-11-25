"""Ordered metadata cannot turn uncertain native work into a new permission."""

import copy
from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_journal as journal,
    persistence_pair_lock as pair,
    persistence_guest_api as api,
)


def phase_payloads(pending):
    """Modeled native metadata, never a claim that a real action occurred."""
    binding = pending.binding.guest
    clock = 1700000000 + pending.sequence
    action = "shutdown" if pending.kind == "shutdown" else "start"
    kind = "vzshutdown" if action == "shutdown" else "vzstart"
    upid = f"UPID:{binding.node}:{16+pending.sequence:08X}:{32+pending.sequence:08X}:{clock:08X}:{kind}:102:root@pam:"
    task = {
        **api.parse_upid(binding, upid, kind=kind),
        "status": "stopped",
        "exitstatus": "OK",
    }
    log = [{"n": 1, "t": "TASK OK"}]
    return {
        "dispatch": {
            "action": action,
            "binding": asdict(binding),
            "prepared_sha256": pending.prepared_sha256,
            "entry_sha256": "e" * 64,
            "host_epoch": {
                "boot_id": "11111111-2222-3333-4444-555555555555",
                "mount_namespace": "mnt:[123]",
            },
            "clock": clock,
            "parameters": (
                {} if action == "start" else {"timeout": "60", "forceStop": "0"}
            ),
        },
        "ack": {"upid": upid, "tls_verified": True},
        "terminal": {
            "task": task,
            "log": log,
            "native_outcome": api.native_outcome(task, log),
        },
    }


class OwnerJournalTests(unittest.TestCase):
    def test_invalid_binding_cannot_create_runtime_or_escape_its_directory(self):
        escape = self.root / "escape"
        foreign = SimpleNamespace(pair_key=str(escape), authority_sha256="b" * 64)
        with self.assertRaises(ValueError):
            journal._initialize(foreign)
        self.assertFalse(journal.RUNTIME_ROOT.exists())
        self.assertFalse(escape.exists())

    def test_malformed_operation_kind_refuses_before_any_slot_is_created(self):
        head = self.initialize()["head_sha256"]
        before = self.files()
        with self.assertRaises(ValueError):
            self.begin(head, kind=[])
        self.assertEqual(before, self.files())

    def test_all_protocol_metadata_versions_require_current_integer_version(self):
        head = self.initialize()["head_sha256"]
        for path in (
            journal.RUNTIME_ROOT / "runtime.json",
            self.path() / "profile.json",
            self.path() / "genesis.json",
        ):
            raw = path.read_bytes()
            value = json.loads(raw)
            value["schema_version"] = True
            path.write_bytes(journal.state.canonical(value))
            with self.subTest(path=path.name), self.assertRaises(ValueError):
                journal._inspect(self.binding, head)
            path.write_bytes(raw)

    def test_runtime_parent_is_reclosed_for_inspect_begin_and_complete(self):
        original = journal._read
        for phase in ("inspect", "begin", "complete"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(
                dir=self.root
            ) as scope, mock.patch.object(
                journal, "RUNTIME_ROOT", Path(scope) / "journal"
            ):
                head = self.initialize()["head_sha256"]
                pending = self.begin(head) if phase == "complete" else None

                def mutate(path, seal):
                    value = original(path, seal)
                    match = (
                        phase == "inspect"
                        or (phase == "begin" and value.get("state") == "pending")
                        or (
                            phase == "complete"
                            and value.get("state") == "ready"
                            and value.get("sequence") == 1
                        )
                    )
                    if path.name == "HEAD.json" and match:
                        Path(scope).chmod(0o777)
                    return value

                with mock.patch.object(journal, "_read", side_effect=mutate):
                    with self.assertRaises(ValueError):
                        if phase == "inspect":
                            journal._inspect(self.binding, head)
                        elif phase == "begin":
                            self.begin(head)
                        else:
                            self.complete(pending)

    def test_replaced_operation_directory_and_symlinked_head_refuse(self):
        head = self.initialize()["head_sha256"]
        pending = self.begin(head)
        slot = self.path() / journal._slot(1)
        saved = self.root / "replaced-slot"
        slot.rename(saved)
        slot.mkdir(mode=0o700)
        path = slot / "intent.json"
        path.write_bytes((saved / "intent.json").read_bytes())
        path.chmod(0o600)
        with self.assertRaises(ValueError):
            self.complete(pending)
        actual = self.path() / "HEAD.json"
        outside = self.root / "copied-head.json"
        outside.write_bytes(actual.read_bytes())
        outside.chmod(0o600)
        actual.unlink()
        actual.symlink_to(outside)
        with self.assertRaises((ValueError, OSError)):
            journal._inspect(self.binding, pending.pending_head_sha256)

    def test_late_profile_change_after_its_read_refuses_the_whole_view(self):
        head = self.initialize()["head_sha256"]
        candidate = self.complete(self.begin(head))
        read = journal._read

        def mutate(path, seal):
            value = read(path, seal)
            if path.name == "result.json":
                profile = self.path() / "profile.json"
                body = json.loads(profile.read_bytes())
                body["authority_sha256"] = "f" * 64
                profile.write_bytes(journal.state.canonical(body))
            return value

        with mock.patch.object(journal, "_read", side_effect=mutate):
            with self.assertRaises(ValueError):
                journal._inspect(self.binding, candidate.head_sha256)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            dir=ROOT / ".generated", prefix="owner-journal-"
        )
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        patch = mock.patch.object(journal, "RUNTIME_ROOT", self.root / "journal")
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(journal.backup, "RUNTIME_ROOT", self.root / "pair")
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(journal, "ROOT_UID", os.geteuid())
        patch.start()
        self.addCleanup(patch.stop)
        self.datasets = {"data": {"guid": "11"}, "config": {"guid": "22"}}
        self.binding = journal.Binding(
            journal.state.pair_key(self.datasets),
            "b" * 64,
            api.GuestBinding("pve-example", 102, "1" * 64, "2" * 64, "3" * 64),
        )

    def initialize(self):
        with pair.locked_pair(self.datasets, initialize=True):
            return journal._initialize(self.binding)

    def begin(self, predecessor, kind="shutdown", request="c" * 64):
        with pair.locked_pair(self.datasets):
            return journal._begin(self.binding, predecessor, kind, request)

    def complete(self, pending, result=None):
        with pair.locked_pair(self.datasets):
            for stage, payload in phase_payloads(pending).items():
                pending = journal._append_phase(pending, stage, payload)
            return journal._complete(
                pending, result or {"observed": "qualified by caller"}
            )

    def path(self):
        return journal.RUNTIME_ROOT / self.binding.pair_key

    def files(self):
        if not journal.RUNTIME_ROOT.exists():
            return {}
        return {
            str(path): (path.read_bytes(), journal.observe.stable(path.lstat()))
            for path in journal.RUNTIME_ROOT.rglob("*")
            if path.is_file()
        }

    def test_inspection_never_initializes_and_initialization_is_exactly_idempotent(
        self,
    ):
        with self.assertRaises((OSError, ValueError)):
            journal._inspect(self.binding, "0" * 64)
        self.assertFalse(journal.RUNTIME_ROOT.exists())
        first = self.initialize()
        before = self.files()
        second = self.initialize()
        self.assertTrue(first["changed"])
        self.assertFalse(second["changed"])
        self.assertEqual(first["head_sha256"], second["head_sha256"])
        self.assertEqual(before, self.files())

    def test_two_completed_cycles_share_one_epoch_without_replay(self):
        head = self.initialize()["head_sha256"]
        for sequence, kind in enumerate(
            ("shutdown", "resume", "shutdown", "resume"), 1
        ):
            pending = self.begin(
                head, kind, journal.state.sha256(str(sequence).encode())
            )
            candidate = self.complete(
                pending, {"epoch": "unchanged", "sequence": sequence}
            )
            self.assertEqual(candidate.sequence, sequence)
            head = candidate.head_sha256
            view = journal._inspect(self.binding, head)
            self.assertEqual(
                (view.head["state"], view.head["sequence"]), ("ready", sequence)
            )
            with self.assertRaises(ValueError):
                self.complete(pending)

    def test_pending_blocks_new_request_epoch_kind_and_owner_binding(self):
        head = self.initialize()["head_sha256"]
        self.begin(head)
        before = self.files()
        for kind, request in (("shutdown", "d" * 64), ("resume", "e" * 64)):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.begin(head, kind, request)
        changed_owner = journal.Binding(
            self.binding.pair_key, "f" * 64, self.binding.guest
        )
        with self.assertRaises(ValueError):
            journal._initialize(changed_owner)
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(before, self.files())

    def test_stale_predecessor_cannot_start_the_next_slot(self):
        old = self.initialize()["head_sha256"]
        candidate = self.complete(self.begin(old))
        with self.assertRaises(ValueError):
            self.begin(old, "resume")
        self.assertEqual(
            journal._inspect(self.binding, candidate.head_sha256).head["sequence"], 1
        )

    def test_partial_intent_never_becomes_dispatch_permission(self):
        head = self.initialize()["head_sha256"]
        write = journal._write

        def fail(path, value):
            if path.name == "intent.json":
                raise OSError("injected disk failure")
            return write(path, value)

        with mock.patch.object(journal, "_write", side_effect=fail):
            with self.assertRaises(OSError):
                self.begin(head)
        with self.assertRaises(ValueError):
            self.begin(head, request="e" * 64)
        with self.assertRaises(ValueError):
            self.initialize()

    def test_pending_head_publication_failure_preserves_an_orphan_barrier(self):
        head = self.initialize()["head_sha256"]
        with mock.patch.object(
            journal.os, "replace", side_effect=OSError("injected rename failure")
        ):
            with self.assertRaises(OSError):
                self.begin(head)
        self.assertTrue((self.path() / "HEAD.next").exists())
        with self.assertRaises(ValueError):
            self.begin(head, "resume")

    def test_result_written_before_failed_publication_cannot_complete_by_retry(self):
        head = self.initialize()["head_sha256"]
        pending = self.begin(head)
        write = journal._write

        def fail(path, value):
            result = write(path, value)
            if path.name == "result.json":
                raise OSError("injected fsync return failure")
            return result

        with mock.patch.object(journal, "_write", side_effect=fail):
            with self.assertRaises(OSError):
                self.complete(pending)
        self.assertTrue((self.path() / journal._slot(1) / "result.json").exists())
        with self.assertRaises(ValueError):
            self.complete(pending)
        with self.assertRaises(ValueError):
            self.begin(head, "resume")

    def test_failed_close_preserves_candidate_and_explicit_failure_barrier(self):
        head = self.initialize()["head_sha256"]
        pending = self.begin(head)
        inspect = journal._inspect

        def fail(binding, trusted):
            result = inspect(binding, trusted)
            if result.head["state"] == "ready" and result.head["sequence"] == 1:
                raise ValueError("injected final closure failure")
            return result

        with mock.patch.object(journal, "_inspect", side_effect=fail):
            with self.assertRaises(ValueError):
                self.complete(pending)
        candidate_raw = (self.path() / "HEAD.json").read_bytes()
        with pair.locked_pair(self.datasets):
            journal._fail(pending, "closing-refused", "unknown")
        self.assertEqual((self.path() / "HEAD.json").read_bytes(), candidate_raw)
        for digest in (head, journal.state.sha256(candidate_raw)):
            with self.assertRaises(ValueError):
                self.begin(digest, "resume")
        self.assertTrue((self.path() / journal._slot(1) / "failure.json").exists())

    def test_orphan_and_permissive_metadata_refuse_without_repair(self):
        head = self.initialize()["head_sha256"]
        path = self.path() / "profile.json"
        path.chmod(0o640)
        with self.assertRaises(ValueError):
            journal._inspect(self.binding, head)
        path.chmod(0o600)
        (self.path() / journal._slot(1)).mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.begin(head)

    def test_substituted_file_and_boolean_sequence_are_not_valid_metadata(self):
        head = self.initialize()["head_sha256"]
        path = self.path() / "HEAD.json"
        value = json.loads(path.read_bytes())
        value["sequence"] = False
        raw = journal.state.canonical(value)
        path.write_bytes(raw)
        with self.assertRaises(ValueError):
            journal._inspect(self.binding, journal.state.sha256(raw))

    def test_chain_tamper_and_foreign_root_file_refuse(self):
        head = self.initialize()["head_sha256"]
        candidate = self.complete(self.begin(head))
        path = self.path() / journal._slot(1) / "intent.json"
        value = json.loads(path.read_bytes())
        value["prepared_sha256"] = "f" * 64
        path.write_bytes(journal.state.canonical(value))
        with self.assertRaises(ValueError):
            journal._inspect(self.binding, candidate.head_sha256)

    def test_real_pair_excludes_other_process_and_pending_survives_its_release(self):
        self.initialize()
        code = r"""
import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import persistence_pair_lock as p, persistence_owner_journal as j
p.backup.RUNTIME_ROOT=Path(sys.argv[2]);j.RUNTIME_ROOT=Path(sys.argv[3]);datasets=json.loads(sys.argv[4])
b=j.Binding(j.state.pair_key(datasets),'b'*64,j.api.GuestBinding('pve-example',102,'1'*64,'2'*64,'3'*64))
try:
 with p.locked_pair(datasets):
  if sys.argv[5]=='busy':raise AssertionError('pair lease was not held')
  try:j._begin(b,sys.argv[6],'resume','e'*64)
  except ValueError:pass
  else:raise AssertionError('pending operation was bypassed')
except p.state.PersistenceError as e:
 assert sys.argv[5]=='busy' and e.code=='persistence-pair-busy'
"""
        head = journal._genesis(self.binding)
        head_sha = journal.state.sha256(journal.state.canonical(head))
        args = [
            sys.executable,
            "-B",
            "-c",
            code,
            str(ROOT / "ansible"),
            str(journal.backup.RUNTIME_ROOT),
            str(journal.RUNTIME_ROOT),
            json.dumps(self.datasets),
        ]
        with pair.locked_pair(self.datasets):
            journal._begin(self.binding, head_sha, "shutdown", "c" * 64)
            result = subprocess.run(
                [*args, "busy", head_sha], capture_output=True, timeout=20
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        result = subprocess.run(
            [*args, "pending", head_sha], capture_output=True, timeout=20
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
