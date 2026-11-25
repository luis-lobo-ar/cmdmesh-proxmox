"""Claimed service/write/stop flow with real locks and SQLite, modeled native IO."""

from contextlib import contextmanager, closing
import copy
import fcntl
import errno
import json
import os
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_writer_execution as execution,
)
import test_persistence_writer_trial as preparation


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class WriterExecutionTests(unittest.TestCase):
    def setUp(self):
        self.base = preparation.WriterPreparationTests("runTest")
        self.addCleanup(self.base.doCleanups)
        self.base.setUp()
        self.fixture = self.base.fixture
        self.prepared = self.base.prepare()
        self.raw = execution.state.canonical(self.prepared)
        self.sha = execution.state.sha256(self.raw)
        self.request = self.prepared["source_request"]
        self.actor = None
        self.actions = []
        self.appends = 0
        self.fault = None
        self.peer = {"pid": 9999, "birth": 9000}
        self.native_service = execution._service
        self.addCleanup(self.release_actor)
        self.old = {
            str(p): p.read_bytes()
            for p in (self.fixture.root / "owner-history").rglob("*")
            if p.is_file()
        }
        original_quiesced = execution._quiesced

        @contextmanager
        def quiesced(*args):
            # The legacy fixture tracks SQL within one observation. Start a new
            # phase before the newly required API/kernel admission outside EX.
            self.fixture.events.clear()
            with original_quiesced(*args) as observed:
                yield observed

        @contextmanager
        def session(*args):
            self.fixture.scopes(True)
            self.assertIsNotNone(self.actor)
            client = SimpleNamespace(
                frame=self.active_frame(), read=self.read, append=self.append
            )
            yield client
            self.fixture.scopes(True)

        for target, name, callback in (
            (execution, "_quiesced", quiesced),
            (execution, "_service", self.service),
            (
                execution,
                "_service_snapshot",
                lambda *args, **kwargs: self.active_frame(),
            ),
            (execution.active, "_session_leased", session),
        ):
            patch = mock.patch.object(target, name, side_effect=callback)
            patch.start()
            self.addCleanup(patch.stop)

    def release_actor(self):
        if self.actor is not None:
            self.actor.close()
            self.actor = None

    def active_frame(self):
        self.fixture.scopes(self.actor is not None)
        before = self.prepared["runtime_identity"]
        image = copy.deepcopy(before["image"])
        image["unit"].update(ActiveState="active", SubState="running", MainPID="321")
        image["accounts"].update(uid_processes=[321], gid_processes=[321])
        return {
            "host": copy.deepcopy(self.prepared["runtime_identity"]["host"]),
            "kernel": copy.deepcopy(self.prepared["runtime_identity"]["kernel"]),
            "guest": {
                **copy.deepcopy(self.prepared["runtime_identity"]["guest"]),
                "runtime": {
                    **copy.deepcopy(
                        self.prepared["runtime_identity"]["guest"]["runtime"]
                    ),
                    "uptime": 500,
                },
            },
            "peer": copy.deepcopy(self.peer),
            "reference": copy.deepcopy(before["reference"]),
            "ownership": copy.deepcopy(before["retained"]["ownership"]),
            "bindings": copy.deepcopy(before["bindings"]),
            "image": image,
        }

    def service(self, prepared, action, expected_peer=None):
        self.assertEqual(prepared["source_request"], self.request)
        self.fixture.scopes(self.actor is not None)
        self.actions.append(action)
        if action == "start":
            self.assertIsNone(self.actor)
            self.actor = self.fixture.config.open("rb")
            fcntl.flock(self.actor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if self.fault == "lost-start":
                raise TimeoutError("PRIVATE_START_ERROR")
        elif action == "stop":
            self.release_actor()
            if self.fault == "lost-stop":
                raise TimeoutError("PRIVATE_STOP_ERROR")
        else:
            self.fail("unknown service action")
        return {
            "exit_code": 0,
            "stdout_sha256": execution.state.sha256(b""),
            "stderr_bytes": 0,
        }

    def read(self):
        self.fixture.scopes(True)
        if self.fault == "auth":
            raise ValueError("PRIVATE_AUTH_ERROR")
        with closing(sqlite3.connect(self.fixture.database)) as database:
            rows = database.execute(
                "SELECT sequence,operation_id,value FROM entries ORDER BY sequence"
            ).fetchall()
        return execution.ledger.validate_read(
            {
                "outcome": "read",
                "instance_id": self.request["policy"]["application"]["instance_id"],
                "entries": [
                    dict(zip(("sequence", "operation_id", "value"), row))
                    for row in rows
                ],
            },
            self.request["policy"]["application"]["instance_id"],
        )

    def append(self, nonce, value):
        self.fixture.scopes(True)
        self.assertEqual(
            (nonce, value),
            (self.prepared["nonce"], execution.trial.payload(self.prepared["nonce"])),
        )
        self.appends += 1
        with closing(sqlite3.connect(self.fixture.database)) as database, database:
            cursor = database.execute(
                "INSERT INTO entries(operation_id,value) VALUES (?,?)", (nonce, value)
            )
            sequence = cursor.lastrowid
        self.fixture.value["retained"]["application"]["database"][
            "bytes"
        ] = self.fixture.database.stat().st_size
        if self.fault == "lost-append":
            raise TimeoutError("PRIVATE_APPEND_ERROR")
        return {
            "outcome": "unchanged" if self.fault == "unchanged" else "committed",
            "sequence": sequence,
        }

    def run_trial(self):
        self.fixture.events.clear()
        return execution.run(self.raw, self.sha)

    def assert_no_replay(self):
        before = list(self.actions), self.appends
        with self.assertRaises(execution.state.PersistenceError):
            self.run_trial()
        self.assertEqual((self.actions, self.appends), before)

    def test_one_claimed_write_preserves_old_rows_stops_and_has_new_read_only_status(
        self,
    ):
        result = self.run_trial()
        self.assertEqual((self.actions, self.appends), (["start", "stop"], 1))
        self.assertIsNone(self.actor)
        self.assertTrue(
            result["rebuild_verified"]
            and result["application_write_verified"]
            and result["application_quiesced"]
        )
        self.assertFalse(
            result["boot_verified"]
            or result["restore_verified"]
            or result["backup_verified"]
        )
        self.assertEqual(result["runtime"]["application"]["record_count"], 2)
        self.assertEqual({name: Path(name).read_bytes() for name in self.old}, self.old)
        self.assert_no_replay()
        with mock.patch.object(
            execution.trial.boot, "status", side_effect=AssertionError("old tuple")
        ), mock.patch.object(
            execution.trial, "prepare", side_effect=AssertionError("replay")
        ):
            status = execution.status(self.raw, self.sha, result["completion_sha256"])
        self.assertFalse(status["mutation_attempted"])
        self.assertEqual(status["completion_sha256"], result["completion_sha256"])
        self.fixture.released()

    def test_unknown_start_is_contained_once_without_write_or_success(self):
        self.fault = "lost-start"
        with self.assertRaises(TimeoutError):
            self.run_trial()
        self.assertEqual((self.actions, self.appends), (["start", "stop"], 0))
        self.assertIsNone(self.actor)
        self.assert_no_replay()

    def test_unknown_append_stops_but_does_not_mint_success_or_retry(self):
        self.fault = "lost-append"
        with self.assertRaises(TimeoutError):
            self.run_trial()
        self.assertEqual((self.actions, self.appends), (["start", "stop"], 1))
        self.assertIsNone(self.actor)
        directory = execution.trial.claim_path(self.request)
        self.assertFalse((directory / "complete.json").exists())
        self.assertTrue((directory / "failed.json").exists())
        self.assertNotIn("PRIVATE_", (directory / "failed.json").read_text())
        self.assert_no_replay()
        with self.assertRaises(execution.state.PersistenceError):
            execution.status(self.raw, self.sha, "0" * 64)

    def test_stop_acknowledgement_loss_never_sends_another_stop(self):
        self.fault = "lost-stop"
        with self.assertRaises(TimeoutError):
            self.run_trial()
        self.assertEqual((self.actions, self.appends), (["start", "stop"], 1))
        self.assert_no_replay()

    def test_auth_failure_still_permits_independently_admitted_containment(self):
        self.fault = "auth"
        with self.assertRaises(ValueError):
            self.run_trial()
        self.assertEqual((self.actions, self.appends), (["start", "stop"], 0))
        self.assertIsNone(self.actor)

    def test_unchanged_response_cannot_qualify_the_first_absent_nonce(self):
        self.fault = "unchanged"
        with self.assertRaises(execution.state.PersistenceError):
            self.run_trial()
        self.assertEqual((self.actions, self.appends), (["start", "stop"], 1))
        self.assertFalse(
            (execution.trial.claim_path(self.request) / "complete.json").exists()
        )

    def test_readiness_observation_retries_without_repeating_service_start(self):
        original = execution.active._session_leased
        attempts = []

        @contextmanager
        def delayed(*args):
            attempts.append(True)
            if len(attempts) == 1:
                raise FileNotFoundError(errno.ENOENT, "not listening yet", "api.sock")
            with original(*args) as client:
                yield client

        with mock.patch.object(
            execution.active, "_session_leased", side_effect=delayed
        ), mock.patch.object(execution.time, "sleep"):
            result = self.run_trial()
        self.assertTrue(result["rebuild_verified"])
        self.assertEqual(
            (self.actions, self.appends, len(attempts)), (["start", "stop"], 1, 2)
        )

    def test_status_refuses_completion_replaced_after_its_initial_read(self):
        result = self.run_trial()
        original = execution._close_parent
        path = execution.trial.claim_path(self.request) / "complete.json"
        calls = []

        def replaced(*args):
            original(*args)
            calls.append(True)
            if len(calls) == 1:
                document = json.loads(path.read_bytes())
                document["unexpected"] = True
                path.write_bytes(execution.state.canonical(document))

        with mock.patch.object(execution, "_close_parent", side_effect=replaced):
            with self.assertRaises(execution.state.PersistenceError):
                execution.status(self.raw, self.sha, result["completion_sha256"])

    def test_changed_append_dispatch_is_not_accepted_as_a_valid_journal(self):
        original = execution._record

        def record(directory, name, value):
            if name == "append-dispatch.json":
                value = {**value, "operation_id": "f" * 32}
            return original(directory, name, value)

        with mock.patch.object(execution, "_record", side_effect=record):
            with self.assertRaises(execution.state.PersistenceError):
                self.run_trial()
        self.assertEqual((self.actions, self.appends), (["start", "stop"], 1))

    def test_database_change_during_completion_write_cannot_qualify(self):
        original = execution._record

        def record(directory, name, value):
            checksum = original(directory, name, value)
            if name == "complete.json":
                with closing(
                    sqlite3.connect(self.fixture.database)
                ) as database, database:
                    database.execute(
                        "INSERT INTO entries(operation_id,value) VALUES (?,?)",
                        ("f" * 32, "late change"),
                    )
            return checksum

        with mock.patch.object(execution, "_record", side_effect=record):
            with self.assertRaises(execution.state.PersistenceError):
                self.run_trial()
        self.assertTrue(
            (execution.trial.claim_path(self.request) / "failed.json").exists()
        )
        self.assert_no_replay()

    def test_readiness_timeout_is_contained_without_api_or_second_start(self):
        @contextmanager
        def missing(*args):
            raise FileNotFoundError(errno.ENOENT, "not ready", "api.sock")
            yield

        clock = mock.Mock(side_effect=[0, 241])
        with mock.patch.object(
            execution, "time", SimpleNamespace(monotonic=clock, sleep=mock.Mock())
        ), mock.patch.object(execution.active, "_session_leased", side_effect=missing):
            with self.assertRaises(execution.state.PersistenceError):
                self.run_trial()
        self.assertEqual((self.actions, self.appends), (["start", "stop"], 0))
        self.assertIsNone(self.actor)

    def test_late_successful_admission_cannot_exceed_the_readiness_deadline(self):
        clock = mock.Mock(side_effect=[0, 241])
        with mock.patch.object(
            execution, "time", SimpleNamespace(monotonic=clock, sleep=mock.Mock())
        ):
            with self.assertRaises(execution.state.PersistenceError):
                self.run_trial()
        self.assertEqual((self.actions, self.appends), (["start", "stop"], 0))

    def test_changed_peer_is_not_stopped_during_normal_or_failure_paths(self):
        original = self.active_frame

        def changed(*args):
            frame = original()
            frame["peer"]["birth"] += 1
            return frame

        with mock.patch.object(execution, "_service_snapshot", side_effect=changed):
            with self.assertRaises(execution.state.PersistenceError):
                self.run_trial()
        self.assertEqual((self.actions, self.appends), (["start"], 1))
        self.assertIsNotNone(self.actor)
        self.assert_no_replay()

    def test_fabricated_read_hash_is_not_accepted_from_a_client(self):
        original = self.read

        def fabricated():
            value = original()
            value["records_sha256"] = "0" * 64
            return value

        with mock.patch.object(self, "read", side_effect=fabricated):
            with self.assertRaises(execution.state.PersistenceError):
                self.run_trial()
        self.assertEqual((self.actions, self.appends), (["start", "stop"], 0))

    def insert_late_row(self):
        with closing(sqlite3.connect(self.fixture.database)) as database, database:
            database.execute(
                "INSERT INTO entries(operation_id,value) VALUES (?,?)",
                ("f" * 32, "late external row"),
            )

    def test_run_final_history_read_precedes_the_last_sql_observation(self):
        original = execution._close_parent
        calls = []

        def mutate(*args):
            original(*args)
            calls.append(True)
            if len(calls) == 3:
                self.insert_late_row()

        with mock.patch.object(execution, "_close_parent", side_effect=mutate):
            with self.assertRaises(execution.state.PersistenceError):
                self.run_trial()
        self.assertTrue(
            (execution.trial.claim_path(self.request) / "failed.json").exists()
        )

    def test_status_final_history_read_precedes_the_last_sql_observation(self):
        result = self.run_trial()
        original = execution._close_parent
        calls = []

        def mutate(*args):
            original(*args)
            calls.append(True)
            if len(calls) == 2:
                self.insert_late_row()

        with mock.patch.object(execution, "_close_parent", side_effect=mutate):
            with self.assertRaises(execution.state.PersistenceError):
                execution.status(self.raw, self.sha, result["completion_sha256"])

    def test_status_wrong_host_refuses_before_configuration_access(self):
        result = self.run_trial()
        with mock.patch.object(
            execution.runtime.observe,
            "host_facts",
            side_effect=execution.state.PersistenceError("wrong-host"),
        ), mock.patch.object(
            execution.runtime.observe,
            "locked_config",
            side_effect=AssertionError("credential access before admission"),
        ):
            with self.assertRaises(execution.state.PersistenceError):
                execution.status(self.raw, self.sha, result["completion_sha256"])

    @contextmanager
    def native_leases(self):
        self.fixture.events.clear()
        policy = self.request["policy"]
        with execution.runtime.pair_lock.locked_pair(
            policy["datasets"]
        ), execution.ExitStack() as held:
            for vmid in sorted((policy["vmid"], policy["retired_guest"]["vmid"])):
                held.enter_context(execution.runtime.config_lock.read_guest(vmid))
            yield

    def test_native_start_uses_only_fixed_service_and_does_not_read_credentials(self):
        with self.native_leases(), mock.patch.object(
            execution.runtime.observe, "native", return_value=b""
        ) as native, mock.patch.object(
            execution.runtime.observe,
            "locked_config",
            side_effect=AssertionError("no credential read for service action"),
        ):
            self.native_service(self.prepared, "start")
        native.assert_called_once_with(
            [
                "/usr/sbin/pct",
                "exec",
                str(self.request["policy"]["vmid"]),
                "--",
                "/usr/bin/systemctl",
                "start",
                "reference-ledger.service",
            ]
        )

    def test_native_stop_requires_matching_current_peer_before_dispatch(self):
        with self.native_leases(), mock.patch.object(
            execution.runtime.observe, "native"
        ) as native:
            with self.assertRaises(execution.state.PersistenceError):
                self.native_service(
                    self.prepared, "stop", expected_peer={**self.peer, "birth": 8999}
                )
        native.assert_not_called()

    def test_unknown_service_action_is_rejected_without_native_dispatch(self):
        with mock.patch.object(execution.runtime.observe, "native") as native:
            with self.assertRaises(execution.state.PersistenceError):
                self.native_service(self.prepared, "restart")
        native.assert_not_called()

    def test_claim_directory_mode_change_during_final_history_refuses_success(self):
        original = execution._close_parent
        calls = []

        def changed(*args):
            original(*args)
            calls.append(True)
            if len(calls) == 3:
                execution.trial.claim_path(self.request).chmod(0o777)

        with mock.patch.object(execution, "_close_parent", side_effect=changed):
            with self.assertRaises(execution.state.PersistenceError):
                self.run_trial()


if __name__ == "__main__":
    unittest.main()
