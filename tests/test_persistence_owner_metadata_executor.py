"""Self-leased metadata orchestration; native/current providers are modeled.

Disposable journals, pair/application/native flocks and Linux publication
observers are real. The external producer/FS qualification is a model, not an
installed-source or managed-filesystem qualification.
"""

import importlib
import copy
from contextlib import contextmanager, ExitStack, closing
import os
from pathlib import Path
import sqlite3
import shutil
import unittest
from unittest import mock


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class MetadataExecutorBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.executor = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_metadata_executor"
        )

    def test_invalid_admission_refuses_before_any_lease_or_observation(self):
        with mock.patch.object(
            self.executor.transition, "_leased", side_effect=AssertionError("lease IO")
        ):
            for function in (
                self.executor.execute_begin,
                self.executor.execute_continuation,
            ):
                with self.subTest(function=function.__name__), self.assertRaises(
                    ValueError
                ):
                    function(
                        admission=object(),
                        capture_raw=b"{}",
                        capture_sha256="0" * 64,
                        plan_raw=b"{}",
                        plan_sha256="0" * 64,
                        phase="os_quiesced",
                        allow_mutation=True,
                        check_mode=False,
                    )

    def test_readonly_requalification_refuses_unselected_object_before_io(self):
        with mock.patch.object(
            self.executor.transition, "_leased", side_effect=AssertionError("lease IO")
        ):
            with self.assertRaises(ValueError):
                self.executor.requalify_complete(
                    admission=object(),
                    capture_raw=b"{}",
                    capture_sha256="0" * 64,
                    complete_raw=b"{}",
                    complete_sha256="0" * 64,
                    phase="os_quiesced",
                )


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class MetadataExecutorTests(unittest.TestCase):
    def setUp(self):
        from test_persistence_owner_fence import OwnerFenceTests
        from test_persistence_owner_execution_admission import examples
        from test_persistence_owner_phase_admission import admission_inputs

        self.executor = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_metadata_executor"
        )
        self.model = OwnerFenceTests("runTest")
        self.model.setUp()
        self.addCleanup(self.model.doCleanups)
        e = self.executor
        r = e.r
        self.r = r
        self.sdk = self.model.sdk
        self.root = self.model.case.case.root
        runtime_root = r.legacy.RUNTIME_ROOT.parent / "handoff"
        self.enterContext(mock.patch.object(r, "RUNTIME_ROOT", runtime_root))
        self.enterContext(mock.patch.object(e.storage, "RUNTIME_ROOT", runtime_root))
        self.enterContext(
            mock.patch.object(e.attempt, "_WALK_ROOT", runtime_root.parent)
        )
        self.selection, self.docs = examples(self.model, e.admission_codec)
        self.evidence, self.entry, self.prior = admission_inputs(
            self.model.case.model, "os_quiesced"
        )
        self.data = self.root / "executor-data"
        self.data.mkdir(mode=0o700)
        self.db = self.data / "ledger.sqlite3"
        with closing(sqlite3.connect(self.db)) as sql, sql:
            sql.execute("CREATE TABLE sample(value)")
            sql.execute("INSERT INTO sample VALUES(7)")
        self.db.chmod(0o600)
        self.ref = self.root / "reference-control"
        self.ref.write_bytes(b"modeled reference")
        self.ref.chmod(0o600)
        self.actor = self.root / "actor-control"
        self.actor.write_bytes(b"modeled installed/source control")
        self.actor.chmod(0o600)
        self.calls = []
        self.fault = None
        self.worker = 0
        self.enterContext(
            mock.patch.object(
                self.sdk.current,
                "_entry_leased",
                side_effect=lambda *args: copy.deepcopy(self.entry),
            )
        )
        original_lock = self.sdk.observe.locked_config_original

        @contextmanager
        def app_lock(path, uid, gid):
            with original_lock(
                self.model.case.config, os.geteuid(), os.getegid()
            ) as raw:
                self.model.case.app_held = True
                try:
                    yield raw
                finally:
                    self.model.case.app_held = False

        self.enterContext(
            mock.patch.object(self.sdk.observe, "locked_config", side_effect=app_lock)
        )

        @contextmanager
        def holder(**kwargs):
            self.calls.append("early-resources")
            with ExitStack() as stack:
                old = e.resources._Seal(self.model.owner.pair_key)
                db = e.resources._Seal(self.model.owner.pair_key)
                ref = e.resources._Seal(self.model.owner.pair_key)
                for reader in (old, db, ref):
                    stack.callback(reader.release)
                intent = r._intent(
                    self.model.owner,
                    self.selection._intent_raw,
                    self.selection._intent_sha256,
                )
                e.resources._old(old, self.selection, intent, kwargs["action"])
                db.exact_directory(self.data, ["ledger.sqlite3"], private=True)
                db.file(self.db)
                ref.file(self.ref)
                value = Bundle((old, db, ref))
                yield value
                if not value.enumerated:
                    value.check_memberships()
                value.close_named()
                value.check_events()

        @contextmanager
        def actors(admission):
            reader = e.resources._Seal(self.model.owner.pair_key)
            try:
                reader.file(self.actor)
                yield reader
                if not reader.enumerated:
                    reader.check_memberships()
                reader.close_named()
                reader.check_events()
            finally:
                reader.release()

        self.enterContext(
            mock.patch.object(e.resources, "hold_owner_resources", side_effect=holder)
        )
        self.enterContext(
            mock.patch.object(e, "_hold_actor_controls", side_effect=actors)
        )

        @contextmanager
        def frames(cp, entry, raw, prior):
            self.model.case.assert_outer_leases()
            self.assertIn("early-resources", self.calls)
            lock = (
                self.executor.storage.RUNTIME_ROOT.parent
                / self.executor.bootstrap.LOCK_NAME
            )
            if lock.exists():
                with self.executor.bootstrap.locked_runtime_bootstrap():
                    pass
            self.worker += 1
            number = self.worker
            self.calls.append(("initial-sql", number))
            with closing(
                sqlite3.connect("file:" + str(self.db) + "?mode=ro", uri=True)
            ) as sql:
                self.assertEqual(
                    sql.execute("SELECT value FROM sample").fetchall(), [(7,)]
                )
            if self.fault == "first-sql-write" and number == 1:
                self.samebyte(self.db)
            evidence = copy.deepcopy(self.evidence)
            if evidence["phase"] == "os_quiesced":
                evidence["observation"]["guest"]["runtime"]["uptime"] += number * 2
            first = r.state.canonical(evidence)
            value = e.current._CurrentFrames(first, None)
            yield value
            if self.fault == "worker-exit" or (
                self.fault == "second-worker-exit" and number == 2
            ):
                raise ValueError("modeled final worker failure")
            if evidence["phase"] == "os_quiesced":
                evidence["observation"]["guest"]["runtime"]["uptime"] += 1
            with closing(
                sqlite3.connect("file:" + str(self.db) + "?mode=ro", uri=True)
            ) as sql:
                sql.execute("SELECT value FROM sample").fetchall()
            self.calls.append(("closing-sql", number))
            object.__setattr__(value, "closing_raw", r.state.canonical(evidence))
            if self.fault == "post-sql-sidecar" and number == 2:
                (self.data / "ledger.sqlite3-wal").touch(mode=0o600)

        self.enterContext(
            mock.patch.object(e.current, "_current_frames_leased", side_effect=frames)
        )
        self.enterContext(
            mock.patch.object(e.runtime, "seal_database", side_effect=self.seal)
        )
        self.enterContext(
            mock.patch.object(
                e.current,
                "_fast_close",
                side_effect=lambda *a: self.calls.append("sdk-fast"),
            )
        )
        self.enterContext(
            mock.patch.object(
                e,
                "_fixed_close",
                side_effect=lambda *a: self.calls.append("fixed-close"),
            )
        )
        with e.filesystem.observe_subject(self.selection) as observed:
            facts = r.observe.decode(observed.raw)
        self.live_facts = facts
        self.admission("begin")
        self.enterContext(
            mock.patch.object(
                self.sdk.api,
                "post_guest_action",
                side_effect=AssertionError("executor native POST"),
            )
        )

    def admission(self, action):
        e = self.executor
        with e.filesystem.observe_subject(self.selection) as observed:
            facts = self.r.observe.decode(observed.raw)
        for frame in (self.entry, self.evidence["observation"]):
            frame["host"].update(facts["subject"]["host_epoch"])
        q = self.docs["filesystem_qualification"]
        q.update(
            subject=copy.deepcopy(facts["subject"]),
            mounts=copy.deepcopy(facts["mounts"]),
            procfs=copy.deepcopy(facts["procfs"]),
        )
        q["roles"] = {
            role: {**row, "probe_index": 0} for role, row in facts["roles"].items()
        }
        q["probes"][0]["mount_index"] = q["roles"]["intent"]["mount_index"]
        self.docs["admission"]["execution"]["filesystem_qualification_sha256"] = (
            self.model.digest(q)
        )
        args = dict(selection=self.selection, action=action)
        for name, value in self.docs.items():
            raw = self.r.state.canonical(value)
            args[name + "_raw"] = raw
            args[name + "_sha256"] = self.r.state.sha256(raw)
        self.accepted = e.admission_codec.load_execution_admission(**args)
        return self.accepted

    def seal(self, *args):
        self.assertFalse(
            any(
                (self.data / ("ledger.sqlite3" + suffix)).exists()
                for suffix in ("-wal", "-shm", "-journal")
            )
        )
        with closing(
            sqlite3.connect("file:" + str(self.db) + "?mode=ro", uri=True)
        ) as sql:
            self.assertEqual(sql.execute("SELECT value FROM sample").fetchall(), [(7,)])

    def samebyte(self, path):
        raw = path.read_bytes()
        fd = os.open(path, os.O_WRONLY)
        try:
            os.pwrite(fd, raw, 0)
        finally:
            os.close(fd)

    def prepare(self, action):
        e = self.executor
        self.admission(action)
        with e.attempt.inspect_attempt_v2(**self.selection._arguments()) as observed:
            raw, sha = observed.raw, observed.sha256
        args = dict(**self.selection._arguments(), capture_raw=raw, capture_sha256=sha)
        plan = (
            e.begin.prepare_begin(**args)
            if action == "begin"
            else e.continuation.prepare_continuation(**args, action=action)
        )
        return dict(
            admission=self.accepted,
            capture_raw=raw,
            capture_sha256=sha,
            plan_raw=plan.raw,
            plan_sha256=plan.sha256,
            phase="os_quiesced",
            allow_mutation=True,
            check_mode=False,
        )

    def execute(self, action):
        args = self.prepare(action)
        method = (
            self.executor.execute_begin
            if action == "begin"
            else self.executor.execute_continuation
        )
        return method(**args)

    def test_real_clean_begin_ends_h0_only_and_uses_actual_closing_frames(self):
        result = self.execute("begin")
        body = self.r.observe.decode(result.raw)
        self.assertEqual(body["final_capture"]["status"], "h0-only")
        self.assertEqual(
            body["initial_closing_current"]["observation"]["guest"]["runtime"][
                "uptime"
            ],
            self.evidence["observation"]["guest"]["runtime"]["uptime"] + 3,
        )
        self.assertEqual(
            body["final_closing_current"]["observation"]["guest"]["runtime"]["uptime"],
            self.evidence["observation"]["guest"]["runtime"]["uptime"] + 5,
        )
        self.assertEqual(len(body["publication_receipts"]), 2)
        self.assertFalse(body["successor_native_admission_authorized"])
        self.assertEqual(
            self.model.case.post_count, 2
        )  # fixture historical shutdown/resume only

    def test_check_or_false_mutation_refuses_before_lease(self):
        args = self.prepare("begin")
        with mock.patch.object(
            self.executor.transition, "_leased", side_effect=AssertionError("lease")
        ):
            for changes in (
                {"allow_mutation": False},
                {"check_mode": True},
                {"check_mode": 0},
                {"allow_mutation": 1},
            ):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    self.executor.execute_begin(**{**args, **changes})

    def test_early_db_samebyte_and_worker_failure_prevent_closed_return(self):
        self.fault = "first-sql-write"
        with self.assertRaises(ValueError):
            self.execute("begin")
        self.assertFalse(
            (
                self.executor.storage.RUNTIME_ROOT
                / self.model.owner.pair_key
                / "intent.json"
            ).exists()
        )

    def test_four_missing_only_edges_and_explicit_readonly_requalification(self):
        e = self.executor
        root = e.storage.RUNTIME_ROOT
        pair = root / self.model.owner.pair_key
        root.mkdir(mode=0o700)
        self.execute("finish-runtime")
        pair.mkdir(mode=0o700)  # source-defined setup of the next missing stage
        self.execute("record-intent")
        self.execute("publish-marker")
        result = self.execute("record-completion")
        body = self.r.observe.decode(result.raw)
        self.assertEqual(body["final_capture"]["status"], "complete-candidate")
        self.assertEqual(body["final_capture"]["completion_schema_version"], 2)
        complete_raw = (pair / "complete.json").read_bytes()
        complete_sha = self.r.state.sha256(complete_raw)
        self.admission("requalify-complete")
        with e.attempt.inspect_attempt_v2(**self.selection._arguments()) as observed:
            args = dict(capture_raw=observed.raw, capture_sha256=observed.sha256)
        value = e.requalify_complete(
            admission=self.accepted,
            **args,
            complete_raw=complete_raw,
            complete_sha256=complete_sha,
            phase="os_quiesced",
            original_contract_raw=self.selection._contract_raw,
            original_contract_sha256=self.selection.contract_sha256
        )
        self.assertTrue(self.r.observe.decode(value.raw)["readonly"])
        self.assertEqual((pair / "complete.json").read_bytes(), complete_raw)
        # A completed stage cannot be implicitly retried as its old edge.
        with self.assertRaises(ValueError):
            self.prepare("record-completion")

    def test_post_sql_sidecar_and_lost_return_leave_barrier_without_candidate(self):
        self.fault = "post-sql-sidecar"
        with self.assertRaises((ValueError, AssertionError)):
            self.execute("begin")
        self.assertTrue(
            (
                self.executor.storage.RUNTIME_ROOT
                / self.model.owner.pair_key
                / "intent.json"
            ).exists()
        )
        self.assertFalse(
            (
                self.executor.storage.RUNTIME_ROOT
                / self.model.owner.pair_key
                / "complete.json"
            ).exists()
        )

    def test_closing_worker_failure_preserves_published_prefix(self):
        self.fault = "second-worker-exit"
        with self.assertRaisesRegex(ValueError, "final worker"):
            self.execute("begin")
        self.assertTrue(
            (
                self.executor.storage.RUNTIME_ROOT
                / self.model.owner.pair_key
                / "intent.json"
            ).exists()
        )

    def test_fresh_projection_and_stopped_prior_refuse_before_publication(self):
        args = self.prepare("begin")
        self.r.state.sha256(args["capture_raw"])
        with self.assertRaisesRegex(ValueError, "explicit-stopped-prior"):
            self.executor.execute_begin(**{**args, "phase": "stopped"})
        self.executor.storage.RUNTIME_ROOT.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.executor.execute_begin(**args)
        self.assertFalse((self.executor.storage.RUNTIME_ROOT / "runtime.json").exists())

    def test_stopped_begin_requires_explicit_prior_and_preserves_historical_h0(self):
        from test_persistence_owner_phase_admission import admission_inputs

        self.evidence, self.entry, prior = admission_inputs(
            self.model.case.model, "stopped", new_epoch=True
        )
        args = self.prepare("begin")
        raw = self.r.state.canonical(prior)
        result = self.executor.execute_begin(
            **{
                **args,
                "phase": "stopped",
                "prior_runtime_raw": raw,
                "prior_runtime_sha256": self.r.state.sha256(raw),
            }
        )
        body = self.r.observe.decode(result.raw)
        self.assertEqual(body["final_closing_current"]["phase"], "stopped")
        self.assertEqual(
            (
                self.executor.storage.RUNTIME_ROOT
                / self.model.owner.pair_key
                / "intent.json"
            ).read_bytes(),
            self.selection._intent_raw,
        )
        self.assertFalse(body["ack_recovered"])

    def test_runtime1_complete_has_distinct_readonly_forensics_not_normal_admission(
        self,
    ):
        # SETUP ONLY: old O_EXCL publisher; no claim of atomic publication.
        with self.sdk.runtime.pair_lock.locked_pair(self.model.case.case.datasets):
            claim = self.r._begin(
                self.model.owner,
                self.selection._intent_raw,
                self.selection._intent_sha256,
            )
            retired = self.r._mark(claim)
            old = self.r.observe.decode(self.selection._intent_raw)["caller_evidence"]
            raw = self.r.state.canonical(old)
            completed = self.r._complete(retired, raw, self.r.state.sha256(raw))
        self.admission("requalify-complete")
        with self.executor.attempt.inspect_attempt_v2(
            **self.selection._arguments()
        ) as observed:
            body = self.r.observe.decode(observed.raw)
            self.assertEqual(body["status"], "blocked")
            self.assertEqual(body["blocked_reasons"], ["legacy-runtime-profile"])
            args = dict(capture_raw=observed.raw, capture_sha256=observed.sha256)
        before = (self.executor.storage.RUNTIME_ROOT / "runtime.json").read_bytes()
        result = self.executor.requalify_complete(
            admission=self.accepted,
            **args,
            complete_raw=completed.raw,
            complete_sha256=completed.sha256,
            phase="os_quiesced"
        )
        result_body = self.r.observe.decode(result.raw)
        self.assertEqual(result_body["final_capture"]["status"], "blocked")
        self.assertTrue(result_body["requalification_candidate"])
        self.assertEqual(
            (self.executor.storage.RUNTIME_ROOT / "runtime.json").read_bytes(), before
        )
        with self.assertRaises(ValueError):
            self.prepare("begin")

    def test_outer_lease_exit_error_prevents_return_and_preserves_prefix(self):
        original = self.executor.transition._leased

        @contextmanager
        def failed(*args):
            with original(*args) as scope:
                yield scope
            raise OSError("modeled lease exit failure")

        with mock.patch.object(self.executor.transition, "_leased", side_effect=failed):
            with self.assertRaisesRegex(OSError, "lease exit failure"):
                self.execute("begin")
        self.assertTrue(
            (
                self.executor.storage.RUNTIME_ROOT
                / self.model.owner.pair_key
                / "intent.json"
            ).exists()
        )

    def test_actor_or_old_slot_write_during_final_sql_refuses(self):
        original = self.executor.current._current_frames_leased

        @contextmanager
        def changed(*args):
            with original(*args) as frames:
                yield frames
            if self.worker == 2:
                self.samebyte(self.actor)

        with mock.patch.object(
            self.executor.current, "_current_frames_leased", side_effect=changed
        ):
            with self.assertRaises(ValueError):
                self.execute("begin")

    def test_cleanup_attempts_preserve_original_error(self):
        trace = []
        first = ValueError("first validation failure")

        @contextmanager
        def broken(name):
            try:
                yield
            finally:
                trace.append(name)
                raise OSError(name)

        try:
            with self.executor._Stack() as stack:
                stack.enter_context(broken("first-resource"))
                stack.enter_context(broken("second-resource"))
                raise first
        except ValueError as caught:
            self.assertIs(caught, first)
        else:
            self.fail("original error suppressed")
        self.assertEqual(trace, ["second-resource", "first-resource"])

    def test_finish_runtime_holds_actual_global_mutex_but_never_during_sql(self):
        e = self.executor
        e.storage.RUNTIME_ROOT.mkdir(mode=0o700)
        with e.bootstrap.locked_runtime_bootstrap(initialize=True):
            pass
        publish = e._publish

        def checked(admission, fs, publication, role):
            if role == "runtime-profile":
                with self.assertRaises(ValueError):
                    with e.bootstrap.locked_runtime_bootstrap():
                        pass
            return publish(admission, fs, publication, role)

        with mock.patch.object(e, "_publish", side_effect=checked):
            self.execute("finish-runtime")
        # The mutex is still a permanent, reusable same-inode record.
        with e.bootstrap.locked_runtime_bootstrap():
            pass

    def test_decoded_closing_evidence_must_match_captured_worker_bytes(self):
        e = self.executor
        raw = self.r.state.canonical(self.evidence)
        frames = e.current._CurrentFrames(raw, raw)
        original = e.current.validate_current

        def changed(cp, phase, evidence):
            original(cp, phase, evidence)
            evidence["observation"]["guest"]["runtime"]["uptime"] += 100

        with mock.patch.object(e.current, "validate_current", side_effect=changed):
            with self.assertRaises(ValueError):
                e._evidence(frames, self.selection._private_checkpoint, "os_quiesced")

    def test_initial_full_inspector_covers_projected_old_resource_setup(self):
        e = self.executor
        root = e.storage.RUNTIME_ROOT
        pair = root / self.model.owner.pair_key
        root.mkdir(mode=0o700)
        self.r.backup.write_private(root / "runtime.json", e.storage.RUNTIME)
        pair.mkdir(mode=0o700)
        self.r.backup.write_private(
            pair / "intent.json", self.r.observe.decode(self.selection._intent_raw)
        )
        path = self.r.legacy.RUNTIME_ROOT / self.model.owner.pair_key
        baseline = e.attempt._identity(path.stat())
        identity = e.attempt._identity
        original = e.resources.hold_owner_resources

        @contextmanager
        def changed(**args):
            with original(**args) as held:
                extra = path / "unexpected"
                extra.touch(mode=0o600)
                extra.unlink()
                yield held

        def same_metadata(info):
            value = identity(info)
            # Real Linux CREATE/DELETE events; only the same-tick metadata
            # collision is modeled. Do not age/restore the fixture timestamps.
            if value[:2] == baseline[:2]:
                value[5:] = baseline[5:]
            return value

        with mock.patch.object(
            e.attempt, "_identity", side_effect=same_metadata
        ), mock.patch.object(e.resources, "hold_owner_resources", side_effect=changed):
            with self.assertRaises(ValueError):
                self.execute("publish-marker")
        self.assertFalse((path / e.storage.MARKER).exists())


class Bundle:
    """Explicit orchestration-only resource provider with real Linux seals."""

    def __init__(self, seals):
        self.seals = seals
        self.enumerated = False

    @property
    def nodes(self):
        return {key: value for seal in self.seals for key, value in seal.nodes.items()}

    def check_memberships(self):
        for seal in self.seals:
            seal.check_memberships()
        self.enumerated = True

    def close_named(self):
        for seal in self.seals:
            seal.close_named()

    def check_events(self):
        for seal in self.seals:
            seal.check_events()
