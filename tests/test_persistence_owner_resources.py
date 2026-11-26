"""Real disposable FD/SQLite/inotify resources; no native/current qualification.

Reference locations/root IDs and mapped application IDs are explicitly projected
to unprivileged fixture files. Pure reference/ownership/selection codecs remain
real; no observer, holder or top-level validation is replaced.
"""

import copy
from contextlib import closing, ExitStack
import importlib
import os
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import unittest
from unittest import mock

import test_persistence_owner_admission as admission_fixture
import test_persistence_owner_completion as fixture
from test_persistence_owner_phase_admission import admission_inputs


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class OwnerResourcesTests(unittest.TestCase):
    def setUp(self):
        self.module = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_resources"
        )
        self.runtime = self.module.current.runtime
        root = Path(__file__).resolve().parents[1] / ".generated"
        temporary = tempfile.TemporaryDirectory(prefix="owner-resources-", dir=root)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        self.data.mkdir(mode=0o700)
        self.database = self.data / "ledger.sqlite3"
        with closing(sqlite3.connect(self.database)) as sql, sql:
            sql.execute("CREATE TABLE sample(value INTEGER)")
            sql.execute("INSERT INTO sample VALUES (7)")
        self.database.chmod(0o600)
        original = admission_fixture.OwnerAdmissionTests.setUp

        def setup(model):
            original(model)
            self.model = model
            policy = model.request["policy"]
            old_mount = policy["datasets"]["data"]["mountpoint"]
            policy["datasets"]["data"]["mountpoint"] = str(self.data)

            def replace(value):
                if type(value) is dict:
                    for key, item in value.items():
                        value[key] = replace(item)
                elif type(value) is list:
                    value[:] = [replace(item) for item in value]
                elif type(value) is str:
                    return value.replace(old_mount, str(self.data))
                return value

            replace(model.frame)
            replace(model.profile)
            database = model.frame["retained"]["application"]["database"]
            database.update(
                inode=self.database.stat().st_ino, bytes=self.database.stat().st_size
            )
            preserved = b"synthetic preserved reference\n"
            policy["retired_guest"]["preserved_dropin_sha256"] = (
                self.runtime.state.sha256(preserved)
            )
            ownership = model.frame["retained"]["ownership"]
            ownership["document"] = model.guard.owner_document(policy)
            for unit in ownership["retired"]["units"].values():
                unit["preserved_file"]["sha256"] = policy["retired_guest"][
                    "preserved_dropin_sha256"
                ]
            files = model.frame["reference"]["files"]
            for logical in files:
                body = (
                    model.profile["guard_python"].encode()
                    if logical == model.request["reference_guard"]["path"]
                    else (
                        self.runtime.state.canonical(policy)
                        if logical.endswith("policy.json")
                        else self.runtime.reference_body(model.request)
                    )
                )
                actual = self.project(logical)
                actual.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                actual.write_bytes(body)
                actual.chmod(0o600)
                files[logical].update(
                    sha256=self.runtime.state.sha256(body),
                    identity=self.virtual_identity(actual),
                )
            owner = self.project(model.guard.owner_path(policy))
            owner.parent.mkdir(mode=0o700, parents=True)
            owner.write_bytes(self.runtime.state.canonical(ownership["document"]))
            owner.chmod(0o600)
            ownership["file"].update(
                sha256=self.runtime.state.sha256(owner.read_bytes()),
                identity=self.virtual_identity(owner),
            )
            ownership["directory"]["identity"] = self.virtual_identity(owner.parent)
            for name, unit in ownership["retired"]["units"].items():
                for logical, field, body in zip(
                    model.guard.retired_paths(policy, name),
                    ("preserved_file", "denial_file"),
                    (preserved, model.guard.DENIAL),
                ):
                    actual = self.project(logical)
                    actual.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    actual.write_bytes(body)
                    actual.chmod(0o600)
                    unit[field].update(
                        sha256=self.runtime.state.sha256(body),
                        identity=self.virtual_identity(actual),
                    )
            model.authority["prepared_sha256"] = self.runtime.state.sha256(
                self.runtime.state.canonical(model.authority["prepared"])
            )
            model.authority["completion_sha256"] = self.runtime.state.sha256(
                self.runtime.state.canonical(model.authority["completion"])
            )

        self.case = fixture.CompletionTests("runTest")
        self.case.prepare_old_completion = False
        with mock.patch.object(admission_fixture.OwnerAdmissionTests, "setUp", setup):
            self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.r = self.case.old.r
        self.enterContext(mock.patch.object(self.module.attempt, "_WALK_ROOT", root))
        # Test-only fixed logical-location/root-ID projection; actual FD/inotify
        # operations and all production semantic validators remain in use.
        self.enterContext(
            mock.patch.object(self.module, "Path", side_effect=self.project)
        )
        expected = self.module._expected

        def local(value):
            value = expected(value)
            if value is not None:
                value[3:5] = [os.geteuid(), os.getegid()]
            return value

        self.enterContext(
            mock.patch.object(self.module, "_expected", side_effect=local)
        )
        identity = self.module.attempt._identity
        mapped = self.case.cp["prepared"]["source_request"]["policy"]["mapping"]

        def application_identity(info):
            value = identity(info)
            if (value[0], value[1]) in {
                (self.data.stat().st_dev, self.data.stat().st_ino),
                (self.database.stat().st_dev, self.database.stat().st_ino),
            }:
                value[3:5] = [mapped["offset"] + mapped[key] for key in ("uid", "gid")]
            return value

        self.enterContext(
            mock.patch.object(
                self.module.attempt, "_identity", side_effect=application_identity
            )
        )
        self.entry = admission_inputs(self.case.model, "os_quiesced")[1]
        self.selected = self.module.semantics.select(**self.case.arguments())

    def project(self, path):
        path = Path(path)
        return (
            self.root / "reference" / path.relative_to("/")
            if str(path).startswith(
                ("/etc/", "/srv/", "/var/lib/cmdmesh/persistence-owners")
            )
            else path
        )

    def virtual_identity(self, path):
        value = list(self.runtime.observe.stable(path.stat()))
        value[3:5] = [0, 0]
        return value

    def held(self, action="inspect", **changes):
        return self.module.hold_owner_resources(
            **dict(selection=self.selected, entry=self.entry, action=action, **changes)
        )

    def samebyte(self, path):
        raw = path.read_bytes()
        fd = os.open(path, os.O_WRONLY)
        try:
            os.pwrite(fd, raw, 0)
        finally:
            os.close(fd)

    def test_readonly_real_files_sql_and_idempotent_release(self):
        before = len(os.listdir("/proc/self/fd"))
        with self.held() as held:
            with closing(
                sqlite3.connect("file:" + str(self.database) + "?mode=ro", uri=True)
            ) as sql:
                self.assertEqual(
                    sql.execute("SELECT value FROM sample").fetchall(), [(7,)]
                )
            held.check_memberships()
            held.close_named()
            held.check_events()
        self.assertTrue(held.closed)
        held.release()
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_early_database_write_same_bytes_refuses(self):
        with self.assertRaises(ValueError):
            with self.held():
                self.samebyte(self.database)

    def test_caught_direct_seal_check_failure_stays_poisoned(self):
        with self.assertRaises(ValueError):
            with self.held() as held:
                self.samebyte(self.database)
                try:
                    held.database.check_events()
                except ValueError:
                    pass
                self.assertTrue(held.database.poisoned)

    def test_no_context_membership_scan_after_joined_stage(self):
        with self.held() as held:
            held.check_memberships()
            held.close_named()
            held.check_events()
            scan = mock.patch.object(
                held, "check_memberships", side_effect=AssertionError("late scan")
            )
            scan.start()
            self.addCleanup(scan.stop)

    def test_database_sidecar_mode_and_replacement_refuse(self):
        for kind in ("sidecar", "mode", "replace"):
            raw = self.database.read_bytes()
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                with self.held():
                    if kind == "sidecar":
                        (self.data / "ledger.sqlite3-wal").touch(mode=0o600)
                    elif kind == "mode":
                        self.database.chmod(0o644)
                    else:
                        replacement = self.root / "replacement"
                        replacement.write_bytes(raw)
                        replacement.chmod(0o600)
                        os.replace(replacement, self.database)
            self.database.chmod(0o600)
            (self.data / "ledger.sqlite3-wal").unlink(missing_ok=True)
            if kind == "replace":
                break

    def test_initial_database_metadata_and_extra_member_refuse(self):
        with mock.patch.object(
            self.module,
            "_application_ids",
            return_value=(os.geteuid() + 1, os.getegid()),
        ), self.assertRaises(ValueError):
            with self.held():
                pass
        extra = self.data / "extra"
        extra.touch(mode=0o600)
        with self.assertRaises(ValueError):
            with self.held():
                pass

    def test_entry_snapshot_cannot_be_rebased_coherently(self):
        with self.assertRaises(ValueError):
            with self.held() as held:
                held._entry["guest"]["runtime"]["uptime"] += 1
                held._private_entry["guest"]["runtime"]["uptime"] += 1
                held._entry_raw = self.r.state.canonical(held._entry)

    def test_final_selection_validation_cannot_follow_last_event_drain(self):
        pending = {"drained": False, "written": False}
        original = self.module.semantics.Selection.validate
        with self.held() as held:
            drain = held.database.check_events

            def drained():
                drain()
                pending["drained"] = True

            def validate(selected):
                original(selected)
                if pending["drained"] and not pending["written"]:
                    pending["written"] = True
                    self.samebyte(self.case.old.base.path() / "HEAD.json")

            event_patch = mock.patch.object(
                held.database, "check_events", side_effect=drained
            )
            memory_patch = mock.patch.object(
                self.module.semantics.Selection, "validate", validate
            )
            event_patch.start()
            memory_patch.start()
            self.addCleanup(event_patch.stop)
            self.addCleanup(memory_patch.stop)
        self.assertFalse(pending["written"])

    def late_memory_fault(self, field):
        original = self.module.semantics.Selection._memory
        with self.assertRaises(ValueError):
            with self.held() as held:

                def memory(selected):
                    original(selected)
                    caller = sys._getframe(1)
                    if (
                        caller.f_code.co_name == "_memory"
                        and caller.f_locals.get("self") is held
                        and held.closed
                    ):
                        if field == "entry":
                            held._private_entry["guest"]["runtime"]["uptime"] += 1
                        else:
                            held._seals = ()

                patch = mock.patch.object(
                    self.module.semantics.Selection, "_memory", memory
                )
                patch.start()
                self.addCleanup(patch.stop)

    def test_late_selection_memory_cannot_mutate_released_entry(self):
        self.late_memory_fault("entry")

    def test_late_selection_memory_cannot_swap_released_seal_handles(self):
        self.late_memory_fault("handles")

    def test_release_callback_cannot_replace_retained_raw_memory(self):
        with self.assertRaises(ValueError):
            with self.held() as held:
                release = held.old.release

                def changed():
                    release()
                    path = str(self.case.old.base.path() / "HEAD.json")
                    held.old.raws[path] = (b"{}", self.r.state.sha256(b"{}"))

                patch = mock.patch.object(held.old, "release", side_effect=changed)
                patch.start()
                self.addCleanup(patch.stop)

    def test_actual_initial_database_inode_change_refuses_and_closes_fds(self):
        replacement = self.root / "new-database"
        replacement.write_bytes(self.database.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, self.database)
        before = len(os.listdir("/proc/self/fd"))
        with self.assertRaises(ValueError):
            with self.held():
                pass
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_reference_symlink_refuses_and_closes_resources(self):
        path = self.project(next(iter(self.entry["reference"]["files"])))
        target = self.root / "reference-target"
        target.write_bytes(path.read_bytes())
        target.chmod(0o600)
        path.unlink()
        path.symlink_to(target)
        before = len(os.listdir("/proc/self/fd"))
        with self.assertRaises((ValueError, OSError)):
            with self.held():
                pass
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_overflow_and_caught_direct_seal_error_refuse(self):
        with self.assertRaises(ValueError):
            with self.held() as held:
                with mock.patch.object(
                    self.module.os,
                    "read",
                    return_value=struct.pack("iIII", -1, 0x4000, 0, 0),
                ):
                    try:
                        held.reference.check_events()
                    except ValueError:
                        pass
                self.assertTrue(held.reference.poisoned)

    def test_inspect_existing_marker_and_required_marker_policy(self):
        with self.assertRaises(ValueError):
            with self.held("record-completion"):
                pass
        path = self.case.old.base.path() / self.r.MARKER
        self.r.backup.write_private(
            path, self.r._marker(self.case.owner, self.case.h0sha)
        )
        with self.held():
            pass
        with self.held("record-completion"):
            pass
        with self.assertRaises(ValueError):
            with self.held("begin"):
                pass

    def test_duplicate_release_does_not_close_reused_foreign_fd(self):
        foreign = None
        try:
            with self.assertRaises(ValueError):
                with self.held() as held:
                    number = held.old.event
                    held.release()
                    fd = os.open(self.database, os.O_RDONLY)
                    if fd != number:
                        os.dup2(fd, number)
                        os.close(fd)
                    foreign = number
                    held.release()
                    os.fstat(foreign)
            os.fstat(foreign)
        finally:
            if foreign is not None:
                os.close(foreign)

    def test_reference_and_old_slot_samebyte_refuse(self):
        self.refusal_write(self.project(next(iter(self.entry["reference"]["files"]))))

    def refusal_write(self, path):
        entered = False
        with self.assertRaises(ValueError):
            with self.held():
                entered = True
                self.samebyte(path)
        self.assertTrue(entered)

    def test_old_head_write_occurs_after_successful_entry(self):
        self.refusal_write(self.case.old.base.path() / "HEAD.json")

    def test_old_slot_write_occurs_after_successful_entry(self):
        self.refusal_write(
            self.case.old.base.path() / self.r.legacy._slot(2) / "failure.json"
        )

    def test_stopped_uses_real_reference_validator(self):
        self.entry = admission_inputs(self.case.model, "stopped")[1]
        with self.held():
            pass
        self.entry["reference"]["units"][next(iter(self.entry["reference"]["units"]))][
            "MainPID"
        ] = 22
        with self.assertRaises(ValueError):
            with self.held():
                pass

    def test_entry_memory_drift_and_caught_check_failure_poison_context(self):
        with self.assertRaises(ValueError):
            with self.held():
                self.entry["guest"]["runtime"]["uptime"] += 1
        self.entry["guest"]["runtime"]["uptime"] -= 1
        with self.assertRaises(ValueError):
            with self.held() as held:
                self.samebyte(self.database)
                try:
                    held.check_events()
                except ValueError:
                    pass

    def test_all_scans_precede_named_and_final_scan_change_refuses(self):
        with self.assertRaises(ValueError):
            with self.held() as held:
                original = held.database.check_memberships

                def late():
                    original()
                    self.samebyte(
                        self.project(next(iter(self.entry["reference"]["files"])))
                    )

                with mock.patch.object(
                    held.database, "check_memberships", side_effect=late
                ):
                    held.check_memberships()
                held.close_named()
                held.check_events()

    def test_publish_marker_requires_external_witness_and_preserves_old_files(self):
        from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
            persistence_owner_publication_witness as witness,
        )

        root, pair = self.r.RUNTIME_ROOT, self.case.old.path
        root.mkdir(mode=0o700)
        self.r.backup.write_private(root / "runtime.json", witness.profile.RUNTIME)
        pair.mkdir(mode=0o700)
        self.r.backup.write_private(
            pair / "intent.json", self.r.observe.decode(self.case.h0)
        )
        with ExitStack() as resources:
            with self.module.attempt.inspect_attempt_v2(**self.case.arguments()):
                publication = resources.enter_context(
                    witness.observe_control_publication_v2(
                        **self.case.arguments(),
                        action="publish-marker",
                        event_profile=witness.EVENT_PROFILE
                    )
                )
                resources.enter_context(self.held("publish-marker"))
            publication.publish()

    def test_unrelated_valid_shared_pair_churn_is_allowed(self):
        with self.held():
            path = self.r.legacy.RUNTIME_ROOT / ("f" * 64)
            path.mkdir(mode=0o700)
            path.rmdir()

    def test_ordinary_old_root_extra_member_refuses(self):
        with self.assertRaises(ValueError):
            with self.held():
                (self.case.old.base.path() / "unexpected").touch(mode=0o600)

    def test_foreign_selection_and_action_refuse_before_io(self):
        with mock.patch.object(
            self.module.attempt, "_Reader", side_effect=AssertionError("IO")
        ):
            with self.assertRaises(ValueError):
                with self.module.hold_owner_resources(
                    selection=object(), entry=self.entry, action="inspect"
                ):
                    pass
            with self.assertRaises(ValueError):
                with self.held("other"):
                    pass

    def test_release_failure_suppresses_return_and_cleanup_is_not_retried(self):
        with self.assertRaises(OSError):
            with self.held() as held:
                original = held.database.release

                def failed():
                    original()
                    raise OSError("release failed")

                with mock.patch.object(held.database, "release", side_effect=failed):
                    held.release()
        self.assertTrue(held.closed)
        held.release()
