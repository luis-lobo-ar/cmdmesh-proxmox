"""Actual disposable FS samples, not a genuine managed qualification."""

import importlib.util
import builtins
import errno
from contextlib import contextmanager
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

import test_persistence_owner_continuation_v2 as fixture


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class ProbeToolTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / "tools/qualify-owner-filesystem.py"
        spec = importlib.util.spec_from_file_location(
            "cmdmesh_filesystem_probe_tool", path
        )
        self.tool = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.tool
        self.addCleanup(sys.modules.pop, spec.name, None)
        spec.loader.exec_module(self.tool)
        self.case = fixture.ContinuationV2Tests("runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.model = self.case.case
        self.r = self.case.r
        self.selection = self.tool.semantics.select(**self.model.arguments())

    def test_real_samples_validate_and_owned_child_is_removed_without_handoff_writes(
        self,
    ):
        before = len(os.listdir("/proc/self/fd"))
        result = self.tool._measure(self.selection)
        body = self.r.observe.decode(result.raw)
        probe = body["probe"]
        common = self.r.RUNTIME_ROOT.parent
        self.assertFalse(Path(probe["parent_path"]).exists())
        self.assertTrue(body["owned_probe_removed"])
        self.assertTrue(body["candidate_only"])
        self.assertFalse(body["producer_authenticated"])
        self.assertFalse(body["filesystem_qualified"])
        self.assertNotIn("closed_probe_provenance_sha256", probe)
        self.assertFalse(self.r.RUNTIME_ROOT.exists())
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)
        # This is a modeled external provenance reference ONLY for checking
        # the real sample's fixed pure grammar. It is never emitted by the tool.
        self.tool.admission_codec._probe(
            {**probe, "closed_probe_provenance_sha256": "7" * 64},
            body["filesystem_subject"]["mounts"],
            common,
        )

    def test_probe_base_symlink_is_refused_without_touching_target(self):
        common = self.r.RUNTIME_ROOT.parent
        base = common / self.tool.admission_codec.PROBE_DIRECTORY
        target = common / "foreign"
        target.mkdir(mode=0o700)
        base.symlink_to(target, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            self.tool._measure(self.selection)
        self.assertEqual(list(target.iterdir()), [])
        self.assertTrue(base.is_symlink())

    def test_post_link_failure_preserves_unknown_final_and_never_retries_it(self):
        original = self.tool.atomic.publish_observed
        published = []

        def lost(path, *args, **kwargs):
            receipt = original(path, *args, **kwargs)
            published.append(Path(path))
            raise OSError("modeled lost return after actual link")

        count = len(os.listdir("/proc/self/fd"))
        with mock.patch.object(
            self.tool.atomic, "publish_observed", side_effect=lost
        ), self.assertRaises(OSError):
            self.tool._measure(self.selection)
        self.assertEqual(len(published), 1)
        self.assertEqual(
            published[0].read_bytes(), self.tool.admission_codec.PROBE_PAYLOAD
        )
        self.assertFalse(self.r.RUNTIME_ROOT.exists())
        self.assertEqual(len(os.listdir("/proc/self/fd")), count)

    def test_false_or_check_permissions_refuse_before_native_leases(self):
        for changes in (
            {},
            {"allow_probe": 1},
            {"allow_probe": True, "check_mode": True},
        ):
            with mock.patch.object(
                self.tool.transition,
                "_leased",
                side_effect=AssertionError("native lease IO"),
            ):
                with self.subTest(options=changes), self.assertRaises(ValueError):
                    self.tool.probe_filesystem(
                        self.selection, phase="os_quiesced", **changes
                    )

    def test_early_sync_failure_preserves_replacement_directory(self):
        original = self.tool.os.fsync
        replacement = []

        def replace_then_fail(fd):
            base = (
                self.r.RUNTIME_ROOT.parent / self.tool.admission_codec.PROBE_DIRECTORY
            )
            if not replacement and base.exists():
                rows = list(base.iterdir())
                if len(rows) == 1 and rows[0].is_dir():
                    probe = rows[0]
                    probe.rename(base / "retained-original")
                    probe.mkdir(mode=0o700)
                    replacement.append((probe, self.tool._identity(probe)))
                    raise OSError(errno.EIO, "original base fsync failure")
            return original(fd)

        before = len(os.listdir("/proc/self/fd"))
        with mock.patch.object(
            self.tool.os, "fsync", side_effect=replace_then_fail
        ), self.assertRaisesRegex(OSError, "original base fsync failure"):
            self.tool._measure(self.selection)
        self.assertEqual(len(replacement), 1)
        path, identity = replacement[0]
        self.assertTrue(path.is_dir())
        self.assertEqual(self.tool._identity(path), identity)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_unbound_probe_directory_is_preserved_on_open_failure(self):
        original = self.tool.resources._Seal._directory
        preserved = []

        def fail_probe(reader, path, *args, **kwargs):
            if Path(path).name.startswith("probe-"):
                preserved.append((Path(path), self.tool._identity(Path(path))))
                raise OSError(errno.EIO, "original probe open failure")
            return original(reader, path, *args, **kwargs)

        before = len(os.listdir("/proc/self/fd"))
        with mock.patch.object(
            self.tool.resources._Seal, "_directory", fail_probe
        ), self.assertRaisesRegex(OSError, "original probe open failure"):
            self.tool._measure(self.selection)
        self.assertEqual(len(preserved), 1)
        path, identity = preserved[0]
        self.assertTrue(path.is_dir())
        self.assertEqual(self.tool._identity(path), identity)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_unplanned_events_in_the_collision_step_refuse(self):
        original = self.tool.atomic.publish_observed
        calls = 0

        def changed(path, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                try:
                    return original(path, *args, **kwargs)
                except FileExistsError:
                    extra = Path(path).parent / "unplanned"
                    extra.write_bytes(b"diagnostic fault")
                    extra.unlink()
                    raise
            return original(path, *args, **kwargs)

        with mock.patch.object(
            self.tool.atomic, "publish_observed", side_effect=changed
        ), self.assertRaises(ValueError):
            self.tool._measure(self.selection)

    def test_secondary_release_keeps_the_original_failure(self):
        original = self.tool.atomic.publish_observed
        release = self.tool.resources._Seal.release

        def lost(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("original lost link return")

        def secondary(reader):
            release(reader)
            raise OSError("secondary close failure")

        with mock.patch.object(
            self.tool.atomic, "publish_observed", side_effect=lost
        ), mock.patch.object(
            self.tool.resources._Seal, "release", secondary
        ), self.assertRaisesRegex(
            OSError, "original lost link return"
        ):
            self.tool._measure(self.selection)

    def test_optimized_program_refuses_before_sdk_or_input_loading(self):
        path = Path(self.tool.__file__)
        program = compile(path.read_bytes(), str(path), "exec")
        importing = builtins.__import__
        sdk = []

        def guard(name, *args, **kwargs):
            if name.startswith("ansible_collections"):
                sdk.append(name)
                raise AssertionError("optimized SDK import")
            return importing(name, *args, **kwargs)

        with mock.patch.object(
            sys, "flags", SimpleNamespace(optimize=1)
        ), mock.patch.object(
            builtins, "__import__", side_effect=guard
        ), self.assertRaisesRegex(
            ValueError, "ordinary Python required"
        ):
            exec(program, {"__name__": "__main__", "__file__": str(path)})
        self.assertEqual(sdk, [])

    def test_normal_wrapper_owns_real_locks_without_reading_database(self):
        # Native entry/reference mapping is the executor's disclosed model;
        # the real pair/native/app flocks and FS measurements remain in use.
        import test_persistence_owner_metadata_executor as metadata
        import sqlite3

        model = metadata.MetadataExecutorTests("runTest")
        model.setUp()
        self.addCleanup(model.doCleanups)
        sample = self.tool._sample
        resources = self.tool.resources.hold_owner_resources

        @contextmanager
        def holder(**arguments):
            with resources(**arguments) as held:
                # Match the real resource holder's fixed DB-role attribute.
                held.database = held.seals[1]
                held.check_memberships()
                held.close_named()
                held.check_events()
                held.enumerated = False
                yield held

        def leased(*args):
            model.model.case.assert_outer_leases()
            return sample(*args)

        with mock.patch.object(
            self.tool, "_sample", side_effect=leased
        ), mock.patch.object(
            self.tool.resources, "hold_owner_resources", side_effect=holder
        ), mock.patch.object(
            sqlite3, "connect", side_effect=AssertionError("probe SQL")
        ):
            result = self.tool.probe_filesystem(
                model.selection, phase="os_quiesced", allow_probe=True
            )
        self.assertFalse(self.r.observe.decode(result.raw)["application_database_read"])
