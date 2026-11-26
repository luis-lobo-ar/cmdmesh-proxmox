"""Real actor-holder FD/event checks with synthetic raw/identity actor rows.

Only fixed paths and root ownership are projected into disposable local files.
Admission authenticity/native/current providers are outside this holder test.
The holder, file reader, hashes, policy, inotify and cleanup remain real.
"""

import importlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


class ActorControlsTests(unittest.TestCase):
    def setUp(self):
        self.e = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_metadata_executor"
        )
        self.r = self.e.r
        scratch = Path(__file__).resolve().parents[1] / ".generated"
        scratch.mkdir(mode=0o700, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(
            prefix="owner-actor-controls-", dir=scratch
        )
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.enterContext(mock.patch.object(self.e.attempt, "_WALK_ROOT", self.root))
        self.enterContext(mock.patch.object(self.r.legacy, "ROOT_UID", os.geteuid()))
        self.assertEqual(os.geteuid(), os.getegid(), "fixture projects one root ID")
        self.files = []
        self.raws = ["", "snowman \u2603\n", "trailing\n\n", "plain"]
        self.actors = dict(
            runtime_directories={},
            history_directories={},
            history_files={},
            runtime_files={},
        )
        for index, (role, count) in enumerate(
            [
                ("publication", 10),
                ("reconciliation", 17),
                ("retained", 14),
                ("writer", 13),
                ("blank_boot", 7),
                ("recipient", 5),
                ("attach", 12),
            ]
        ):
            runtime = self.root / (role + "-runtime")
            runtime.mkdir(mode=0o700)
            self.actors["runtime_directories"][str(runtime)] = self.identity(runtime)[
                :5
            ]
            directory = runtime / ("a" * 64)
            directory.mkdir(mode=0o700)
            items = {}
            for number in range(count):
                path = directory / ("record-%02d.json" % number)
                raw = self.raws[(index + number) % len(self.raws)]
                items[path.name] = self.file(path, raw)
            group = dict(
                path=str(directory), identity=self.identity(directory), files=items
            )
            if index < 3:
                self.actors["history_directories"][str(directory)] = group
            else:
                self.actors[role] = group
        for role, count in (("history_files", 16), ("runtime_files", 4)):
            for number in range(count):
                path = self.root / (role + "-%02d.json" % number)
                item = self.file(path, self.raws[number % len(self.raws)])
                item["path"] = str(path)
                self.actors[role][str(path)] = item
        vendor_paths, sources = {}, {}
        for role in self.e.VENDOR_PATHS:
            path = self.root / (role + ".pm")
            raw = "synthetic vendor " + role + "\n"
            self.file(path, raw, mode=0o644)
            vendor_paths[role] = str(path)
            sources[role] = self.r.state.sha256(raw.encode())
        self.enterContext(mock.patch.object(self.e, "VENDOR_PATHS", vendor_paths))
        self.vendor = Path(next(iter(vendor_paths.values())))
        self.authority = dict(source_profile=dict(sources=sources))
        self.bind()

    def identity(self, path):
        return list(self.r.observe.stable(path.lstat()))

    def file(self, path, raw, *, mode=0o600):
        path.write_bytes(raw.encode("utf-8"))
        path.chmod(mode)
        self.files.append(path)
        return dict(raw=raw, identity=self.identity(path))

    def bind(self):
        capture = self.r.state.canonical(dict(actors=self.actors))
        authority = self.r.state.canonical(self.authority)
        self.admission = SimpleNamespace(
            selection=SimpleNamespace(
                _private_binding=SimpleNamespace(pair_key="a" * 64)
            ),
            historical_capture_raw=capture,
            historical_capture_sha256=self.r.state.sha256(capture),
            historical_authority_raw=authority,
            historical_authority_sha256=self.r.state.sha256(authority),
        )

    def fd_count(self):
        return len(os.listdir("/proc/self/fd"))

    def test_exact_raw_actor_schema_and_vendor_files_close_without_leaks(self):
        before = self.fd_count()
        expected = {str(path): path.read_bytes() for path in self.files}
        with self.e._hold_actor_controls(self.admission) as held:
            self.assertEqual(set(held.raws), set(expected))
            for path, raw in expected.items():
                self.assertEqual(held.raws[path], (raw, self.r.state.sha256(raw)))
            self.assertTrue(
                all(
                    "sha256" not in item
                    for group in self.actors["history_directories"].values()
                    for item in group["files"].values()
                )
            )
            self.assertTrue(
                all(
                    "sha256" not in item
                    for name in ("history_files", "runtime_files")
                    for item in self.actors[name].values()
                )
            )
        self.assertTrue(held.closed)
        self.assertEqual(self.fd_count(), before)
        self.assertEqual(
            {str(path): path.read_bytes() for path in self.files}, expected
        )

    def test_same_byte_actor_write_is_refused_and_descriptors_close(self):
        before = self.fd_count()
        path = self.files[0]
        with self.assertRaises(self.r.state.PersistenceError):
            with self.e._hold_actor_controls(self.admission):
                path.write_bytes(path.read_bytes())
        self.assertEqual(self.fd_count(), before)

    def test_same_byte_vendor_write_is_refused(self):
        before = self.fd_count()
        with self.assertRaises(self.r.state.PersistenceError):
            with self.e._hold_actor_controls(self.admission):
                self.vendor.write_bytes(self.vendor.read_bytes())
        self.assertEqual(self.fd_count(), before)

    def test_selected_raw_does_not_match_actual_bytes(self):
        next(iter(self.actors["runtime_files"].values()))["raw"] = "different"
        self.bind()
        before = self.fd_count()
        with self.assertRaises(self.r.state.PersistenceError):
            with self.e._hold_actor_controls(self.admission):
                self.fail("holder accepted different bytes")
        self.assertEqual(self.fd_count(), before)

    def test_unsafe_vendor_mode_refuses_without_leaking(self):
        self.vendor.chmod(0o666)
        before = self.fd_count()
        with self.assertRaises(self.r.state.PersistenceError):
            with self.e._hold_actor_controls(self.admission):
                self.fail("unsafe vendor accepted")
        self.assertEqual(self.fd_count(), before)

    def test_primary_error_survives_secondary_release_error(self):
        original = self.e.resources._Seal.release
        primary = RuntimeError("synthetic primary")
        before = self.fd_count()

        def release(reader):
            original(reader)
            raise OSError("synthetic secondary")

        with mock.patch.object(self.e.resources._Seal, "release", release):
            with self.assertRaises(RuntimeError) as caught:
                with self.e._hold_actor_controls(self.admission):
                    raise primary
        self.assertIs(caught.exception, primary)
        self.assertEqual(self.fd_count(), before)
