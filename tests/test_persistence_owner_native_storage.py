"""Native journal bootstrap over real disposable local files and flocks.

No installed-producer, managed-filesystem or native-action qualification.
"""

from contextlib import contextmanager
import importlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def fixture_scope(root):
    module = importlib.import_module(
        "ansible_collections.cmdmesh.proxmox.plugins.module_utils."
        "persistence_owner_native_storage"
    )
    root = Path(root)
    with mock.patch.object(
        module.journal, "RUNTIME_ROOT", root / "native"
    ), mock.patch.object(module.journal, "ROOT_UID", os.geteuid()), mock.patch.object(
        module.attempt.r, "RUNTIME_ROOT", root / "metadata"
    ), mock.patch.object(
        module.attempt.r.legacy, "RUNTIME_ROOT", root / "legacy"
    ), mock.patch.object(
        module.attempt.r.legacy, "ROOT_UID", os.geteuid()
    ), mock.patch.object(
        module.attempt, "_WALK_ROOT", root
    ):
        yield module


class NativeStorageTests(unittest.TestCase):
    def setUp(self):
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(
            dir=ROOT / ".generated", prefix="native-storage-"
        )
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.s = self.enterContext(fixture_scope(self.root))
        self.j = self.s.journal
        self.binding = self.j.Binding(
            "a" * 64,
            "b" * 64,
            self.j.api.GuestBinding("pve-example", 102, "1" * 64, "2" * 64, "3" * 64),
        )
        self.path = self.root / self.s.LOCK_NAME
        for name in ("post_guest_action", "post_owner_guest_action", "get"):
            self.enterContext(
                mock.patch.object(
                    self.j.api, name, side_effect=AssertionError("native IO")
                )
            )

    def files(self):
        return {
            str(p.relative_to(self.root)): p.read_bytes()
            for p in self.root.rglob("*")
            if p.is_file()
        }

    def test_mutex_is_explicit_distinct_and_idempotent_without_journal_creation(self):
        with self.assertRaises(ValueError):
            with self.s._locked_bootstrap():
                self.fail("missing mutex")
        self.assertEqual(self.files(), {})
        with self.s._locked_bootstrap(initialize=True):
            pass
        original = self.path.read_bytes(), self.path.stat()
        with self.s._locked_bootstrap(initialize=True):
            pass
        self.assertEqual(self.path.read_bytes(), original[0])
        self.assertEqual(self.path.stat(), original[1])
        self.assertEqual(set(self.files()), {self.s.LOCK_NAME})
        self.assertFalse(self.j.RUNTIME_ROOT.exists())

    def test_nested_and_other_processes_cannot_enter_same_domain(self):
        with self.s._locked_bootstrap(initialize=True):
            with self.assertRaisesRegex(ValueError, "bootstrap-busy"):
                with self.s._locked_bootstrap():
                    self.fail("independent descriptor entered")
            child = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    """
import sys
from test_persistence_owner_native_storage import fixture_scope
with fixture_scope(sys.argv[1]) as module:
    try:
        with module._locked_bootstrap():
            print("acquired")
    except ValueError as error:
        print("busy" if "bootstrap-busy" in str(error) else str(error))
""",
                    str(self.root),
                ],
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "PYTHONPATH": os.pathsep.join(sys.path),
                },
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            self.assertEqual(child.stdout.strip(), "busy")
        with self.s._locked_bootstrap():
            pass

    def test_partial_foreign_mutex_and_links_are_preserved(self):
        for raw in (b"", b'{"partial":', b"foreign"):
            self.path.write_bytes(raw)
            self.path.chmod(0o600)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                with self.s._locked_bootstrap(initialize=True):
                    self.fail("foreign mutex")
            self.assertEqual(self.path.read_bytes(), raw)
        self.path.unlink()
        outside = self.root / "outside"
        outside.write_bytes(b"preserved")
        outside.chmod(0o600)
        for kind in ("symlink", "hardlink"):
            if kind == "symlink":
                self.path.symlink_to(outside)
            else:
                os.link(outside, self.path)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                with self.s._locked_bootstrap(initialize=True):
                    self.fail("linked mutex")
            self.assertEqual(outside.read_bytes(), b"preserved")
            self.path.unlink()

    def test_mutex_mutation_and_configuration_drift_prevent_return(self):
        with self.s._locked_bootstrap(initialize=True):
            pass
        with self.assertRaises(ValueError):
            with self.s._locked_bootstrap():
                self.path.write_bytes(self.path.read_bytes())
        with self.assertRaises(ValueError):
            with self.s._locked_bootstrap():
                with mock.patch.object(self.j, "ACTION_PROFILE", "wrong"):
                    self.s._configuration()

    def test_parent_and_exact_mode_checks_precede_creation(self):
        for mode in (1, "true", None):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                with self.s._locked_bootstrap(initialize=mode):
                    self.fail("bad mode")
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            with self.s._locked_bootstrap(initialize=True):
                self.fail("public parent")
        self.assertFalse(self.path.exists())

    def test_readonly_initialization_inspection_does_not_create_files(self):
        view = self.s._inspect_initialization(self.binding)
        self.assertTrue(view.would_change)
        self.s._close_initialization(view)
        self.assertEqual(self.files(), {})

    def test_initialize_only_v4_genesis_and_existing_unused_state_is_idempotent(self):
        old = self.root / "legacy"
        old.mkdir(mode=0o700)
        (old / "uncertain.json").write_bytes(b"preserve historical uncertainty")
        result = self.s._initialize_journal(self.binding)
        self.assertTrue(result["changed"])
        self.assertEqual(
            result["head_sha256"], self.j._digest(self.j._genesis(self.binding))
        )
        before = self.files()
        result = self.s._initialize_journal(self.binding)
        self.assertFalse(result["changed"])
        self.assertEqual(self.files(), before)
        view = self.s._inspect_initialization(self.binding)
        self.assertFalse(view.would_change)
        self.s._close_initialization(view)
        self.assertEqual(
            (old / "uncertain.json").read_bytes(), b"preserve historical uncertainty"
        )

    def test_partial_global_state_is_refused_before_mutex_creation(self):
        self.j.RUNTIME_ROOT.mkdir(mode=0o700)
        path = self.j.RUNTIME_ROOT / "runtime.json"
        path.write_bytes(b'{"partial":')
        path.chmod(0o600)
        before = self.files()
        with self.assertRaises(ValueError):
            self.s._initialize_journal(self.binding)
        self.assertEqual(self.files(), before)
        self.assertFalse(self.path.exists())

    def test_partial_pair_and_unknown_members_are_never_repaired(self):
        self.s._initialize_journal(self.binding)
        target = self.j.RUNTIME_ROOT / self.binding.pair_key
        (target / "HEAD.json").unlink()
        before = self.files()
        with self.assertRaises((ValueError, OSError)):
            self.s._initialize_journal(self.binding)
        self.assertEqual(self.files(), before)

    def test_absence_and_same_byte_metadata_changes_refuse_closure(self):
        view = self.s._inspect_initialization(self.binding)
        self.j.RUNTIME_ROOT.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.s._close_initialization(view)
        self.j.RUNTIME_ROOT.rmdir()
        self.s._initialize_journal(self.binding)
        view = self.s._inspect_initialization(self.binding)
        path = self.j.RUNTIME_ROOT / self.binding.pair_key / "HEAD.json"
        path.write_bytes(path.read_bytes())
        with self.assertRaises(ValueError):
            self.s._close_initialization(view)

    def test_write_failure_retains_partial_state_and_no_retry_repairs_it(self):
        original = self.j._write

        def fail(path, value):
            if path.name == "genesis.json":
                path.write_bytes(b'{"incomplete":')
                path.chmod(0o600)
                raise OSError("modeled incomplete journal write")
            return original(path, value)

        with mock.patch.object(self.j, "_write", side_effect=fail):
            with self.assertRaisesRegex(OSError, "incomplete journal write"):
                self.s._initialize_journal(self.binding)
        before = self.files()
        with self.assertRaises((ValueError, OSError)):
            self.s._initialize_journal(self.binding)
        self.assertEqual(self.files(), before)

    def test_named_write_never_overwrites_and_failed_head_replace_is_retained(self):
        result = self.s._initialize_journal(self.binding)
        target = self.j.RUNTIME_ROOT / self.binding.pair_key
        before = (target / "HEAD.json").read_bytes()
        with self.assertRaises(FileExistsError):
            self.j._write(target / "HEAD.json", {"foreign": True})
        self.assertEqual((target / "HEAD.json").read_bytes(), before)
        with mock.patch.object(
            self.j.os, "replace", side_effect=OSError("modeled replace failure")
        ):
            with self.assertRaisesRegex(OSError, "modeled replace failure"):
                self.j._publish(
                    self.binding, result["head_sha256"], self.j._genesis(self.binding)
                )
        self.assertEqual((target / "HEAD.json").read_bytes(), before)
        self.assertEqual((target / "HEAD.next").read_bytes(), before)
        failed = self.files()
        with self.assertRaises(ValueError):
            self.s._initialize_journal(self.binding)
        self.assertEqual(self.files(), failed)

    def test_protocol_probe_is_explicit_and_removes_only_owned_scratch(self):
        for kwargs in (
            {},
            {"allow_mutation": 1},
            {"allow_mutation": True, "check_mode": True},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.s.probe_protocol(**kwargs)
        self.assertEqual(self.files(), {})
        result = self.s.probe_protocol(allow_mutation=True)
        value = self.j.observe.decode(result.raw)
        self.assertEqual(result.sha256, self.j.state.sha256(result.raw))
        self.assertEqual(value["protocol"], self.s.PROTOCOL)
        self.assertEqual(
            value["configuration_sha256"], self.j.state.sha256(self.s._configuration())
        )
        self.assertEqual(value["exclusive_errno"], 17)
        self.assertNotEqual(value["initial_file"][1], value["replaced_file"][1])
        self.assertTrue(value["scratch_removed"])
        self.assertFalse(value["filesystem_qualified"])
        self.assertFalse(value["native_action_dispatched"])
        self.assertEqual(self.files(), {})
        self.assertFalse(self.j.RUNTIME_ROOT.exists())

    def test_probe_replace_failure_preserves_the_two_owned_records(self):
        with mock.patch.object(
            self.s.os, "replace", side_effect=OSError("probe replace failed")
        ):
            with self.assertRaisesRegex(OSError, "probe replace failed"):
                self.s.probe_protocol(allow_mutation=True)
        roots = list(self.root.glob(self.s.PROBE_PREFIX + "*"))
        self.assertEqual(len(roots), 1)
        self.assertEqual(
            {p.name for p in roots[0].iterdir()}, {"HEAD.json", "HEAD.next"}
        )

    def test_probe_preserves_unknown_children_and_never_cleans_them(self):
        original = self.s.os.replace

        def extra(source, target):
            original(source, target)
            (target.parent / "unknown").write_bytes(b"preserved")

        with mock.patch.object(self.s.os, "replace", side_effect=extra):
            with self.assertRaises(ValueError):
                self.s.probe_protocol(allow_mutation=True)
        roots = list(self.root.glob(self.s.PROBE_PREFIX + "*"))
        self.assertEqual(len(roots), 1)
        self.assertEqual((roots[0] / "unknown").read_bytes(), b"preserved")
        self.assertTrue((roots[0] / "HEAD.json").is_file())

    def test_probe_fsync_failure_after_replace_never_returns_a_candidate(self):
        original_replace = self.s.os.replace
        original_sync = self.j.backup.sync_directory
        replaced = False

        def replace(source, target):
            nonlocal replaced
            original_replace(source, target)
            replaced = True

        def sync(path):
            if replaced:
                raise OSError("probe directory fsync failed")
            original_sync(path)

        with mock.patch.object(
            self.s.os, "replace", side_effect=replace
        ), mock.patch.object(self.j.backup, "sync_directory", side_effect=sync):
            with self.assertRaisesRegex(OSError, "probe directory fsync failed"):
                self.s.probe_protocol(allow_mutation=True)
        roots = list(self.root.glob(self.s.PROBE_PREFIX + "*"))
        self.assertEqual(len(roots), 1)
        self.assertEqual({p.name for p in roots[0].iterdir()}, {"HEAD.json"})

    def test_probe_never_adopts_a_replacement_at_first_parent_sync(self):
        original = self.j.backup.sync_directory
        replacement = None
        moved = None

        def swap(path):
            nonlocal replacement, moved
            if path == self.root and replacement is None:
                replacement = next(self.root.glob(self.s.PROBE_PREFIX + "*"))
                moved = replacement.with_name(replacement.name + ".moved")
                replacement.rename(moved)
                replacement.mkdir(mode=0o700)
            original(path)

        with mock.patch.object(self.j.backup, "sync_directory", side_effect=swap):
            with self.assertRaises(ValueError):
                self.s.probe_protocol(allow_mutation=True)
        self.assertTrue(moved.is_dir())
        self.assertTrue(replacement.is_dir())
        self.assertEqual(list(moved.iterdir()), [])
        self.assertEqual(list(replacement.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
