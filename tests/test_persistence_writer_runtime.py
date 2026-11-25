"""Active requests keep native leases and close current service evidence."""

from contextlib import contextmanager
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_writer_runtime as active,
)
import test_persistence_writer_peer as peer_fixtures


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class WriterRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.base = peer_fixtures.WriterPeerTests("runTest")
        self.base.setUp()
        self.request, self.profile = self.base.request, self.base.profile
        self.frame = {
            "guest": copy.deepcopy(self.base.value["guest"]),
            "kernel": copy.deepcopy(self.base.kernel),
            "peer": {"pid": self.base.peer.pid, "birth": self.base.peer.birth},
        }
        self.count = 0
        self.mutation = None
        self.uptimes = None
        self.leases = set()
        self.events = []

        @contextmanager
        def pair(unused):
            self.assertFalse(self.leases)
            self.leases.add("pair")
            try:
                yield
            finally:
                self.leases.remove("pair")

        @contextmanager
        def native(vmid):
            self.assertIn("pair", self.leases)
            self.leases.add(vmid)
            try:
                yield
            finally:
                self.leases.remove(vmid)

        @contextmanager
        def admitted(request, profile, guard, binding, host):
            self.assertEqual(len(self.leases), 3)
            self.count += 1
            frame = copy.deepcopy(self.frame)
            frame["guest"]["runtime"]["uptime"] += self.count
            if self.uptimes is not None:
                frame["guest"]["runtime"]["uptime"] = self.uptimes.pop(0)
            if self.mutation:
                frame["peer"]["birth"] += 1
            endpoint = active.Endpoint(
                11,
                12,
                self.base.peer,
                {
                    "instance_id": self.request["policy"]["application"]["instance_id"],
                    "config_sha256": self.request["policy"]["application"][
                        "config_sha256"
                    ],
                    "application_uid": 1100,
                },
            )
            yield frame, endpoint

        self.read_result = {
            "instance_id": self.request["policy"]["application"]["instance_id"],
            "entries": [{"sequence": 1, "operation_id": "c" * 32, "value": "original"}],
            "records_sha256": "d" * 64,
            "record_count": 1,
        }

        def read(*unused):
            self.events.append("authenticated-read")
            self.assertEqual(len(self.leases), 3)
            if self.mutation == "after-read":
                self.frame["peer"]["pid"] += 1
            return copy.deepcopy(self.read_result)

        for target, name, callback in (
            (
                active.runtime.observe,
                "host_facts",
                lambda request: copy.deepcopy(self.base.value["host"]),
            ),
            (
                active.runtime.observe,
                "load_guard",
                lambda ref: active.runtime.load_profile(self.request, self.profile)[0],
            ),
            (active.runtime.pair_lock, "locked_pair", pair),
            (active.runtime.config_lock, "read_guest", native),
            (active, "_admitted", admitted),
            (active.ledger, "read", read),
            (
                active.runtime.observe,
                "locked_config",
                lambda *a, **kw: self.fail("no application EX"),
            ),
            (
                active.runtime.observe,
                "read_database",
                lambda *a, **kw: self.fail("no host SQLite"),
            ),
            (
                active.runtime,
                "retained_facts",
                lambda *a, **kw: self.fail("no database header reads"),
            ),
        ):
            patch = mock.patch.object(target, name, side_effect=callback)
            patch.start()
            self.addCleanup(patch.stop)

    def test_read_only_collection_keeps_native_leases_and_returns_no_rows(self):
        result = active.collect(self.request, self.profile)
        self.assertEqual(result["application"]["record_count"], 1)
        self.assertEqual(result["application"]["records_sha256"], "d" * 64)
        self.assertNotIn("entries", result["application"])
        self.assertTrue(result["application_read_verified"])
        self.assertTrue(all(result[name] is False for name in active.FLAGS))
        self.assertFalse(self.leases)
        self.assertGreaterEqual(self.count, 4)

    def test_changed_process_after_request_refuses_and_releases_leases(self):
        self.mutation = "after-read"
        with self.assertRaises(active.state.PersistenceError):
            active.collect(self.request, self.profile)
        self.assertEqual(self.events, ["authenticated-read"])
        self.assertFalse(self.leases)

    def test_private_client_append_is_explicit_and_still_closes_identity(self):
        self.mutation = None
        guard, _, binding = active.runtime.load_profile(self.request, self.profile)
        self.leases = {"pair", 101, 102}
        with mock.patch.object(
            active.ledger,
            "append",
            return_value={"outcome": "committed", "sequence": 2},
        ) as append:
            with active._session_leased(
                self.request, self.profile, guard, binding, self.base.value["host"]
            ) as client:
                result = client.append("e" * 32, "one qualified test record")
                self.assertEqual(result["sequence"], 2)
            self.assertEqual(append.call_count, 1)
        self.assertEqual(self.leases, {"pair", 101, 102})
        self.leases.clear()

    def test_client_cannot_be_used_after_its_context_closes(self):
        guard, _, binding = active.runtime.load_profile(self.request, self.profile)
        self.leases = {"pair", 101, 102}
        with active._session_leased(
            self.request, self.profile, guard, binding, self.base.value["host"]
        ) as client:
            pass
        count = self.count
        with self.assertRaises(active.state.PersistenceError):
            client.read()
        self.assertEqual(self.count, count)
        self.assertEqual(self.events, [])
        self.leases.clear()

    def test_decreasing_uptime_refuses_even_above_initial_uptime(self):
        self.uptimes = [10, 20, 30, 25]
        with self.assertRaises(active.state.PersistenceError):
            active.collect(self.request, self.profile)
        self.assertFalse(self.leases)


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class WriterBaseFrameTests(unittest.TestCase):
    def setUp(self):
        self.base = peer_fixtures.WriterPeerTests("runTest")
        self.base.setUp()
        self.request, self.profile = self.base.request, self.base.profile
        self.guard, _, self.binding = active.runtime.load_profile(
            self.request, self.profile
        )
        self.value = self.base.value
        self.guest = copy.deepcopy(self.value["guest"])
        self.image = copy.deepcopy(self.base.image)
        for target, name, callback in (
            (
                active.runtime.observe,
                "host_facts",
                lambda request: copy.deepcopy(self.value["host"]),
            ),
            (
                active.runtime.observe,
                "guest_facts",
                lambda policy: copy.deepcopy(self.guest),
            ),
            (
                active.runtime.kernel,
                "collect",
                lambda binding: copy.deepcopy(self.base.kernel),
            ),
            (
                active.runtime,
                "reference_facts",
                lambda request: copy.deepcopy(self.value["reference"]),
            ),
            (
                self.guard,
                "collect_ownership",
                lambda policy: copy.deepcopy(self.value["retained"]["ownership"]),
            ),
            (
                active,
                "_datasets",
                lambda policy, guard: copy.deepcopy(self.value["retained"]["datasets"]),
            ),
            (
                active.runtime,
                "collect_bindings",
                lambda *args: copy.deepcopy(self.value["bindings"]),
            ),
            (active.runtime.observe, "native", lambda argv: b"321\n"),
            (active.runtime, "guest_image", lambda *a, **kw: copy.deepcopy(self.image)),
            (
                active.runtime.observe,
                "read_database",
                lambda *a, **kw: self.fail("host SQL forbidden"),
            ),
            (
                active.runtime.observe,
                "locked_config",
                lambda *a, **kw: self.fail("app EX forbidden"),
            ),
            (
                active.runtime,
                "retained_facts",
                lambda *a, **kw: self.fail("header read forbidden"),
            ),
        ):
            patch = mock.patch.object(target, name, side_effect=callback)
            patch.start()
            self.addCleanup(patch.stop)

    def frame(self):
        return active._base_frame(
            self.request, self.profile, self.guard, self.binding, self.value["host"]
        )

    def test_full_native_provider_frame_has_no_host_database_path(self):
        result = self.frame()
        self.assertEqual(result["image"]["unit"]["MainPID"], "321")
        self.assertNotIn("application", result)
        self.assertNotIn("database", result)

    def test_wrong_current_guest_refuses_before_guest_execution(self):
        self.guest["status"] = "stopped"
        with mock.patch.object(
            active.runtime.observe, "native", side_effect=AssertionError("too early")
        ):
            with self.assertRaises(active.state.PersistenceError):
                self.frame()

    def test_wrong_active_image_or_retired_owner_refuses(self):
        self.image["unit"]["MainPID"] = "322"
        with self.assertRaises(active.state.PersistenceError):
            self.frame()
        self.image = copy.deepcopy(self.base.image)
        with mock.patch.object(self.guard, "collect_ownership", return_value={}):
            with self.assertRaises((active.state.PersistenceError, KeyError)):
                self.frame()


class WriterGuestFileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for relative in ("usr", "usr/bin", "opt", "opt/reference-ledger"):
            (self.root / relative).mkdir(mode=0o755)
        self.owner = (os.getuid(), os.getgid())
        self.stack = active.ExitStack()
        self.addCleanup(self.stack.close)
        self.descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.stack.callback(os.close, self.descriptor)
        self.python = self.root / "usr/bin/python3.12"
        self.python.write_bytes(b"synthetic executable inode")
        self.python.chmod(0o755)
        (self.root / "usr/bin/python3").symlink_to("python3.12")
        self.program = self.root / "opt/reference-ledger/ledger.py"
        self.program.write_bytes(b"synthetic known program\n")
        self.program.chmod(0o644)

    def test_actual_program_and_python_inode_observation(self):
        identity = active._python(self.stack, self.descriptor, self.owner)
        self.assertEqual(
            identity, (self.python.stat().st_dev, self.python.stat().st_ino)
        )
        active._program(
            self.stack,
            self.descriptor,
            self.owner,
            active.state.sha256(self.program.read_bytes()),
        )

    def test_python_link_cannot_escape_guest_root(self):
        link = self.root / "usr/bin/python3"
        for target in ("/usr/bin/python3", "../../../outside", "python3.12/other"):
            link.unlink()
            link.symlink_to(target)
            with self.subTest(target=target), self.assertRaises(
                active.state.PersistenceError
            ):
                active._python(self.stack, self.descriptor, self.owner)

    def test_program_hash_and_permissions_are_required(self):
        with self.assertRaises(active.state.PersistenceError):
            active._program(self.stack, self.descriptor, self.owner, "0" * 64)
        self.program.chmod(0o666)
        with self.assertRaises(active.state.PersistenceError):
            active._program(
                self.stack,
                self.descriptor,
                self.owner,
                active.state.sha256(self.program.read_bytes()),
            )


if __name__ == "__main__":
    unittest.main()
