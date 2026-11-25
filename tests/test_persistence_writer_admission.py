"""Close real directory/program/lock FDs with modeled native guest admission.

This is not a native namespace test. It drives actual admission/session control
flow using real private directories, program files, a socket and an EX owner.
"""

from contextlib import ExitStack
from dataclasses import replace
import copy
import fcntl
import os
from pathlib import Path
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_writer_runtime as active,
)


class WriterAdmissionTests(unittest.TestCase):
    def exercise(self, fault):
        with tempfile.TemporaryDirectory() as scratch, ExitStack() as mocks:
            base = Path(scratch)
            root = base / "root"
            root.mkdir(mode=0o755)
            for relative in (
                "usr",
                "usr/bin",
                "opt",
                "opt/reference-ledger",
                "etc",
                "etc/reference-ledger",
                "var",
                "var/lib",
                "var/lib/reference-ledger",
                "run",
                "run/reference-ledger",
            ):
                private = relative in (
                    "etc/reference-ledger",
                    "var/lib/reference-ledger",
                    "run/reference-ledger",
                )
                (root / relative).mkdir(mode=0o700 if private else 0o755)
            program = root / "opt/reference-ledger/ledger.py"
            program.write_bytes(b"synthetic program\n")
            program.chmod(0o644)
            checksum = active.state.sha256(program.read_bytes())
            python = root / "usr/bin/python3.12"
            python.write_bytes(b"synthetic python inode")
            python.chmod(0o755)
            (root / "usr/bin/python3").symlink_to("python3.12")
            config = root / "etc/reference-ledger/application.json"
            config.write_bytes(b"synthetic configuration")
            config.chmod(0o600)
            descriptor = os.open(config, os.O_RDONLY)
            mocks.callback(os.close, descriptor)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            run = os.open(root / "run/reference-ledger", os.O_RDONLY | os.O_DIRECTORY)
            mocks.callback(os.close, run)
            listener = mocks.enter_context(socket.socket(socket.AF_UNIX))
            listener.bind(f"/proc/self/fd/{run}/api.sock")
            (root / "run/reference-ledger/api.sock").chmod(0o600)
            actual = active.unix_peer.process_identity(os.getpid())
            root_identity = (root.stat().st_dev, root.stat().st_ino)
            peer = replace(actual, root=root_identity)
            init = replace(actual, pid=2, nspid=(2, 1), root=root_identity)
            proc = base / "proc"
            (proc / "2").mkdir(parents=True)
            (proc / "2/root").symlink_to(root)
            request = {
                "policy": {
                    "mapping": {
                        "offset": os.getuid(),
                        "uid": 0,
                        "gid": os.getgid() - os.getuid(),
                    },
                    "datasets": {
                        "config": {"mountpoint": str(root / "etc/reference-ledger")},
                        "data": {"mountpoint": str(root / "var/lib/reference-ledger")},
                    },
                    "application": {
                        "instance_id": "a" * 32,
                        "config_sha256": active.state.sha256(config.read_bytes()),
                    },
                }
            }
            # This fixed local model uses equal user/group IDs. Native UID/GID
            # mapping is tested independently by the pure process validator.
            self.assertEqual(os.getuid(), os.getgid())
            frame = {
                "kernel": {"init": {"pid": 2}},
                "image": {"unit": {"MainPID": "123"}},
                "guest": {"runtime": {"uptime": 1}},
            }
            changed = [False]
            calls = [0]
            original = active._program

            def program_read(*args):
                original(*args)
                calls[0] += 1
                if fault == "peer-after-final-program" and calls[0] == 2:
                    changed[0] = True

            def identity(pid):
                return (
                    init
                    if pid == 2
                    else replace(peer, birth=peer.birth + int(changed[0]))
                )

            def read(parent, *unused):
                if fault == "run-replaced":
                    path = root / "run/reference-ledger"
                    path.rename(root / "run/old-reference-ledger")
                    path.mkdir(mode=0o700)
                return {
                    "instance_id": "a" * 32,
                    "records_sha256": "d" * 64,
                    "record_count": 1,
                }

            for obj, name, value in (
                (active, "PROC_ROOT", proc),
                (active, "_base_frame", lambda *a: copy.deepcopy(frame)),
                (active, "_find_peer", lambda *a: peer),
                (
                    active.runtime,
                    "load_profile",
                    lambda *a: (None, SimpleNamespace(PROGRAM_SHA256=checksum), None),
                ),
                (active.process, "validate", lambda *a: None),
                (active.unix_peer, "process_identity", identity),
                (active, "_program", program_read),
                (active.ledger, "read", read),
            ):
                mocks.enter_context(patch.object(obj, name, value))
            if fault == "peer-after-final-program":
                with active._admitted(request, {}, None, None, {}):
                    pass
            else:
                with active._session_leased(request, {}, None, None, {}) as client:
                    client.read()

    def test_real_fd_model_accepts_unchanged_state(self):
        self.exercise("none")

    def test_named_run_directory_replacement_refuses_cached_endpoint(self):
        with self.assertRaises((active.state.PersistenceError, OSError)):
            self.exercise("run-replaced")

    def test_peer_change_during_final_slow_program_read_refuses(self):
        with self.assertRaises(active.state.PersistenceError):
            self.exercise("peer-after-final-program")


if __name__ == "__main__":
    unittest.main()
