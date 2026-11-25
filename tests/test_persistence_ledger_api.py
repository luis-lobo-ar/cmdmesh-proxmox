"""Exercise original credentials against the actual reference application's API."""

import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_ledger_api as api,
    unix_peer,
)

FIXTURE = r"""
import importlib.util,json,os,pathlib,socketserver,sys
source,root=sys.argv[1:];root=pathlib.Path(root)
spec=importlib.util.spec_from_file_location('real_ledger',source)
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
identity={'schema_version':1,'instance_id':'a'*32,'uid':os.geteuid(),'token':'b'*64}
app.initialize(root/'data',root/'config',identity)
with app.Ledger(root/'data',root/'config') as ledger:
 result=ledger.request({'action':'append','token':identity['token'],'operation_id':'c'*32,'value':'original record'})
 assert result=={'outcome':'committed','sequence':1}
# The real native socket path is short. Use a relative bind in this fixture to
# avoid AF_UNIX's 108-byte path limit under a long project worktree path.
os.chdir(root/'run')
socketserver.UnixStreamServer.server_bind=lambda server: server.socket.bind('api.sock')
activate=socketserver.UnixStreamServer.server_activate
def active(server):
 activate(server);print('ready',flush=True)
socketserver.UnixStreamServer.server_activate=active
with app.Ledger(root/'data',root/'config') as ledger:
 app.serve(ledger,root/'run'/'api.sock')
"""


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide reference source"
)
class LedgerApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ("config", "data", "run"):
            (self.root / name).mkdir(mode=0o700)
        source = (
            Path(os.environ["CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"]).parent / "ledger.py"
        )
        self.assertEqual(
            hashlib.sha256(source.read_bytes()).hexdigest(),
            "7dcf85b94609f8c8cab13fed97ce78fff23a2beb66938484a1aa00d484137542",
        )
        self.child = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-c",
                FIXTURE,
                str(source),
                str(self.root),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            umask=0o077,
        )
        self.addCleanup(self.stop)
        line = self.child.stdout.readline()
        if line != b"ready\n":
            self.fail(self.child.communicate(timeout=5)[1].decode())
        self.binding = unix_peer.process_identity(self.child.pid)
        self.run = os.open(self.root / "run", os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.run)
        self.config = os.open(self.root / "config", os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.config)
        self.identity = {
            "instance_id": "a" * 32,
            "config_sha256": hashlib.sha256(
                (self.root / "config/application.json").read_bytes()
            ).hexdigest(),
            "application_uid": os.getuid(),
        }

    def stop(self):
        if self.child.poll() is None:
            self.child.terminate()
        self.child.communicate(timeout=5)

    def read(self):
        return api.read(self.run, self.binding, self.config, self.identity)

    def test_original_token_read_append_and_idempotent_readback_without_sql(self):
        # The actual writer owns the EX lock throughout. The client must not try
        # to acquire it or read SQLite while this writer runs.
        with (self.root / "config/application.json").open("rb") as configuration:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(configuration, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with mock.patch(
            "sqlite3.connect", side_effect=AssertionError("host SQL forbidden")
        ), mock.patch("fcntl.flock", side_effect=AssertionError("client EX forbidden")):
            original = self.read()
            self.assertEqual(
                original["entries"],
                [{"sequence": 1, "operation_id": "c" * 32, "value": "original record"}],
            )
            result = api.append(
                self.run,
                self.binding,
                self.config,
                self.identity,
                "d" * 32,
                "retained write",
            )
            self.assertEqual(result, {"outcome": "committed", "sequence": 2})
            self.assertEqual(
                api.append(
                    self.run,
                    self.binding,
                    self.config,
                    self.identity,
                    "d" * 32,
                    "retained write",
                ),
                {"outcome": "unchanged", "sequence": 2},
            )
            after = self.read()
            self.assertEqual(after["entries"][:-1], original["entries"])
            self.assertEqual(after["record_count"], 2)
            self.assertEqual(after["entries"][-1]["value"], "retained write")
        self.assertNotIn("b" * 64, repr((original, result, after)))

    def test_changed_configuration_or_wrong_identity_refuses(self):
        for key, value in (
            ("config_sha256", "e" * 64),
            ("instance_id", "e" * 32),
            ("application_uid", True),
        ):
            with self.subTest(key=key):
                identity = {**self.identity, key: value}
                with self.assertRaises(api.LedgerApiError):
                    api.read(self.run, self.binding, self.config, identity)
        path = self.root / "config/application.json"
        path.chmod(0o644)
        with self.assertRaises(api.LedgerApiError):
            self.read()

    def test_duplicate_json_keys_and_malformed_records_refuse(self):
        valid = {
            "outcome": "read",
            "instance_id": "a" * 32,
            "entries": [
                {"sequence": 1, "operation_id": "c" * 32, "value": "original record"}
            ],
        }
        bad = [b'{"outcome":"unauthorized","outcome":"read"}\n']
        for field, value in (
            ("sequence", True),
            ("sequence", 0),
            ("operation_id", "invalid"),
            ("value", 5),
        ):
            item = copy.deepcopy(valid)
            item["entries"][0][field] = value
            bad.append(json.dumps(item).encode() + b"\n")
        for mutation in (
            "wrong-instance",
            "extra",
            "duplicate-sequence",
            "duplicate-operation",
        ):
            item = copy.deepcopy(valid)
            if mutation == "wrong-instance":
                item["instance_id"] = "e" * 32
            elif mutation == "extra":
                item["token"] = "b" * 64
            elif mutation == "duplicate-sequence":
                item["entries"].append(
                    {"sequence": 1, "operation_id": "d" * 32, "value": "x"}
                )
            else:
                item["entries"].append(
                    {"sequence": 2, "operation_id": "c" * 32, "value": "x"}
                )
            bad.append(json.dumps(item).encode() + b"\n")
        for raw in bad:

            def response(parent, name, binding, supplier):
                supplier()
                return raw

            with self.subTest(raw=raw[:60]), mock.patch.object(
                unix_peer, "exchange", side_effect=response
            ):
                with self.assertRaises(api.LedgerApiError) as raised:
                    self.read()
                self.assertNotIn("b" * 64, str(raised.exception))

    def test_append_requires_exact_success_and_never_retries(self):
        for result in (
            {"outcome": "uncertain"},
            {"outcome": "conflict"},
            {"outcome": "committed", "sequence": True},
            {"outcome": "committed", "sequence": 2, "token": "b" * 64},
        ):

            def response(parent, name, binding, supplier):
                supplier()
                return json.dumps(result).encode() + b"\n"

            with self.subTest(result=result), mock.patch.object(
                unix_peer, "exchange", side_effect=response
            ) as exchange:
                with self.assertRaises(api.LedgerApiError):
                    api.append(
                        self.run,
                        self.binding,
                        self.config,
                        self.identity,
                        "d" * 32,
                        "retained write",
                    )
                self.assertEqual(exchange.call_count, 1)

    def test_configuration_change_after_response_is_refused(self):
        original = unix_peer.exchange

        def mutate(*args, **kwargs):
            raw = original(*args, **kwargs)
            path = self.root / "config/application.json"
            path.write_bytes(path.read_bytes() + b" ")
            return raw

        with mock.patch.object(unix_peer, "exchange", side_effect=mutate):
            with self.assertRaises(api.LedgerApiError):
                self.read()

    def test_response_cannot_return_the_credential_as_a_record(self):
        # A valid peer and valid row shape do not authorize returning a secret.
        # Seed through the actual fixture API without the client under test.
        command = {
            "action": "append",
            "token": "b" * 64,
            "operation_id": "d" * 32,
            "value": "b" * 64,
        }
        unix_peer.exchange(
            self.run,
            "api.sock",
            self.binding,
            lambda: json.dumps(command).encode() + b"\n",
        )
        with self.assertRaises(api.LedgerApiError) as raised:
            self.read()
        self.assertNotIn("b" * 64, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
