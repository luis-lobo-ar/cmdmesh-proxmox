"""Live memory observation uses loopback TLS and a synthetic SSH transport only."""

import contextlib
import copy
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

from test_memory_state import expected, observation

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = ROOT / ".generated/memory-collect-tests"
SCRATCH.mkdir(parents=True, exist_ok=True, mode=0o700)


class MemoryCollectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(dir=SCRATCH)
        cls.root = Path(cls.work.name)
        cls.bundle = cls.root / "inspector.pyz"
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/build_inspector.py"),
                "--out",
                str(cls.bundle),
            ],
            check=True,
            capture_output=True,
        )
        cls.ca, cls.leaf, cls.key = (
            cls.root / name for name in ("ca.pem", "leaf.pem", "leaf.key")
        )
        ca_key, csr = cls.root / "ca.key", cls.root / "leaf.csr"
        ext = cls.root / "extensions"
        ext.write_text("subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n")
        commands = [
            [
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(ca_key),
                "-out",
                str(cls.ca),
                "-days",
                "1",
                "-subj",
                "/CN=Example CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
            ],
            [
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(cls.key),
                "-out",
                str(csr),
                "-subj",
                "/CN=localhost",
            ],
            [
                "x509",
                "-req",
                "-in",
                str(csr),
                "-CA",
                str(cls.ca),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(cls.leaf),
                "-days",
                "1",
                "-extfile",
                str(ext),
            ],
        ]
        for command in commands:
            subprocess.run(
                ["openssl", *command], check=True, capture_output=True, timeout=10
            )

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.called = self.base / "called"

    @contextlib.contextmanager
    def transports(self):
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_error(500)

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.leaf, self.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(16)
                yield server.server_port, listener.getsockname()[1], requests
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def settings(self, tls_port, ssh_port, frame=None, mode="normal"):
        value, frame = expected(), copy.deepcopy(
            frame if frame is not None else observation()
        )
        for field, path in (
            ("ca_certificate_sha256", self.ca),
            ("leaf_certificate_sha256", self.leaf),
        ):
            value["host_profile"][field] = hashlib.sha256(
                ssl.PEM_cert_to_DER_cert(path.read_text())
            ).hexdigest()
        frame["host_profile"] = copy.deepcopy(value["host_profile"])
        fixture = self.base / "frame.json"
        fixture.write_text(json.dumps(frame))
        identity, known = self.base / "identity", self.base / "known_hosts"
        identity.write_text("SYNTHETIC_PRIVATE_KEY")
        known.write_text("SYNTHETIC_HOST_KEY")
        tool = self.base / "ssh"
        source_hash = hashlib.sha256(
            (
                ROOT
                / "ansible/ansible_collections/cmdmesh/proxmox/plugins/module_utils/memory_remote.py"
            ).read_bytes()
        ).hexdigest()
        tool.write_text(
            f"#!{sys.executable}\n"
            + f"""
import hashlib,json,os,shlex,sys
from pathlib import Path
a=sys.argv[1:]
assert a[:2]==['-F','none']
assert all(o in a for o in ['StrictHostKeyChecking=yes','IdentityAgent=none','CertificateFile=none','PreferredAuthentications=publickey','ProxyCommand=none','ProxyJump=none','ControlPath=none'])
assert 'SYNTHETIC_SECRET' not in os.environ
c=shlex.split(a[-1])
assert c[:4]==['/usr/bin/python3','-I','-B','-c']
assert len(c)==6 and hashlib.sha256(c[4].encode()).hexdigest()=={source_hash!r}
envelope=json.loads(c[5])
assert set(envelope)=={{'request','observed_at_unix_ms'}}
Path({str(self.called)!r}).touch()
f=json.loads(Path({str(fixture)!r}).read_text())
if {mode!r} != 'replay-id': f['request_id']=envelope['request']['request_id']
if {mode!r} != 'replay-time': f['observed_at_unix_ms']=envelope['observed_at_unix_ms']
if {mode!r} == 'overflow': print('{{"bad":1e999}}')
elif {mode!r} == 'duplicate': print('{{"bad":1,"bad":2}}')
elif {mode!r} == 'invalid-utf8':
    f['tags'].append('CORRUPT_BYTE')
    sys.stdout.buffer.write(json.dumps(f).encode().replace(b'CORRUPT_BYTE',b'\\xff'))
elif {mode!r} == 'unknown-error': print('{{"schema_version":1,"error":"SYNTHETIC_PRIVATE_OUTPUT"}}');sys.exit(1)
elif {mode!r} == 'remote-error': print('{{"schema_version":1,"error":"remote-memory-host-mismatch"}}');sys.exit(1)
else: print(json.dumps(f))
"""
        )
        tool.chmod(0o700)
        return value, {
            "schema_version": 1,
            "origin": "example",
            "controller": {"scratch_root": str(self.base)},
            "tls": {
                "host": "127.0.0.1",
                "port": tls_port,
                "server_name": "localhost",
                "ca_file": str(self.ca),
            },
            "ssh": {
                "executable": str(tool),
                "host": "127.0.0.1",
                "port": ssh_port,
                "user": "root",
                "identity_file": str(identity),
                "known_hosts_file": str(known),
            },
        }

    def inspect(self, value, config):
        result = subprocess.run(
            [str(self.bundle)],
            input=json.dumps(
                {
                    "document_type": "cmdmesh.inspection.request",
                    "schema_version": 1,
                    "operation": "lxc-memory-observe",
                    "input": value,
                    "config": config,
                }
            ),
            text=True,
            capture_output=True,
            timeout=10,
            env={**os.environ, "SYNTHETIC_SECRET": "PRIVATE"},
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        self.assertEqual(result.stderr, "")
        response = json.loads(result.stdout)
        self.assertNotIn("SYNTHETIC_PRIVATE", result.stdout)
        return response

    def test_live_observation_authenticates_both_channels_without_http_or_guest_execution(
        self,
    ):
        with self.transports() as (tls_port, ssh_port, requests):
            value, config = self.settings(tls_port, ssh_port)
            result = self.inspect(value, config)
            self.assertEqual(result["outcome"], "observed", result)
            self.assertTrue(result["data"]["current_observation"])
            self.assertFalse(result["data"]["mutation_authorized"])
            self.assertEqual(
                result["data"]["observation"]["configuration"]["memory_mb"], 256
            )
            self.assertEqual(result["data"]["source"]["mode"], "live")
            self.assertEqual(requests, [])
        self.assertTrue(self.called.exists())

    def test_nonce_is_generated_if_omitted_and_echoed_as_collected(self):
        with self.transports() as (tls_port, ssh_port, _):
            value, config = self.settings(tls_port, ssh_port)
            del value["request_id"]
            result = self.inspect(value, config)
        self.assertEqual(result["outcome"], "observed", result)
        self.assertRegex(result["data"]["observation"]["request_id"], r"^[a-f0-9]{32}$")

    def test_bad_origin_offline_command_and_missing_explicit_ca_stop_before_ssh(self):
        for mode in ("origin", "offline", "command", "ca", "user"):
            with self.subTest(mode=mode), self.transports() as (tls_port, ssh_port, _):
                value, config = self.settings(tls_port, ssh_port)
                if mode == "origin":
                    config["origin"] = "elsewhere"
                elif mode == "ca":
                    del config["tls"]["ca_file"]
                elif mode == "user":
                    config["ssh"]["user"] = "operator"
                else:
                    value[mode] = "anything"
                self.assertEqual(self.inspect(value, config)["outcome"], "rejected")
                self.assertFalse(self.called.exists())

    def test_ca_leaf_and_name_mismatch_do_not_run_ssh(self):
        for mode in ("ca", "leaf", "name", "extra-certificate"):
            with self.subTest(mode=mode), self.transports() as (tls_port, ssh_port, _):
                value, config = self.settings(tls_port, ssh_port)
                if mode == "extra-certificate":
                    combined = self.base / "combined.pem"
                    combined.write_bytes(self.ca.read_bytes() + self.leaf.read_bytes())
                    config["tls"]["ca_file"] = str(combined)
                elif mode == "name":
                    config["tls"]["server_name"] = "wrong.invalid"
                else:
                    value["host_profile"][mode + "_certificate_sha256"] = "f" * 64
                result = self.inspect(value, config)
                self.assertNotEqual(result["outcome"], "observed", result)
                self.assertFalse(self.called.exists())

    def test_partial_wrong_owner_unknown_version_and_wrong_runtime_fail(self):
        for field, replacement in (
            ("complete", False),
            ("warnings", ["private"]),
            ("node", "node-b"),
            ("tags", ["cmdmesh-ansible"]),
            ("versions", {"pve-manager": "99.0.0", "pve-container": "6.1.14"}),
        ):
            with self.subTest(field=field), self.transports() as (
                tls_port,
                ssh_port,
                _,
            ):
                frame = observation()
                frame[field] = replacement
                value, config = self.settings(tls_port, ssh_port, frame)
                result = self.inspect(value, config)
                self.assertNotEqual(result["outcome"], "observed", result)

    def test_replayed_nonce_time_nonfinite_duplicate_and_remote_error_are_bounded_failures(
        self,
    ):
        for mode in (
            "replay-id",
            "replay-time",
            "overflow",
            "duplicate",
            "invalid-utf8",
            "remote-error",
            "unknown-error",
        ):
            with self.subTest(mode=mode), self.transports() as (tls_port, ssh_port, _):
                value, config = self.settings(tls_port, ssh_port, mode=mode)
                value["request_id"] = "8" * 32
                result = self.inspect(value, config)
                self.assertNotEqual(result["outcome"], "observed", result)
                self.assertTrue(result["diagnostics"])


if __name__ == "__main__":
    unittest.main()
