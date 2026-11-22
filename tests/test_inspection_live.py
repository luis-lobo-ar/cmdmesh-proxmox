"""Qualify live collection only against disposable loopback HTTPS fixtures."""

import contextlib
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = ROOT / ".generated/inspection-tests"
SCRATCH.mkdir(parents=True, exist_ok=True, mode=0o700)


class InspectionLiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(dir=SCRATCH)
        cls.root = Path(cls.work.name)
        cls.bundle = cls.root / "inspector.pyz"
        subprocess.run(
            [
                "python3",
                str(ROOT / "tools/build_inspector.py"),
                "--out",
                str(cls.bundle),
            ],
            check=True,
            capture_output=True,
            timeout=10,
        )
        cls.ca, cls.key = cls.root / "ca.pem", cls.root / "key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(cls.key),
                "-out",
                str(cls.ca),
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
            ],
            check=True,
            capture_output=True,
            timeout=10,
        )

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    @contextlib.contextmanager
    def server(self, mode="normal"):
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(
                    (self.command, self.path, self.headers.get("Authorization"))
                )
                if mode == "unauthorized":
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"SYNTHETIC_PRIVATE_RESPONSE")
                    return
                if self.path == "/api2/json/nodes":
                    data = [{"node": "node-a", "status": "online"}]
                elif self.path.endswith("/qemu"):
                    if mode == "partial":
                        self.send_error(503)
                        return
                    data = []
                else:
                    data = [{"vmid": 101, "name": "demo", "status": "running"}]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({"data": data}).encode())

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.ca, self.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_port, requests
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def request(self, port):
        return {
            "document_type": "cmdmesh.inspection.request",
            "schema_version": 1,
            "operation": "target-resolve",
            "input": {
                "source": {"mode": "live"},
                "selector": {
                    "origin": "example",
                    "node": "node-a",
                    "kind": "proxmox.lxc",
                    "vmid": 101,
                },
            },
            "config": {
                "schema_version": 1,
                "origin": "example",
                "api": {
                    "endpoint": f"https://localhost:{port}",
                    "ca_file": str(self.ca),
                    "token_id_env": "INSPECTION_TEST_TOKEN_ID",
                    "token_secret_env": "INSPECTION_TEST_TOKEN_SECRET",
                    "timeout_seconds": 1,
                },
            },
        }

    def inspect(self, request):
        result = subprocess.run(
            [str(self.bundle)],
            input=json.dumps(request),
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "INSPECTION_TEST_TOKEN_ID": "reader@pve!fixture",
                "INSPECTION_TEST_TOKEN_SECRET": "SYNTHETIC_PRIVATE_TOKEN",
            },
            timeout=10,
        )
        self.assertNotIn("SYNTHETIC_PRIVATE", result.stdout + result.stderr)
        return result.returncode, json.loads(result.stdout)

    def test_live_mode_reuses_verified_get_only_provider_and_binds_origin(self):
        with self.server() as (port, requests):
            code, result = self.inspect(self.request(port))
            self.assertEqual(code, 0, result)
            self.assertEqual(result["outcome"], "observed")
            self.assertEqual(result["data"]["resolution"], "resolved")
            self.assertEqual(result["data"]["source"]["mode"], "live")
            self.assertEqual(
                result["data"]["source"]["collection_scope"], "configured-api-endpoint"
            )
            self.assertFalse(result["data"]["source"]["visibility_qualified"])
            self.assertTrue(result["data"]["current_observation"])
            self.assertFalse(result["data"]["mutation_authorized"])
            self.assertRegex(
                result["data"]["source"]["configuration_sha256"], r"^[a-f0-9]{64}$"
            )
            self.assertEqual(len(requests), 3)
            self.assertTrue(
                all(
                    method == "GET" and auth.endswith("SYNTHETIC_PRIVATE_TOKEN")
                    for method, _, auth in requests
                )
            )

    def test_live_origin_mismatch_and_snapshot_injection_stop_before_network(self):
        with self.server() as (port, requests):
            request = self.request(port)
            request["config"]["origin"] = "another-origin"
            self.assertEqual(
                self.inspect(request)[1]["diagnostics"][0]["code"], "origin-mismatch"
            )
            request = self.request(port)
            request["input"]["source"]["snapshot"] = {"complete": True}
            self.assertEqual(self.inspect(request)[1]["outcome"], "rejected")
            self.assertEqual(requests, [])

    def test_partial_live_collection_remains_indeterminate_despite_one_match(self):
        with self.server("partial") as (port, _):
            code, result = self.inspect(self.request(port))
            self.assertNotEqual(code, 0)
            self.assertEqual(result["outcome"], "incomplete")
            self.assertEqual(result["data"]["resolution"], "indeterminate")
            self.assertFalse(result["data"]["current_observation"])

    def test_authentication_and_tls_failure_never_fall_back_to_offline_data(self):
        with self.server("unauthorized") as (port, _):
            code, result = self.inspect(self.request(port))
            self.assertNotEqual(code, 0)
            self.assertEqual(result["outcome"], "unavailable")
            self.assertEqual(
                result["diagnostics"][0]["code"], "api-authentication-failed"
            )
        with self.server() as (port, requests):
            request = self.request(port)
            request["config"]["api"]["endpoint"] = f"https://127.0.0.1:{port}"
            code, result = self.inspect(request)
            self.assertNotEqual(code, 0)
            self.assertEqual(result["outcome"], "unavailable")
            self.assertEqual(requests, [])

    def test_nonregular_trust_file_fails_before_ssl_can_block_on_a_fifo(self):
        path = self.root / "trust.pipe"
        os.mkfifo(path)
        request = self.request(1)
        request["config"]["api"]["ca_file"] = str(path)
        result = subprocess.run(
            [str(self.bundle)],
            input=json.dumps(request),
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "INSPECTION_TEST_TOKEN_ID": "reader@pve!fixture",
                "INSPECTION_TEST_TOKEN_SECRET": "SYNTHETIC_PRIVATE_TOKEN",
            },
            timeout=2,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            json.loads(result.stdout)["diagnostics"][0]["code"], "invalid-trust-file"
        )

    def test_invalid_api_configuration_is_an_input_error_not_remote_unavailability(
        self,
    ):
        request = self.request(1)
        request["config"]["api"] = True
        code, result = self.inspect(request)
        self.assertNotEqual(code, 0)
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["diagnostics"][0]["code"], "invalid-provider-config")

    def test_invalid_explicit_ca_does_not_fall_back_to_ambient_default_trust(self):
        with self.server() as (port, requests):
            for invalid in (False, 0, [], {}, None, ""):
                with self.subTest(ca_file=invalid):
                    request = self.request(port)
                    request["config"]["api"]["ca_file"] = invalid
                    result = subprocess.run(
                        [str(self.bundle)],
                        input=json.dumps(request),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        env={
                            **os.environ,
                            "SSL_CERT_FILE": str(self.ca),
                            "INSPECTION_TEST_TOKEN_ID": "reader@pve!fixture",
                            "INSPECTION_TEST_TOKEN_SECRET": "SYNTHETIC_PRIVATE_TOKEN",
                        },
                    )
                    self.assertNotEqual(result.returncode, 0)
                    parsed = json.loads(result.stdout)
                    self.assertEqual(parsed["outcome"], "rejected")
                    self.assertEqual(
                        parsed["diagnostics"][0]["code"], "invalid-trust-file"
                    )
            self.assertEqual(requests, [])

    def test_missing_trust_file_has_specific_recovery_guidance(self):
        request = self.request(1)
        request["config"]["api"]["ca_file"] = str(self.root / "missing-ca.pem")
        code, result = self.inspect(request)
        self.assertNotEqual(code, 0)
        diagnostic = result["diagnostics"][0]
        self.assertEqual(diagnostic["code"], "trust-unavailable")
        self.assertIn("PEM", " ".join(diagnostic["next_checks"]))
