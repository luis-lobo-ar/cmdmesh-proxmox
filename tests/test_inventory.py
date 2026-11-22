"""Protocol tests use only disposable loopback HTTPS servers."""

import contextlib
import hashlib
import http.server
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import ssl
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin/cmdmesh-proxmox"
SCRATCH = ROOT / ".generated/inventory-tests"
SCRATCH.mkdir(parents=True, exist_ok=True, mode=0o700)


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(dir=SCRATCH)
        cls.ca = Path(cls.work.name) / "ca.pem"
        cls.key = Path(cls.work.name) / "key.pem"
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
                    self.wfile.write(b"PRIVATE_TOKEN_SHOULD_NOT_APPEAR")
                    return
                if mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", "https://example.invalid/stolen")
                    self.end_headers()
                    return
                if self.path == "/api2/json/nodes":
                    data = [{"node": "node-a", "status": "online"}]
                elif self.path.endswith("/qemu"):
                    if mode == "partial":
                        self.send_error(503)
                        return
                    data = [{"vmid": 101, "name": "demo-vm", "status": "running"}]
                else:
                    data = [{"vmid": 102, "name": "demo-lxc", "status": "stopped"}]
                payload = json.dumps({"data": data}).encode()
                if mode == "malformed":
                    payload = b"not-json PRIVATE_TOKEN_SHOULD_NOT_APPEAR"
                if mode == "oversize":
                    payload = b"x" * (2 * 1024 * 1024 + 1)
                if mode == "empty":
                    payload = b'{"data": []}'
                self.send_response(200)
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_):
                pass

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(self.ca), str(self.key))
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        config = {
            "endpoint": f"https://localhost:{httpd.server_port}",
            "ca_file": str(self.ca),
            "token_id_env": "TEST_PVE_ID",
            "token_secret_env": "TEST_PVE_SECRET",
            "timeout_seconds": 2,
        }
        try:
            yield config, requests
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join()

    def invoke(self, config):
        request = {"schema_version": 1, "operation": "inventory", "config": config}
        result = subprocess.run(
            ["python3", str(CLI)],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            timeout=15,
            env={
                **os.environ,
                "TEST_PVE_ID": "reader@pve!inventory",
                "TEST_PVE_SECRET": "PRIVATE_TOKEN_SHOULD_NOT_APPEAR",
            },
        )
        self.assertNotIn(
            "PRIVATE_TOKEN_SHOULD_NOT_APPEAR", result.stdout + result.stderr
        )
        return result, json.loads(result.stdout)

    def test_complete_get_only_inventory(self):
        with self.server() as (config, requests):
            result, snapshot = self.invoke(config)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(snapshot["complete"])
        self.assertEqual(
            [r["kind"] for r in snapshot["resources"]],
            ["proxmox.node", "proxmox.vm", "proxmox.lxc"],
        )
        self.assertEqual(snapshot["resources"][2]["id"], "node-a/102")
        self.assertTrue(all(method == "GET" for method, _, _ in requests))
        self.assertTrue(
            all(
                auth
                == "PVEAPIToken=reader@pve!inventory=PRIVATE_TOKEN_SHOULD_NOT_APPEAR"
                for _, _, auth in requests
            )
        )

    def test_partial_is_not_complete(self):
        with self.server("partial") as (config, _):
            result, snapshot = self.invoke(config)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(snapshot["complete"])
        self.assertEqual(len(snapshot["resources"]), 2)

    def test_untrusted_certificate_rejected(self):
        with self.server() as (config, _):
            del config["ca_file"]
            _, snapshot = self.invoke(config)
        self.assertFalse(snapshot["complete"])
        self.assertEqual(snapshot["resources"], [])

    def test_hostname_mismatch_rejected(self):
        with self.server() as (config, _):
            config["endpoint"] = config["endpoint"].replace("localhost", "127.0.0.1")
            _, snapshot = self.invoke(config)
        self.assertFalse(snapshot["complete"])

    def test_invalid_responses_are_safe_failures(self):
        for mode in ("unauthorized", "malformed", "oversize", "empty", "redirect"):
            with self.subTest(mode=mode), self.server(mode) as (config, requests):
                result, snapshot = self.invoke(config)
                self.assertEqual(result.returncode, 0)
                self.assertFalse(snapshot["complete"])
                self.assertEqual(len(requests), 1)

    def test_invalid_config_rejected_before_request(self):
        with self.server() as (config, requests):
            for change in (
                {"endpoint": "http://example.invalid"},
                {"insecure": True},
                {"timeout_seconds": 0},
                {"timeout_seconds": True},
                {"token_id_env": "DOES_NOT_EXIST"},
            ):
                _, snapshot = self.invoke({**config, **change})
                self.assertFalse(snapshot["complete"])
            self.assertEqual(requests, [])

    def test_explicit_fixture(self):
        fixture = ROOT / "examples/inventory.fixture.json"
        result = subprocess.run(
            ["python3", str(CLI), "--fixture", str(fixture)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["complete"])

    def test_total_deadline_escapes_guest_collection(self):
        loader = importlib.machinery.SourceFileLoader("inventory_test_module", str(CLI))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        calls = []

        def slow_get(_opener, _endpoint, path, _token, _timeout):
            calls.append(path)
            if path == "/nodes":
                return [{"node": "node-a"}, {"node": "node-b"}]
            time.sleep(0.5)
            return []

        config = {
            "endpoint": "https://example.invalid",
            "token_id_env": "TEST_PVE_ID",
            "token_secret_env": "TEST_PVE_SECRET",
        }
        previous = signal.signal(signal.SIGALRM, module.deadline)
        start = time.monotonic()
        try:
            with mock.patch.object(
                module, "api_get", side_effect=slow_get
            ), mock.patch.dict(
                os.environ,
                {"TEST_PVE_ID": "reader@pve!inventory", "TEST_PVE_SECRET": "sentinel"},
            ):
                signal.setitimer(signal.ITIMER_REAL, 0.1)
                with self.assertRaises(module.InventoryDeadline):
                    module.inventory(config)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        self.assertLess(time.monotonic() - start, 0.4)
        self.assertEqual(calls, ["/nodes", "/nodes/node-a/qemu"])

    def test_nonfinite_json_is_safe_failure(self):
        request = '{"schema_version":1,"operation":"inventory","config":{"timeout_seconds":NaN}}'
        result = subprocess.run(
            ["python3", str(CLI)],
            input=request,
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)["complete"])
        self.assertEqual(result.stderr, "")

    def test_invalid_explicit_ca_values_never_select_default_trust(self):
        with self.server() as (config, requests), mock.patch.dict(
            os.environ, {"SSL_CERT_FILE": str(self.ca)}
        ):
            for invalid in (False, 0, [], {}, None, ""):
                with self.subTest(ca_file=invalid):
                    _, snapshot = self.invoke({**config, "ca_file": invalid})
                    self.assertFalse(snapshot["complete"])
            self.assertEqual(len(requests), 0)

    def test_nonregular_ca_is_rejected_without_waiting_for_ssl(self):
        fifo = Path(self.work.name) / "legacy-ca.pipe"
        os.mkfifo(fifo)
        request = {
            "schema_version": 1,
            "operation": "inventory",
            "config": {
                "endpoint": "https://localhost:1",
                "ca_file": str(fifo),
                "token_id_env": "TEST_PVE_ID",
                "token_secret_env": "TEST_PVE_SECRET",
            },
        }
        result = subprocess.run(
            ["python3", str(CLI)],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            timeout=2,
            env={
                **os.environ,
                "TEST_PVE_ID": "reader@pve!inventory",
                "TEST_PVE_SECRET": "synthetic",
            },
        )
        self.assertEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)["complete"])

    def test_prepared_client_uses_the_captured_trust_bytes_during_and_after_file_change(
        self,
    ):
        loader = importlib.machinery.SourceFileLoader(
            "inventory_trust_module", str(CLI)
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        with self.server() as (config, requests):
            copied_ca = Path(self.work.name) / "captured-ca.pem"
            original = self.ca.read_bytes()
            copied_ca.write_bytes(original)
            config = {**config, "ca_file": str(copied_ca)}
            factory = module.ssl.create_default_context

            def rotate_file(*args, **kwargs):
                copied_ca.write_text("invalid rotated trust file")
                return factory(*args, **kwargs)

            with mock.patch.dict(
                os.environ,
                {"TEST_PVE_ID": "reader@pve!inventory", "TEST_PVE_SECRET": "synthetic"},
            ), mock.patch.object(
                module.ssl, "create_default_context", side_effect=rotate_file
            ):
                prepared = module.prepare_config(config)
                result = module.inventory_from_context(*prepared[:4])
            self.assertTrue(result["complete"])
            self.assertEqual(len(requests), 3)
            self.assertEqual(
                prepared[4],
                {
                    "mode": "explicit-ca-snapshot",
                    "sha256": hashlib.sha256(original).hexdigest(),
                },
            )

    def test_empty_ca_contents_cannot_fall_back_to_default_trust(self):
        path = Path(self.work.name) / "empty-ca.pem"
        path.write_bytes(b"")
        with self.server() as (config, requests), mock.patch.dict(
            os.environ, {"SSL_CERT_FILE": str(self.ca)}
        ):
            _, result = self.invoke({**config, "ca_file": str(path)})
            self.assertFalse(result["complete"])
            self.assertEqual(len(requests), 0)


if __name__ == "__main__":
    unittest.main()
