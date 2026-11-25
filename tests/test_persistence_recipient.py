"""A stopped replacement rootfs is not a completed application rebuild."""

from contextlib import contextmanager
import copy
import http.server
import json
import os
from pathlib import Path
import sys
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_recipient as recipient,
    persistence_state as state,
)
from test_persistence_state import manifest

REAL_POST = recipient.post_create
REAL_VERIFY = recipient.verify_target


def example_request():
    return {
        "schema_version": 1,
        "operation_id": "b" * 64,
        "source_request": {"source": manifest()["source"], "policy": {}},
        "target": {
            "vmid": 102,
            "hostname": "reference-rebuilt",
            "generation_tag": "cmdmesh-gen-" + "9" * 32,
        },
        "template": {
            "volume": "local:vztmpl/ubuntu-24.04-standard_24.04-2_amd64.tar.zst",
            "bytes": 100,
            "sha256": "c" * 64,
        },
        "storage_id": "local",
    }


class RecipientTests(unittest.TestCase):
    def setUp(self):
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(
            dir=ROOT / ".generated", prefix="recipient-"
        )
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        model = manifest()
        self.source = {
            "source": model["source"],
            "policy": {
                "vmid": 101,
                "node": "node-a",
                "owner_tag": model["source"]["owner_tag"],
                "datasets": {
                    role: {"mountpoint": "/srv/reference/" + role}
                    for role in ("data", "config")
                },
                "rootfs": {"uuid": "source-uuid"},
            },
            "versions": {},
        }
        self.request = {
            "schema_version": 1,
            "operation_id": "b" * 64,
            "source_request": self.source,
            "target": {
                "vmid": 102,
                "hostname": "reference-rebuilt",
                "generation_tag": "cmdmesh-gen-" + "9" * 32,
            },
            "template": {
                "volume": "local:vztmpl/ubuntu-24.04-standard_24.04-2_amd64.tar.zst",
                "bytes": 100,
                "sha256": "c" * 64,
            },
            "storage_id": "local",
        }
        self.facts = {
            "quiesced": True,
            "application": model["application"],
            "source": model["source"],
        }
        self.preflight = {
            "source_sha256": state.sha256(state.canonical(self.facts)),
            "inventory": [
                {
                    "vmid": 101,
                    "node": "node-a",
                    "type": "lxc",
                    "name": "reference-original",
                    "status": "stopped",
                    "tags": "cmdmesh-ansible;"
                    + model["source"]["owner_tag"]
                    + ";"
                    + model["source"]["generation_tag"],
                    "template": None,
                }
            ],
            "storage": {
                "type": "dir",
                "path": "/var/lib/vz",
                "content": "rootdir,vztmpl",
            },
            "template": {
                "path": "/var/lib/vz/template/cache/ubuntu-24.04-standard_24.04-2_amd64.tar.zst",
                "sha256": "c" * 64,
                "identity": [1, 2, stat.S_IFREG | 0o644, 0, 0, 1, 100, 1, 1],
            },
            "ha": [],
        }
        self.after = {
            "vmid": 102,
            "rootfs": {
                "volume": "local:102/vm-102-disk-0.raw",
                "uuid": "replacement-uuid",
            },
        }
        now = int(time.time())
        self.task = {
            "upid": "UPID:node-a:00000010:00000020:"
            + format(now, "08X")
            + ":vzcreate:102:root@pam:",
            "node": "node-a",
            "pid": 16,
            "pstart": 32,
            "starttime": now,
            "type": "vzcreate",
            "id": "102",
            "user": "root@pam",
            "status": "stopped",
            "exitstatus": "OK",
        }
        self.log = [{"n": 1, "t": "TASK OK"}]
        self.posts = []
        self.inside_lock = False

        @contextmanager
        def source(request, require_stopped=False):
            self.assertTrue(require_stopped)
            self.assertFalse(self.inside_lock)
            self.inside_lock = True
            try:
                yield copy.deepcopy(self.facts)
            finally:
                self.inside_lock = False

        def post(request):
            self.assertTrue(self.inside_lock)
            self.assertTrue(any(recipient.RUNTIME_ROOT.rglob("intent.json")))
            self.assertTrue(any(recipient.RUNTIME_ROOT.rglob("write-possible.json")))
            self.posts.append(copy.deepcopy(request))
            return {"upid": self.task["upid"], "tls_verified": True}

        def status(request, upid):
            self.assertEqual(upid, self.task["upid"])
            return copy.deepcopy(self.task), copy.deepcopy(self.log)

        for patch in (
            mock.patch.object(recipient.observe, "source_state", side_effect=source),
            mock.patch.object(
                recipient,
                "collect_preflight",
                side_effect=lambda *args, **kwargs: copy.deepcopy(self.preflight),
            ),
            mock.patch.object(recipient, "post_create", side_effect=post),
            mock.patch.object(recipient, "task_state", side_effect=status),
            mock.patch.object(
                recipient,
                "verify_target",
                side_effect=lambda *args: copy.deepcopy(self.after),
            ),
            mock.patch.object(
                recipient, "RUNTIME_ROOT", self.root / "managed/recipients"
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def prepared(self):
        raw = state.canonical(recipient.prepare(self.request))
        return raw, state.sha256(raw)

    def test_prepare_is_readonly_and_fixed_request_has_no_start_or_network(self):
        raw, trusted = self.prepared()
        self.assertEqual(recipient.load_prepared(raw, trusted)["request"], self.request)
        body = recipient.create_request(self.request)
        self.assertEqual(body["vmid"], "102")
        self.assertEqual(body["start"], "0")
        self.assertEqual(body["onboot"], "0")
        self.assertEqual(body["protection"], "1")
        self.assertEqual(body["unprivileged"], "1")
        self.assertEqual(body["cpulimit"], "1")
        self.assertEqual(body["rootfs"], "local:2")
        self.assertNotIn("mp0", body)
        self.assertNotIn("mp1", body)
        self.assertFalse(
            any(
                k.startswith("net")
                or k in {"features", "hookscript", "password", "force"}
                for k in body
            )
        )
        self.assertFalse(recipient.RUNTIME_ROOT.exists())

        self.assertEqual(self.posts, [])

    def test_one_post_consumes_target_and_reports_provision_only(self):
        raw, trusted = self.prepared()
        result = recipient.provision(raw, trusted)
        self.assertEqual(len(self.posts), 1)
        self.assertTrue(result["provisioned_verified"])
        self.assertFalse(result["rebuild_verified"] or result["restore_verified"])
        self.assertEqual(result["target"], self.after)
        self.assertTrue(any(recipient.RUNTIME_ROOT.rglob("complete.json")))
        with self.assertRaises(state.PersistenceError):
            recipient.provision(raw, trusted)
        changed = json.loads(raw)
        changed["request"]["operation_id"] = "d" * 64
        raw = state.canonical(changed)
        with self.assertRaises(state.PersistenceError):
            recipient.provision(raw, state.sha256(raw))
        self.assertEqual(len(self.posts), 1)

    def test_wrong_prepared_hash_or_changed_source_refuses_before_claim(self):
        raw, trusted = self.prepared()
        with self.assertRaises(state.PersistenceError):
            recipient.provision(raw, "0" * 64)
        self.preflight["source_sha256"] = "0" * 64
        with self.assertRaises(state.PersistenceError):
            recipient.provision(raw, trusted)
        self.assertFalse(recipient.RUNTIME_ROOT.exists())
        self.assertEqual(self.posts, [])

    def test_rehashed_preparation_cannot_omit_or_falsify_destination_evidence(self):
        raw, _ = self.prepared()
        frozen = json.loads(raw)
        cases = []
        for field in ("inventory", "storage", "template", "ha"):
            value = copy.deepcopy(frozen)
            del value["preflight"][field]
            cases.append(value)
        value = copy.deepcopy(frozen)
        value["preflight"]["template"]["sha256"] = "0" * 64
        cases.append(value)
        value = copy.deepcopy(frozen)
        value["preflight"]["template"]["identity"][6] += 1
        cases.append(value)
        value = copy.deepcopy(frozen)
        value["preflight"]["storage"]["path"] = "/srv/foreign"
        cases.append(value)
        value = copy.deepcopy(frozen)
        value["preflight"]["inventory"][0]["vmid"] = 102
        cases.append(value)
        value = copy.deepcopy(frozen)
        value["preflight"]["inventory"][0]["status"] = "running"
        cases.append(value)
        for value in cases:
            changed = state.canonical(value)
            with self.assertRaises(state.PersistenceError):
                recipient.load_prepared(changed, state.sha256(changed))
        self.assertFalse(recipient.RUNTIME_ROOT.exists())

    def test_lost_ack_is_consumed_and_status_never_reposts(self):
        raw, trusted = self.prepared()
        with mock.patch.object(
            recipient, "post_create", side_effect=OSError("lost response")
        ) as post:
            with self.assertRaises(OSError):
                recipient.provision(raw, trusted)
            result = recipient.status(raw, trusted)
        self.assertEqual(post.call_count, 1)
        self.assertFalse(result["provisioned_verified"])
        self.assertEqual(result["phase"], "create-uncertain")
        self.assertTrue(any(recipient.RUNTIME_ROOT.rglob("failed.json")))
        self.assertFalse(any(recipient.RUNTIME_ROOT.rglob("complete.json")))

    def test_known_native_warning_is_separate_from_target_verification(self):
        raw, trusted = self.prepared()
        self.task["exitstatus"] = "WARNINGS: 1"
        self.log = [
            {"n": 1, "t": "extracting qualified archive"},
            {"n": 2, "t": recipient.WARNING},
            {"n": 3, "t": "TASK WARNINGS: 1"},
        ]
        result = recipient.provision(raw, trusted)
        self.assertTrue(result["provisioned_verified"])
        self.assertEqual(result["native_outcome"]["warning_count"], 1)
        self.assertEqual(result["log"], self.log)

    def test_failed_or_unknown_warning_cannot_reach_target_success(self):
        raw, trusted = self.prepared()
        self.task["exitstatus"] = "WARNINGS: 1"
        self.log = [{"n": 1, "t": "WARN: unknown"}, {"n": 2, "t": "TASK WARNINGS: 1"}]
        with mock.patch.object(recipient, "verify_target") as verify:
            with self.assertRaises(state.PersistenceError):
                recipient.provision(raw, trusted)
        verify.assert_not_called()
        self.assertEqual(len(self.posts), 1)

    def test_rejected_closing_log_cannot_publish_success(self):
        raw, trusted = self.prepared()
        bad = [{"n": 1, "t": "ERROR: newly observed failure"}, {"n": 2, "t": "TASK OK"}]
        with mock.patch.object(
            recipient,
            "task_state",
            side_effect=[(self.task, self.log), (self.task, bad)],
        ):
            with self.assertRaises(state.PersistenceError):
                recipient.provision(raw, trusted)
        self.assertFalse(any(recipient.RUNTIME_ROOT.rglob("complete.json")))
        self.assertTrue(any(recipient.RUNTIME_ROOT.rglob("failed.json")))

    def test_target_change_during_source_closure_cannot_publish_success(self):
        raw, trusted = self.prepared()

        @contextmanager
        def source_closes_after_target_read(*args, **kwargs):
            self.inside_lock = True
            try:
                yield copy.deepcopy(self.facts)
            finally:
                self.inside_lock = False
                self.after["status"] = {"status": "running", "pid": 321}

        with mock.patch.object(
            recipient.observe,
            "source_state",
            side_effect=source_closes_after_target_read,
        ):
            with self.assertRaises(state.PersistenceError):
                recipient.provision(raw, trusted)
        self.assertFalse(any(recipient.RUNTIME_ROOT.rglob("complete.json")))
        self.assertTrue(any(recipient.RUNTIME_ROOT.rglob("failed.json")))

    def test_target_alias_running_source_boolean_vmid_and_template_traversal_refuse(
        self,
    ):
        cases = []
        for vmid in (True, 101):
            value = copy.deepcopy(self.request)
            value["target"]["vmid"] = vmid
            cases.append(value)
        value = copy.deepcopy(self.request)
        value["template"]["volume"] = "local:vztmpl/../foreign.tar.zst"
        cases.append(value)
        value = copy.deepcopy(self.request)
        value["target"]["generation_tag"] = value["source_request"]["source"][
            "generation_tag"
        ]
        cases.append(value)
        for value in cases:
            with self.assertRaises(state.PersistenceError):
                recipient.prepare(value)
        self.facts["quiesced"] = False
        with self.assertRaises(state.PersistenceError):
            recipient.prepare(self.request)
        self.assertFalse(recipient.RUNTIME_ROOT.exists())


class NativeShapeTests(unittest.TestCase):
    def test_storage_content_order_is_not_drift_but_membership_and_other_fields_are(
        self,
    ):
        original = {
            "type": "dir",
            "path": "/var/lib/vz",
            "content": "rootdir,backup,vztmpl,images,iso,snippets",
            "digest": "a" * 40,
        }
        reordered = {**original, "content": "iso,backup,vztmpl,images,snippets,rootdir"}
        self.assertEqual(
            recipient.normalize_storage(original),
            recipient.normalize_storage(reordered),
        )
        self.assertEqual(
            original["content"], "rootdir,backup,vztmpl,images,iso,snippets"
        )
        self.assertNotEqual(
            recipient.normalize_storage(original),
            recipient.normalize_storage({**original, "content": "rootdir,vztmpl"}),
        )
        self.assertNotEqual(
            recipient.normalize_storage(original),
            recipient.normalize_storage({**original, "path": "/srv/foreign"}),
        )
        for invalid in (
            "rootdir,rootdir,vztmpl",
            "rootdir,,vztmpl",
            " rootdir,vztmpl",
            None,
        ):
            with self.assertRaises(state.PersistenceError):
                recipient.normalize_storage({**original, "content": invalid})

    def test_target_starting_during_filesystem_probe_is_not_a_stopped_recipient(self):
        request = example_request()
        request["source_request"]["policy"] = {"rootfs": {"uuid": "source-uuid"}}
        expected = recipient.create_request(request)
        config = {key: expected[key] for key in ("hostname", "description", "tags")}
        config.update(
            arch="amd64",
            ostype="ubuntu",
            cores=1,
            cpulimit=1,
            memory=512,
            swap=0,
            unprivileged=1,
            onboot=0,
            protection=1,
            rootfs="local:102/vm-102-disk-0.raw,size=2G",
        )
        current = {"status": "stopped", "pid": 0, "uptime": 0}

        def get(path, *args):
            if path.endswith("/status/current"):
                return copy.deepcopy(current)
            if path.endswith("/config"):
                return copy.deepcopy(config)
            if path.endswith("/pending"):
                return []
            raise AssertionError(path)

        def native(argv):
            if argv[0] == "/usr/sbin/pvesm":
                return b"/var/lib/vz/images/102/vm-102-disk-0.raw\n"
            current.update(status="running", pid=321, uptime=1)
            return b"TYPE=ext4\nUUID=44444444-4444-4444-4444-444444444444\n"

        info = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            st_size=2 * 1024**3,
            st_dev=7,
            st_ino=88,
            st_mtime_ns=1,
            st_ctime_ns=1,
        )

        class FakePath:
            def __init__(self, value):
                self.value = str(value)

            def __truediv__(self, other):
                return FakePath(self.value + "/" + str(other))

            def __eq__(self, other):
                return isinstance(other, FakePath) and self.value == other.value

            def __str__(self):
                return self.value

            def resolve(self, strict=True):
                return self

            def lstat(self):
                return info

        with mock.patch.object(recipient, "get", side_effect=get), mock.patch.object(
            recipient.observe, "native", side_effect=native
        ), mock.patch.object(recipient, "Path", FakePath):
            with self.assertRaises(state.PersistenceError):
                REAL_VERIFY(request, {})

    def test_target_config_refuses_any_network_bind_raw_feature_lock_or_limit_drift(
        self,
    ):
        request = example_request()
        expected = recipient.create_request(request)
        config = {key: expected[key] for key in ("description", "hostname", "tags")}
        config.update(
            {
                key: int(expected[key])
                for key in (
                    "cores",
                    "cpulimit",
                    "memory",
                    "swap",
                    "unprivileged",
                    "onboot",
                    "protection",
                )
            }
        )
        config.update(
            arch="amd64", ostype="ubuntu", rootfs="local:102/vm-102-disk-0.raw,size=2G"
        )
        self.assertEqual(
            recipient.validate_target_config(request, config),
            "local:102/vm-102-disk-0.raw",
        )
        # PVE's actual config reader terminates a stored description with LF.
        self.assertEqual(
            recipient.validate_target_config(
                request, {**config, "description": config["description"] + "\n"}
            ),
            "local:102/vm-102-disk-0.raw",
        )
        self.assertEqual(
            recipient.validate_target_config(request, {**config, "cpulimit": "1"}),
            "local:102/vm-102-disk-0.raw",
        )
        for key, value in (
            ("net0", "name=eth0,bridge=vmbr0"),
            ("mp0", "/srv/data,mp=/var/lib/reference-ledger"),
            ("features", "nesting=1"),
            ("hookscript", "local:snippets/run.pl"),
            ("lxc", []),
            ("lock", "create"),
            ("cpulimit", 0),
            ("cpulimit", True),
            ("cpulimit", "0"),
            ("cpulimit", "01"),
            ("cpulimit", "1.0"),
            ("cpulimit", "NaN"),
            ("onboot", 1),
            ("unprivileged", 0),
            ("rootfs", "local:101/vm-101-disk-0.raw,size=2G"),
            ("description", config["description"] + "\n\n"),
            ("description", config["description"] + " modified\n"),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(
                state.PersistenceError
            ):
                recipient.validate_target_config(request, {**config, key: value})

    def test_pending_order_is_semantic_but_values_and_unsafe_rows_are_not(self):
        rows = [
            {"key": "rootfs", "value": "local:102/vm-102-disk-0.raw,size=2G"},
            {"key": "memory", "value": 512},
        ]
        self.assertEqual(
            recipient.ordered_pending(rows),
            recipient.ordered_pending(list(reversed(rows))),
        )
        self.assertNotEqual(
            recipient.ordered_pending(rows),
            recipient.ordered_pending([{**rows[0], "value": "foreign"}, rows[1]]),
        )
        for invalid in (
            [*rows, rows[0]],
            [{**rows[0], "pending": "foreign"}],
            [{**rows[0], "delete": 1}],
            [{"value": 512}],
            "not-list",
        ):
            with self.assertRaises(state.PersistenceError):
                recipient.ordered_pending(invalid)

    def test_upid_is_bound_to_node_target_operation_and_user(self):
        request = example_request()
        good = "UPID:node-a:00000010:00000020:00000030:vzcreate:102:root@pam:"
        self.assertEqual(recipient.parse_upid(request, good)["id"], "102")
        for wrong in (
            good.replace("node-a", "node-b"),
            good.replace(":102:", ":101:"),
            good.replace("vzcreate", "vzstart"),
            good.replace("root@pam", "other@pam"),
            good.replace("00000010", "00000000"),
        ):
            with self.assertRaises(state.PersistenceError):
                recipient.parse_upid(request, wrong)

    def test_native_warning_count_truncation_errors_and_unknown_warnings_refuse(self):
        task = {"status": "stopped", "exitstatus": "WARNINGS: 1"}
        good = [
            {"n": 1, "t": "formatting owned rootfs"},
            {"n": 2, "t": recipient.WARNING},
            {"n": 3, "t": "TASK WARNINGS: 1"},
        ]
        self.assertTrue(recipient.native_outcome(task, good)["accepted"])
        for wrong in (
            good[:-1],
            [{"n": 1, "t": "WARN: other"}, good[-1]],
            [{"n": 1, "t": "ERROR: setup failed"}, *good[1:]],
            [*good[:2], {"n": 3, "t": "TASK WARNINGS: 2"}],
        ):
            try:
                result = recipient.native_outcome(task, wrong)
            except state.PersistenceError:
                continue
            self.assertFalse(result["accepted"])


class CreateWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        cls.tmp = tempfile.TemporaryDirectory(
            dir=ROOT / ".generated", prefix="recipient-https-"
        )
        cls.root = Path(cls.tmp.name)
        cls.cert, cls.key = cls.root / "cert.pem", cls.root / "key.pem"
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
                str(cls.cert),
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
            umask=0o077,
        )

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @contextmanager
    def server(self, code=200):
        requests = []
        upid = "UPID:localhost:00000010:00000020:00000030:vzcreate:102:root@pam:"

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                size = int(self.headers["Content-Length"])
                body = self.rfile.read(size)
                requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "parameters": parse_qs(body.decode()),
                        "cookie": self.headers.get("Cookie"),
                        "csrf": self.headers.get("CSRFPreventionToken"),
                    }
                )
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {"data": upid}
                        if code == 200
                        else {"error": "PRIVATE_SERVER_SENTINEL"}
                    ).encode()
                )

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_port, requests
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def call(self, port, *, node="localhost", bad_leaf=False):
        request = example_request()
        raw = self.cert.read_bytes()
        fingerprint = state.sha256(ssl.PEM_cert_to_DER_cert(raw.decode()))
        request["source_request"]["source"]["selector"]["node"] = node
        request["source_request"]["source"]["host_profile"].update(
            ca_certificate_sha256=fingerprint,
            leaf_certificate_sha256="0" * 64 if bad_leaf else fingerprint,
        )
        connect = socket.create_connection

        def redirected(address, timeout):
            self.assertEqual(address, ("127.0.0.1", 8006))
            return connect(("127.0.0.1", port), timeout=timeout)

        credentials = {
            "ticket": "PVE:root@pam:PRIVATE_TICKET_SENTINEL",
            "csrf": "PRIVATE_CSRF_SENTINEL",
        }
        with mock.patch.object(
            recipient.observe, "read_regular", return_value=(raw, None)
        ), mock.patch.object(
            recipient.subprocess,
            "run",
            return_value=SimpleNamespace(
                returncode=0, stdout=json.dumps(credentials).encode(), stderr=b""
            ),
        ) as auth, mock.patch.object(
            recipient.socket, "create_connection", side_effect=redirected
        ):
            result = REAL_POST(request)
        self.assertEqual(
            auth.call_args.args[0],
            [
                "/usr/bin/perl",
                "-MPVE::AccessControl",
                "-MJSON::PP",
                "-e",
                recipient.TICKET_PROGRAM,
            ],
        )
        return result, recipient.create_request(request)

    def test_real_verified_tls_post_sends_only_the_fixed_stopped_create(self):
        with self.server() as (port, requests):
            result, expected = self.call(port)
        self.assertTrue(result["tls_verified"])
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["path"], "/api2/json/nodes/localhost/lxc")
        self.assertEqual(
            requests[0]["parameters"], {key: [value] for key, value in expected.items()}
        )
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_wrong_leaf_or_hostname_cannot_send_create_credentials(self):
        for node, bad_leaf in (("localhost", True), ("wrong.example", False)):
            with self.server() as (port, requests):
                with self.assertRaises(
                    (state.PersistenceError, ssl.SSLCertVerificationError)
                ):
                    self.call(port, node=node, bad_leaf=bad_leaf)
            self.assertEqual(requests, [])

    def test_server_failure_is_opaque_and_never_followed_or_retried(self):
        with self.server(302) as (port, requests):
            with self.assertRaises(state.PersistenceError) as failed:
                self.call(port)
        self.assertEqual(len(requests), 1)
        self.assertNotIn("PRIVATE", str(failed.exception))


if __name__ == "__main__":
    unittest.main()
