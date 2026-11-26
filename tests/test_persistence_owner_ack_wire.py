"""One real local TLS request captures an unqualified, privacy-safe response."""

import copy
import http.client
import io
import json
from pathlib import Path
import socket
import ssl
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_guest_api as api,
    persistence_owner_ack as codec,
)
import test_persistence_recipient as legacy
import test_persistence_owner_ack as ack_fixtures


class ObservedOwnerWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        legacy.CreateWireTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        legacy.CreateWireTests.tearDownClass.__func__(cls)

    server = legacy.CreateWireTests.server
    epoch = {
        "boot_id": "11111111-2222-3333-4444-555555555555",
        "mount_namespace": "mnt:[123]",
    }

    def call(
        self,
        port,
        requests,
        operation="start",
        *,
        bad_leaf=False,
        receive_error=False,
        partial=False,
        bad_send=False,
    ):
        source = copy.deepcopy(legacy.example_request()["source_request"]["source"])
        source["selector"].update(vmid=102, node="localhost")
        cert = self.cert.read_bytes()
        fingerprint = api.state.sha256(ssl.PEM_cert_to_DER_cert(cert.decode()))
        source["host_profile"].update(
            ca_certificate_sha256=fingerprint,
            leaf_certificate_sha256="0" * 64 if bad_leaf else fingerprint,
        )
        binding = api.GuestBinding.from_source(source)
        original_connect, original_context = (
            socket.create_connection,
            ssl.create_default_context,
        )
        events = {"auth": False, "tls": False, "samples": 0}

        def redirected(address, timeout):
            self.assertEqual(address, ("127.0.0.1", 8006))
            return original_connect(("127.0.0.1", port), timeout=timeout)

        def authentication(*args, **kwargs):
            events["auth"] = True
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {"ticket": "PVE:root@pam:PRIVATE_TICKET", "csrf": "PRIVATE_CSRF"}
                ).encode(),
                stderr=b"",
            )

        class Context:
            def __init__(self, inner):
                self.inner = inner

            def __getattr__(self, name):
                return getattr(self.inner, name)

            def wrap_socket(self, *args, **kwargs):
                secure = self.inner.wrap_socket(*args, **kwargs)
                events["tls"] = True
                return secure

        def sample():
            self.assertTrue(events["auth"])
            self.assertTrue(events["tls"])
            self.assertEqual(len(requests), events["samples"])
            tick = events["samples"] * 200_000_000
            events["samples"] += 1
            if events["samples"] == 2 and receive_error:
                raise ValueError("synthetic receive clock unavailable")
            value = {
                "epoch": copy.deepcopy(self.epoch),
                "wall_ns": 48 * 10**9 + tick + 500,
                "monotonic_before_ns": 100_000_000 + tick,
                "monotonic_after_ns": 100_001_000 + tick,
            }
            if bad_send and events["samples"] == 1:
                value["monotonic_after_ns"] = value["monotonic_before_ns"] - 1
            return value

        with mock.patch.object(api, "check_host"), mock.patch.object(
            api.observe, "read_regular", return_value=(cert, None)
        ), mock.patch.object(
            api.subprocess, "run", side_effect=authentication
        ), mock.patch.object(
            api.socket, "create_connection", side_effect=redirected
        ), mock.patch.object(
            api.ssl,
            "create_default_context",
            side_effect=lambda **kw: Context(original_context(**kw)),
        ), mock.patch.object(
            api, "_owner_clock", side_effect=sample, create=True
        ):
            if partial:
                with mock.patch.object(
                    api.http.client.HTTPResponse,
                    "read",
                    side_effect=http.client.IncompleteRead(b"PRIVATE_PARTIAL", 1),
                ):
                    result = api.post_owner_guest_action(
                        binding, operation, "d" * 64, self.epoch
                    )
            else:
                result = api.post_owner_guest_action(
                    binding, operation, "d" * 64, self.epoch
                )
        return result, binding, events

    def test_fixed_actions_capture_clocks_after_auth_tls_and_one_request(self):
        for action in ("start", "shutdown"):
            with self.subTest(action=action), self.server() as (port, requests):
                observed, binding, events = self.call(port, requests, action)
            self.assertEqual(len(requests), 1)
            self.assertEqual(events["samples"], 2)
            self.assertEqual(
                requests[0]["path"],
                "/api2/json/nodes/localhost/lxc/102/status/" + action,
            )
            codec.validate_observation(observed)
            qualified = codec.validate_ack(
                binding, action, "d" * 64, self.epoch, observed
            )
            self.assertIs(qualified["tls_verified"], True)
            self.assertNotIn("PRIVATE", json.dumps(observed))

    def test_wrong_peer_stops_before_post_or_clock_observation(self):
        with self.server() as (port, requests):
            with self.assertRaises(ValueError):
                self.call(port, requests, bad_leaf=True)
        self.assertEqual(requests, [])

    def test_redirect_is_observed_without_following_or_plaintext_server_body(self):
        with self.server(302) as (port, requests):
            observed, binding, _ = self.call(port, requests)
        self.assertEqual(len(requests), 1)
        self.assertEqual(observed["response"]["http_status"], 302)
        self.assertIsNone(observed["response"]["safe_body"])
        self.assertNotIn("PRIVATE", json.dumps(observed))
        with self.assertRaises(ValueError):
            codec.validate_ack(binding, "start", "d" * 64, self.epoch, observed)

    def test_received_ack_survives_missing_receive_clock_as_unqualified(self):
        with self.server() as (port, requests):
            observed, binding, _ = self.call(port, requests, receive_error=True)
        self.assertEqual(len(requests), 1)
        self.assertIsNone(observed["receive"])
        self.assertIn("UPID:", observed["response"]["safe_body"])
        with self.assertRaises(ValueError):
            codec.validate_ack(binding, "start", "d" * 64, self.epoch, observed)

    def test_partial_response_retains_only_bounded_hash_without_retry(self):
        with self.server() as (port, requests):
            observed, binding, _ = self.call(port, requests, partial=True)
        self.assertEqual(len(requests), 1)
        self.assertIs(observed["response"]["body_complete"], False)
        self.assertIsNone(observed["response"]["safe_body"])
        self.assertNotIn("PRIVATE_PARTIAL", json.dumps(observed))
        self.assertEqual(
            observed["response"]["body_sha256"], api.state.sha256(b"PRIVATE_PARTIAL")
        )
        with self.assertRaises(ValueError):
            codec.validate_ack(binding, "start", "d" * 64, self.epoch, observed)

    def test_invalid_send_sample_refuses_before_post(self):
        with self.server() as (port, requests):
            with self.assertRaises(ValueError):
                self.call(port, requests, bad_send=True)
        self.assertEqual(requests, [])

    def test_clock_capture_preserves_typed_uncertainty_for_later_observation(self):
        with mock.patch.object(
            api.Path, "read_text", return_value=self.epoch["boot_id"]
        ), mock.patch.object(
            api.os, "readlink", return_value=self.epoch["mount_namespace"]
        ), mock.patch.object(
            api.time, "time_ns", return_value=48 * 10**9
        ), mock.patch.object(
            api.time, "monotonic_ns", side_effect=[10**9, 10**9 + 200_000_000]
        ):
            sample = api._owner_clock()
        codec.clock_shape(sample)
        self.assertEqual(
            sample["monotonic_after_ns"] - sample["monotonic_before_ns"], 200_000_000
        )


class ObservedOwnerFramingTests(unittest.TestCase):
    def call(self, framing, *, legacy_action=False):
        fixture = ack_fixtures.OwnerAckTests()
        fixture.setUp()
        body = json.dumps({"data": fixture.upid}).encode()
        if framing == "short-length":
            headers = b"Content-Length: " + str(len(body) + 31).encode() + b"\r\n"
            encoded = body
        elif framing == "length":
            headers = b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            encoded = body
        elif framing in {"chunked", "short-chunked"}:
            headers = b"Transfer-Encoding: chunked\r\n"
            encoded = f"{len(body):X}\r\n".encode() + body + b"\r\n"
            if framing == "chunked":
                encoded += b"0\r\n\r\n"
        else:
            self.assertEqual(framing, "close")
            headers, encoded = b"", body
        raw = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + headers
            + b"Connection: close\r\n\r\n"
            + encoded
        )

        class Wire:
            def makefile(self, *args):
                return io.BytesIO(raw)

        response = http.client.HTTPResponse(Wire())
        response.begin()
        leaf = b"synthetic-certificate"
        fingerprint = api.state.sha256(leaf)
        binding = api.GuestBinding(
            "pve-example", 102, "1" * 64, fingerprint, fingerprint
        )

        class Secure:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def getpeercert(self, **kwargs):
                return leaf

            def version(self):
                return "TLSv1.3"

        class Context:
            verify_mode = ssl.CERT_REQUIRED
            check_hostname = True

            def wrap_socket(self, *args, **kwargs):
                return Secure()

        with mock.patch.object(api, "check_host"), mock.patch.object(
            api.observe, "read_regular", return_value=(b"PEM", None)
        ), mock.patch.object(
            api.ssl, "PEM_cert_to_DER_cert", return_value=leaf
        ), mock.patch.object(
            api.ssl, "create_default_context", return_value=Context()
        ), mock.patch.object(
            api.subprocess,
            "run",
            return_value=SimpleNamespace(
                returncode=0,
                stderr=b"",
                stdout=b'{"ticket":"PVE:root@pam:PRIVATE","csrf":"PRIVATE"}',
            ),
        ), mock.patch.object(
            api.socket, "create_connection", return_value=Secure()
        ), mock.patch.object(
            api.http.client.HTTPConnection, "request"
        ) as request, mock.patch.object(
            api.http.client.HTTPConnection, "getresponse", return_value=response
        ), mock.patch.object(
            api, "_owner_clock", side_effect=[fixture.send, fixture.receive]
        ):
            if legacy_action:
                return api.post_guest_action(binding, "start")
            observed = api.post_owner_guest_action(
                binding, "start", fixture.dispatch, fixture.epoch
            )
        self.assertEqual(request.call_count, 1)
        return observed, binding, fixture

    def test_short_content_length_valid_json_is_not_a_complete_ack(self):
        observed, binding, fixture = self.call("short-length")
        self.assertIs(observed["response"]["body_complete"], False)
        self.assertIsNone(observed["response"]["safe_body"])
        with self.assertRaises(ValueError):
            codec.validate_ack(
                binding, "start", fixture.dispatch, fixture.epoch, observed
            )

    def test_valid_length_chunked_and_close_framing_still_qualify(self):
        for framing in ("length", "chunked", "close"):
            with self.subTest(framing=framing):
                observed, binding, fixture = self.call(framing)
                self.assertIs(observed["response"]["body_complete"], True)
                codec.validate_ack(
                    binding, "start", fixture.dispatch, fixture.epoch, observed
                )

    def test_missing_terminal_chunk_is_not_complete(self):
        observed, binding, fixture = self.call("short-chunked")
        self.assertIs(observed["response"]["body_complete"], False)
        self.assertIsNone(observed["response"]["safe_body"])

    def test_legacy_action_also_refuses_short_declared_body(self):
        with self.assertRaises(ValueError):
            self.call("short-length", legacy_action=True)


if __name__ == "__main__":
    unittest.main()
