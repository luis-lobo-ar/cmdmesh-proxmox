"""Recorded native response observations are not certified acknowledgements."""

import copy
from dataclasses import asdict
import importlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_guest_api as api,
)


class OwnerAckTests(unittest.TestCase):
    def setUp(self):
        self.codec = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_ack"
        )
        self.binding = api.GuestBinding(
            "pve-example", 102, "1" * 64, "2" * 64, "3" * 64
        )
        self.dispatch = "d" * 64
        self.epoch = {
            "boot_id": "11111111-2222-3333-4444-555555555555",
            "mount_namespace": "mnt:[123]",
        }
        self.send = self.clock(161_000_000_000)
        self.receive = self.clock(161_200_000_000)
        self.upid = self.task(1700000161)

    def clock(self, tick):
        return {
            "epoch": copy.deepcopy(self.epoch),
            "wall_ns": 1700000000 * 10**9 + tick + 500,
            "monotonic_before_ns": tick,
            "monotonic_after_ns": tick + 1000,
        }

    def task(self, second, *, node="pve-example", vmid=102, kind="vzstart"):
        return f"UPID:{node}:00000010:00000020:{second:08X}:{kind}:{vmid}:root@pam:"

    def observation(self, **overrides):
        fields = {
            "tls_verified": True,
            "tls_peer_sha256": self.binding.leaf_sha256,
            "tls_version": "TLSv1.3",
            "http_status": 200,
            "content_type": "application/json; charset=utf-8",
            "body": json.dumps({"data": self.upid}).encode(),
        }
        fields.update(overrides)
        return self.codec.observe_response(
            self.binding, "start", self.dispatch, self.send, self.receive, **fields
        )

    def validate(self, value):
        return self.codec.validate_ack(
            self.binding, "start", self.dispatch, self.epoch, value
        )

    def test_fresh_task_is_bound_to_actual_interval_after_long_earlier_work(self):
        value = self.observation()
        result = self.validate(value)
        self.assertEqual(result["upid"], self.upid)
        self.assertIs(result["tls_verified"], True)
        self.assertEqual(
            result["observation_sha256"], api.state.sha256(api.state.canonical(value))
        )
        self.assertEqual(value["binding"], asdict(self.binding))

    def test_integer_task_second_may_overlap_a_subsecond_request(self):
        self.send = self.clock(161_900_000_000)
        self.receive = self.clock(161_950_000_000)
        self.assertEqual(self.validate(self.observation())["upid"], self.upid)

    def test_stale_and_future_tasks_are_retained_but_not_certified(self):
        for second in (1700000160, 1700000162):
            with self.subTest(second=second):
                self.upid = self.task(second)
                value = self.observation()
                self.assertIn(self.upid, value["response"]["safe_body"])
                self.codec.validate_observation(value)
                with self.assertRaises(ValueError):
                    self.validate(value)

    def test_wrong_target_kind_tls_or_dispatch_cannot_certify(self):
        for changes in (
            {
                "body": json.dumps(
                    {"data": self.task(1700000161, node="pve-other")}
                ).encode()
            },
            {"body": json.dumps({"data": self.task(1700000161, vmid=103)}).encode()},
            {
                "body": json.dumps(
                    {"data": self.task(1700000161, kind="vzshutdown")}
                ).encode()
            },
            {"tls_verified": False},
            {"tls_peer_sha256": "f" * 64},
            {"tls_version": "TLSv1.1"},
            {"http_status": 503},
            {"content_type": "text/plain"},
        ):
            with self.subTest(changes=changes):
                value = self.observation(**changes)
                self.codec.validate_observation(value)
                with self.assertRaises(ValueError):
                    self.validate(value)
        value = self.observation()
        value["dispatch_sha256"] = "e" * 64
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_clock_or_epoch_discontinuity_stays_observed_only(self):
        for field, replacement in (
            ("wall_ns", self.send["wall_ns"] - 1),
            ("wall_ns", self.receive["wall_ns"] + 10**9),
            ("monotonic_before_ns", self.send["monotonic_before_ns"] - 1),
            ("monotonic_after_ns", self.receive["monotonic_before_ns"] - 1),
            ("monotonic_after_ns", self.receive["monotonic_before_ns"] + 10**9),
            ("epoch", {**self.epoch, "mount_namespace": "mnt:[124]"}),
            (
                "epoch",
                {**self.epoch, "boot_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
            ),
        ):
            with self.subTest(field=field, replacement=replacement):
                saved = copy.deepcopy(self.receive)
                self.receive[field] = replacement
                value = self.observation()
                self.codec.validate_observation(value)
                with self.assertRaises(ValueError):
                    self.validate(value)
                self.receive = saved
        self.receive = None
        value = self.observation()
        self.assertIn(self.upid, value["response"]["safe_body"])
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_coherent_other_action_cannot_replace_the_expected_action(self):
        value = self.observation(
            body=json.dumps({"data": self.task(1700000161, kind="vzshutdown")}).encode()
        )
        value["action"] = "shutdown"
        self.codec.validate_observation(value)
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_unsafe_bodies_and_headers_never_enter_plaintext_observation(self):
        for body in (
            b'{"ticket":"PRIVATE_TICKET","csrf":"PRIVATE_CSRF"}',
            b'{"data":"PRIVATE_TICKET"}',
            b'{"data":"PRIVATE_TICKET","data":"PRIVATE_CSRF"}',
            b"PRIVATE_TICKET",
        ):
            with self.subTest(body=body):
                value = self.observation(body=body, content_type="PRIVATE_CSRF")
                encoded = api.state.canonical(value)
                self.assertNotIn(b"PRIVATE_TICKET", encoded)
                self.assertNotIn(b"PRIVATE_CSRF", encoded)
                self.assertIsNone(value["response"]["safe_body"])
                self.assertEqual(
                    value["response"]["body_sha256"], api.state.sha256(body)
                )
                with self.assertRaises(ValueError):
                    self.validate(value)

    def test_truncated_lost_or_oversized_body_cannot_certify(self):
        for changes in (
            {"body": None},
            {"body_complete": False},
            {"body": b"x" * 262145},
        ):
            with self.subTest(changes=changes):
                value = self.observation(**changes)
                self.codec.validate_observation(value)
                self.assertIsNone(value["response"]["safe_body"])
                with self.assertRaises(ValueError):
                    self.validate(value)
        with self.assertRaises(ValueError):
            self.observation(body=b"x" * 262146)

    def test_strict_types_and_safe_body_hash_binding(self):
        for path, replacement in (
            (("schema_version",), True),
            (("schema_version",), 1.0),
            (("send", "wall_ns"), True),
            (("send", "wall_ns"), 1.5),
            (("tls", "verified"), 1),
            (("response", "http_status"), True),
            (("response", "body_sha256"), "f" * 64),
            (("response", "body_length"), 1),
            (("response", "safe_body"), '{"data":"PRIVATE_TICKET"}'),
        ):
            with self.subTest(path=path):
                value = self.observation()
                target = value
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = replacement
                with self.assertRaises(ValueError):
                    self.validate(value)
        value = self.observation()
        value["foreign"] = True
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_historical_validation_has_no_io_or_present_clock_dependency(self):
        value = self.observation()
        saved = copy.deepcopy(value)
        with mock.patch.object(
            api, "post_guest_action", side_effect=AssertionError("POST")
        ), mock.patch.object(
            api, "get", side_effect=AssertionError("GET")
        ), mock.patch.object(
            api, "check_host", side_effect=AssertionError("host")
        ), mock.patch(
            "time.time", side_effect=AssertionError("present clock")
        ), mock.patch(
            "builtins.open", side_effect=AssertionError("file")
        ):
            self.validate(value)
        self.assertEqual(value, saved)

    def test_late_observation_or_expected_epoch_mutation_cannot_certify(self):
        original = api.parse_upid
        for target in ("observation", "expected-epoch"):
            with self.subTest(target=target):
                value = self.observation()
                expected = copy.deepcopy(self.epoch)

                def late(*args, **kwargs):
                    result = original(*args, **kwargs)
                    if target == "observation":
                        value["dispatch_sha256"] = "e" * 64
                    else:
                        expected["mount_namespace"] = "mnt:[124]"
                    return result

                with mock.patch.object(api, "parse_upid", side_effect=late):
                    with self.assertRaises(ValueError):
                        self.codec.validate_ack(
                            self.binding, "start", self.dispatch, expected, value
                        )

    def test_malformed_tls_versions_have_typed_refusal(self):
        for version in ([], {}, True, 1):
            with self.subTest(version=version):
                value = self.observation()
                value["tls"]["version"] = version
                with self.assertRaises(ValueError):
                    self.validate(value)


if __name__ == "__main__":
    unittest.main()
