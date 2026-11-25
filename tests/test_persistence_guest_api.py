"""Current owners use finite verified guest actions without fake recipient context."""

import copy
from dataclasses import FrozenInstanceError, replace
import json
import os
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
)
import test_persistence_recipient as legacy


class GuestBindingTests(unittest.TestCase):
    def test_shared_task_status_validation_is_pure_and_keeps_exact_identity(self):
        binding = api.GuestBinding("pve-example", 102, "1" * 64, "2" * 64, "3" * 64)
        upid = "UPID:pve-example:00000010:00000020:6553F100:vzshutdown:102:root@pam:"
        task = {
            **api.parse_upid(binding, upid, kind="vzshutdown"),
            "status": "stopped",
            "exitstatus": "OK",
        }
        with mock.patch.object(
            api, "get", side_effect=AssertionError("pure GET")
        ), mock.patch.object(
            api, "check_host", side_effect=AssertionError("pure host")
        ):
            api.validate_task_status(binding, upid, task, kind="vzshutdown")
            for key, value in (
                ("id", "103"),
                ("pid", True),
                ("status", "unknown"),
                ("status", []),
            ):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    api.validate_task_status(
                        binding, upid, dict(task, **{key: value}), kind="vzshutdown"
                    )

    def setUp(self):
        request = legacy.example_request()
        self.source = copy.deepcopy(request["source_request"]["source"])
        self.source["selector"]["vmid"] = request["target"]["vmid"]
        self.source["generation_tag"] = request["target"]["generation_tag"]

    def test_current_source_is_bound_directly_without_old_source_target_alias(self):
        binding = api.GuestBinding.from_source(self.source)
        self.assertEqual(binding.vmid, 102)
        self.assertEqual(binding.node, self.source["selector"]["node"])
        with self.assertRaises(FrozenInstanceError):
            binding.vmid = 103
        for field, value in (
            ("vmid", True),
            ("vmid", 99),
            ("node", "../other"),
            ("machine_id_sha256", "bad"),
            ("leaf_sha256", "f" * 63),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                replace(binding, **{field: value})

    def test_wrong_host_refuses_before_ticket_or_socket(self):
        binding = api.GuestBinding.from_source(self.source)
        with mock.patch.object(api.os, "geteuid", return_value=0), mock.patch.object(
            api.socket, "gethostname", return_value="other-node"
        ), mock.patch.object(api.subprocess, "run") as auth, mock.patch.object(
            api.socket, "create_connection"
        ) as connect:
            with self.assertRaises(ValueError):
                api.post_guest_action(binding, "start")
        auth.assert_not_called()
        connect.assert_not_called()

    def test_wrong_machine_refuses_before_ticket_or_socket(self):
        binding = api.GuestBinding.from_source(self.source)
        with mock.patch.object(api.os, "geteuid", return_value=0), mock.patch.object(
            api.socket, "gethostname", return_value=binding.node
        ), mock.patch.object(
            api.observe, "read_regular", return_value=(b"1" * 32, None)
        ), mock.patch.object(
            api.subprocess, "run"
        ) as auth, mock.patch.object(
            api.socket, "create_connection"
        ) as connect:
            with self.assertRaises(ValueError):
                api.post_guest_action(binding, "start")
        auth.assert_not_called()
        connect.assert_not_called()

    def test_unknown_action_and_wrong_source_kind_refuse_before_io(self):
        binding = api.GuestBinding.from_source(self.source)
        with mock.patch.object(api, "check_host") as host:
            for action in ("create", "stop", "reboot", "destroy", "../start", None):
                with self.subTest(action=action), self.assertRaises(ValueError):
                    api.post_guest_action(binding, action)
        host.assert_not_called()
        self.source["selector"]["kind"] = "proxmox.qemu"
        with self.assertRaises(ValueError):
            api.GuestBinding.from_source(self.source)

    def test_exact_host_machine_fingerprint_reaches_only_the_finite_transport(self):
        machine = b"1" * 32
        self.source["host_profile"]["machine_id_sha256"] = api.state.sha256(machine)
        binding = api.GuestBinding.from_source(self.source)
        with mock.patch.object(api.os, "geteuid", return_value=0), mock.patch.object(
            api.socket, "gethostname", return_value=binding.node
        ), mock.patch.object(
            api.observe, "read_regular", return_value=(machine + b"\n", None)
        ), mock.patch.object(
            api, "_post_bound", return_value={"tls_verified": True}
        ) as transport:
            self.assertEqual(
                api.post_guest_action(binding, "start"), {"tls_verified": True}
            )
        transport.assert_called_once_with(binding, "start")

    def test_legacy_recipient_retains_its_admission_and_uses_the_shared_transport(self):
        request = legacy.example_request()
        with mock.patch.object(
            api, "_post_bound", return_value={"tls_verified": True}
        ) as transport, mock.patch.object(
            api.observe,
            "read_regular",
            side_effect=AssertionError(
                "wrapper must not own a duplicate wire implementation"
            ),
        ):
            self.assertEqual(legacy.REAL_POST(request), {"tls_verified": True})
        binding, action, parameters = transport.call_args.args
        self.assertEqual(
            (binding.node, binding.vmid, action),
            (request["source_request"]["source"]["selector"]["node"], 102, "create"),
        )
        self.assertEqual(parameters, legacy.recipient.create_request(request))
        request["target"]["vmid"] = request["source_request"]["source"]["selector"][
            "vmid"
        ]
        transport.reset_mock()
        with mock.patch.object(api, "_post_bound") as transport:
            with self.assertRaises(ValueError):
                legacy.REAL_POST(request)
        transport.assert_not_called()

    def test_current_task_preserves_exact_known_warning_semantics(self):
        binding = api.GuestBinding.from_source(self.source)
        upid = f"UPID:{binding.node}:00000010:00000020:00000030:vzstart:102:root@pam:"
        status = {
            **api.parse_upid(binding, upid, kind="vzstart"),
            "status": "stopped",
            "exitstatus": "WARNINGS: 1",
        }
        log = [{"n": 1, "t": api.WARNING}, {"n": 2, "t": "TASK WARNINGS: 1"}]
        with mock.patch.object(api, "check_host"), mock.patch.object(
            api, "get", side_effect=[status, log]
        ) as read:
            observed, lines = api.task_state(binding, upid)
        self.assertTrue(api.native_outcome(observed, lines)["accepted"])
        self.assertEqual(
            read.call_args_list[0].args, (f"/nodes/{binding.node}/tasks/{upid}/status",)
        )
        self.assertEqual(
            read.call_args_list[1].args,
            (
                f"/nodes/{binding.node}/tasks/{upid}/log",
                "--start",
                "0",
                "--limit",
                "100",
            ),
        )
        status["pid"] = True
        with mock.patch.object(api, "check_host"), mock.patch.object(
            api, "get", return_value=status
        ):
            with self.assertRaises(ValueError):
                api.task_state(binding, upid)

    def test_transport_rejects_extra_create_or_guest_parameters_before_io(self):
        binding = api.GuestBinding.from_source(self.source)
        parameters = legacy.recipient.create_request(legacy.example_request())
        parameters["net0"] = "name=eth0,bridge=vmbr0"
        with mock.patch.object(api.observe, "read_regular") as read, mock.patch.object(
            api.subprocess, "run"
        ) as auth:
            with self.assertRaises(ValueError):
                api._post_bound(binding, "create", parameters)
            with self.assertRaises(ValueError):
                api._post_bound(binding, "shutdown", {"forceStop": "1"})
        read.assert_not_called()
        auth.assert_not_called()


class CurrentGuestWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        legacy.CreateWireTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        legacy.CreateWireTests.tearDownClass.__func__(cls)

    server = legacy.CreateWireTests.server

    def call(self, port, operation="start", *, bad_leaf=False, node="localhost"):
        source = copy.deepcopy(legacy.example_request()["source_request"]["source"])
        source["selector"].update(vmid=102, node=node)
        cert = self.cert.read_bytes()
        fingerprint = api.state.sha256(ssl.PEM_cert_to_DER_cert(cert.decode()))
        source["host_profile"].update(
            ca_certificate_sha256=fingerprint,
            leaf_certificate_sha256="0" * 64 if bad_leaf else fingerprint,
        )
        binding = api.GuestBinding.from_source(source)
        original = socket.create_connection

        def redirected(address, timeout):
            self.assertEqual(address, ("127.0.0.1", 8006))
            return original(("127.0.0.1", port), timeout=timeout)

        with mock.patch.object(api, "check_host"), mock.patch.object(
            api.observe, "read_regular", return_value=(cert, None)
        ), mock.patch.object(
            api.subprocess,
            "run",
            return_value=SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {"ticket": "PVE:root@pam:PRIVATE_TICKET", "csrf": "PRIVATE_CSRF"}
                ).encode(),
                stderr=b"",
            ),
        ), mock.patch.object(
            api.socket, "create_connection", side_effect=redirected
        ):
            return api.post_guest_action(binding, operation)

    def test_real_verified_tls_actions_use_only_exact_current_guest_and_fixed_parameters(
        self,
    ):
        for operation, kind in (("start", "vzstart"), ("shutdown", "vzshutdown")):
            with self.server() as (port, requests):
                result = self.call(port, operation)
            self.assertEqual(len(requests), 1)
            self.assertEqual(
                requests[0]["path"],
                "/api2/json/nodes/localhost/lxc/102/status/" + operation,
            )
            self.assertEqual(
                requests[0]["parameters"],
                {} if operation == "start" else {"timeout": ["60"], "forceStop": ["0"]},
            )
            self.assertIn(":" + kind + ":102:root@pam:", result["upid"])
            self.assertNotIn("PRIVATE", json.dumps(result))

    def test_wrong_peer_or_redirect_never_sends_credentials_to_foreign_peer_or_retries(
        self,
    ):
        with self.server() as (port, requests):
            with self.assertRaises(ValueError):
                self.call(port, bad_leaf=True)
        self.assertEqual(requests, [])
        with self.server(302) as (port, requests):
            with self.assertRaises(ValueError) as error:
                self.call(port)
        self.assertEqual(len(requests), 1)
        self.assertNotIn("PRIVATE", str(error.exception))

    def test_task_identity_is_bound_to_current_node_guest_operation_and_root_principal(
        self,
    ):
        source = legacy.example_request()["source_request"]["source"]
        source["selector"].update(vmid=102, node="localhost")
        binding = api.GuestBinding.from_source(source)
        good = "UPID:localhost:00000010:00000020:00000030:vzstart:102:root@pam:"
        self.assertEqual(api.parse_upid(binding, good, kind="vzstart")["id"], "102")
        for changed in (
            good.replace("localhost", "other"),
            good.replace(":102:", ":103:"),
            good.replace("vzstart", "vzcreate"),
            good.replace("root@pam", "other@pam"),
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                api.parse_upid(binding, changed, kind="vzstart")
