"""A retained response is not an ACK, successful operation, or native permission."""

import ast
import copy
from dataclasses import asdict
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_guest_api as api,
    persistence_owner_ack as ack,
    persistence_owner_journal as legacy,
    persistence_pair_lock as pair,
)


class RequestJournalTests(unittest.TestCase):
    def setUp(self):
        self.j = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils."
            "persistence_owner_request_journal"
        )
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / ".generated")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for module, name, value in (
            (self.j, "RUNTIME_ROOT", self.root / "v4"),
            (legacy, "RUNTIME_ROOT", self.root / "v3"),
            (self.j.backup, "RUNTIME_ROOT", self.root / "pair"),
            (self.j, "ROOT_UID", os.geteuid()),
            (legacy, "ROOT_UID", os.geteuid()),
        ):
            self.enterContext(mock.patch.object(module, name, value))
        for name in ("post_guest_action", "post_owner_guest_action", "get"):
            self.enterContext(
                mock.patch.object(api, name, side_effect=AssertionError("native IO"))
            )
        self.datasets = {"data": {"guid": "11"}, "config": {"guid": "22"}}
        self.guest = api.GuestBinding("pve-example", 102, "1" * 64, "2" * 64, "3" * 64)
        self.owner = self.j.Binding(
            api.state.pair_key(self.datasets), "b" * 64, self.guest
        )
        self.epoch = {
            "boot_id": "11111111-2222-3333-4444-555555555555",
            "mount_namespace": "mnt:[123]",
        }
        self.head = self.call(self.j._initialize, self.owner)["head_sha256"]
        self.anchor = (self.path / "HEAD.json").read_bytes()

    @property
    def path(self):
        return self.j.RUNTIME_ROOT / self.owner.pair_key

    def call(self, function, *args):
        with pair.locked_pair(self.datasets, initialize=True):
            return function(*args)

    def begin(self, kind="shutdown", head=None, request="c" * 64):
        return self.call(self.j._begin, self.owner, head or self.head, kind, request)

    def append(self, operation, stage, payload):
        return self.call(self.j._append_phase, operation, stage, payload)

    def dispatch(self, operation):
        action = "shutdown" if operation.kind == "shutdown" else "start"
        return self.append(
            operation,
            "dispatch",
            {
                "action": action,
                "binding": asdict(self.guest),
                "prepared_sha256": operation.prepared_sha256,
                "entry_sha256": "e" * 64,
                "host_epoch": copy.deepcopy(self.epoch),
                "clock": 1700000000,
                "parameters": (
                    {} if action == "start" else {"timeout": "60", "forceStop": "0"}
                ),
            },
        )

    def observation(self, operation, *, second=1700000061):
        action = "shutdown" if operation.kind == "shutdown" else "start"
        kind = "vzshutdown" if action == "shutdown" else "vzstart"
        upid = f"UPID:pve-example:00000010:00000020:{second:08X}:{kind}:102:root@pam:"

        def clock(tick):
            return {
                "epoch": copy.deepcopy(self.epoch),
                "wall_ns": 1700000000 * 10**9 + tick + 500,
                "monotonic_before_ns": tick,
                "monotonic_after_ns": tick + 1000,
            }

        return ack.observe_response(
            self.guest,
            action,
            self.j._digest(operation.phases.records["dispatch.json"]),
            clock(61_000_000_000),
            clock(61_200_000_000),
            tls_verified=True,
            tls_peer_sha256=self.guest.leaf_sha256,
            tls_version="TLSv1.3",
            http_status=200,
            content_type="application/json",
            body=json.dumps({"data": upid}).encode(),
        )

    def certified(self, operation, observation):
        return ack.validate_ack(
            self.guest,
            observation["action"],
            self.j._digest(operation.phases.records["dispatch.json"]),
            self.epoch,
            observation,
        )

    def through_ack(self, operation):
        operation = self.dispatch(operation)
        observation = self.observation(operation)
        operation = self.append(operation, "ack-observed", observation)
        return self.append(operation, "ack", self.certified(operation, observation))

    def terminal(self, operation):
        payload = operation.phases.records["ack.json"]["payload"]
        kind = "vzshutdown" if operation.kind == "shutdown" else "vzstart"
        task = {
            **api.parse_upid(self.guest, payload["upid"], kind=kind),
            "status": "stopped",
            "exitstatus": "OK",
        }
        log = [{"n": 1, "t": "TASK OK"}]
        return self.append(
            operation,
            "terminal",
            {
                "task": task,
                "log": log,
                "native_outcome": api.native_outcome(task, log),
            },
        )

    def files(self):
        return {
            str(p): (p.read_bytes(), self.j.observe.stable(p.lstat()))
            for p in self.path.rglob("*")
            if p.is_file()
        }

    def test_profile_and_namespace_are_explicitly_new(self):
        self.assertEqual(
            (self.j.VERSION, self.j.ACTION_PROFILE), (4, "owner-os-action-v3")
        )
        self.assertEqual(self.j.STAGES, ("dispatch", "ack-observed", "ack", "terminal"))
        source = Path(self.j.__file__).read_text()
        self.assertIn("/var/lib/cmdmesh/owner-lifecycle-v4", source)
        self.assertNotEqual(
            self.j._genesis(self.owner),
            legacy._genesis(
                legacy.Binding(
                    self.owner.pair_key, self.owner.authority_sha256, self.guest
                )
            ),
        )

    def test_slow_fresh_ack_completes_repeated_cycles(self):
        head = self.head
        for number, kind in enumerate(("shutdown", "resume", "shutdown", "resume"), 1):
            operation = self.begin(kind, head, self.j._digest({"request": number}))
            operation = self.terminal(self.through_ack(operation))
            candidate = self.call(
                self.j._complete, operation, {"modeled_current": kind}
            )
            head = candidate.head_sha256
            self.assertEqual(candidate.sequence, number)
            self.assertEqual(len(candidate.phases.records), 4)
            view = self.call(self.j._inspect, self.owner, head)
            self.assertEqual(view.head["state"], "ready")
            with self.assertRaises(ValueError):
                self.call(self.j._complete, operation, {})

    def test_ack_cannot_skip_observation_or_terminal(self):
        operation = self.dispatch(self.begin())
        observation = self.observation(operation)
        before = self.files()
        with self.assertRaises(ValueError):
            self.append(operation, "ack", self.certified(operation, observation))
        self.assertEqual(before, self.files())
        operation = self.append(operation, "ack-observed", observation)
        operation = self.append(
            operation, "ack", self.certified(operation, observation)
        )
        with self.assertRaises(ValueError):
            self.call(self.j._complete, operation, {})
        self.assertFalse((self.path / self.j._slot(1) / "result.json").exists())

    def test_semantically_bad_response_is_retained_without_ack_or_success(self):
        for fault in (
            "old",
            "future",
            "tls",
            "epoch",
            "jump",
            "missing-receive",
            "body",
        ):
            with self.subTest(fault=fault):
                self._retain_bad_response(fault)

    def _retain_bad_response(self, fault):
        # A separate pair models each independent failed operation, not a reset.
        number = (
            "old",
            "future",
            "tls",
            "epoch",
            "jump",
            "missing-receive",
            "body",
        ).index(fault)
        self.datasets = {
            "data": {"guid": str(100 + number)},
            "config": {"guid": str(200 + number)},
        }
        self.owner = self.j.Binding(
            api.state.pair_key(self.datasets), "b" * 64, self.guest
        )
        self.head = self.call(self.j._initialize, self.owner)["head_sha256"]
        operation = self.dispatch(self.begin())
        value = self.observation(
            operation,
            second={"old": 1700000060, "future": 1700000062}.get(fault, 1700000061),
        )
        if fault == "tls":
            value["tls"]["verified"] = False
        if fault == "epoch":
            value["receive"]["epoch"]["mount_namespace"] = "mnt:[124]"
        if fault == "jump":
            value["receive"]["wall_ns"] += 10**9
        if fault == "missing-receive":
            value["receive"] = None
        if fault == "body":
            value["response"]["safe_body"] = None
        operation = self.append(operation, "ack-observed", value)
        retained = self.path / self.j._slot(1) / "ack-observed.json"
        self.assertEqual(json.loads(retained.read_bytes())["payload"], value)
        with self.assertRaises(ValueError):
            self.certified(operation, value)
        with self.assertRaises(ValueError):
            self.append(
                operation,
                "ack",
                {
                    "upid": "untrusted",
                    "tls_verified": True,
                    "observation_sha256": self.j._digest(value),
                },
            )
        with self.assertRaises(ValueError):
            self.call(self.j._complete, operation, {})
        self.assertFalse((retained.parent / "ack.json").exists())
        self.assertFalse((retained.parent / "result.json").exists())

    def test_wrong_dispatch_binding_action_or_unsafe_body_cannot_be_persisted(self):
        operation = self.dispatch(self.begin())
        original = self.observation(operation)
        variants = []
        for field, value in (("dispatch_sha256", "f" * 64), ("action", "start")):
            changed = copy.deepcopy(original)
            changed[field] = value
            variants.append(changed)
        changed = copy.deepcopy(original)
        changed["binding"]["vmid"] = 103
        variants.append(changed)
        changed = copy.deepcopy(original)
        changed["response"]["safe_body"] = "PRIVATE_TICKET"
        variants.append(changed)
        before = self.files()
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.append(operation, "ack-observed", value)
        self.assertEqual(before, self.files())

    def test_certified_ack_must_equal_qualification_of_retained_observation(self):
        operation = self.dispatch(self.begin())
        value = self.observation(operation)
        operation = self.append(operation, "ack-observed", value)
        certified = self.certified(operation, value)
        for field, replacement in (
            ("upid", certified["upid"].replace("00000010", "00000011")),
            ("observation_sha256", "f" * 64),
            ("tls_verified", False),
        ):
            forged = {**certified, field: replacement}
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.append(operation, "ack", forged)
        self.assertFalse((self.path / self.j._slot(1) / "ack.json").exists())

    def test_historical_reader_rechecks_observation_without_current_clock(self):
        operation = self.terminal(self.through_ack(self.begin()))
        candidate = self.call(self.j._complete, operation, {})
        with mock.patch(
            "time.time", side_effect=AssertionError("present clock")
        ), mock.patch("time.time_ns", side_effect=AssertionError("present clock")):
            self.call(self.j._inspect, self.owner, candidate.head_sha256)
        path = self.path / self.j._slot(1) / "ack-observed.json"
        value = json.loads(path.read_bytes())
        value["payload"]["receive"]["wall_ns"] += 10**9
        path.write_bytes(self.j.state.canonical(value))
        with self.assertRaises(ValueError):
            self.call(self.j._inspect, self.owner, candidate.head_sha256)

    def test_observation_mutation_and_stale_token_refuse_before_next_write(self):
        operation = self.dispatch(self.begin())
        stale = operation
        value = self.observation(operation)
        operation = self.append(operation, "ack-observed", value)
        with self.assertRaises(ValueError):
            self.append(stale, "ack-observed", value)
        path = self.path / self.j._slot(1) / "ack-observed.json"
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.append(operation, "ack", self.certified(operation, value))
        self.assertFalse((path.parent / "ack.json").exists())

    def test_pending_observation_blocks_redispatch_and_new_preparation(self):
        operation = self.dispatch(self.begin())
        value = self.observation(operation)
        operation = self.append(operation, "ack-observed", value)
        before = self.files()
        with self.assertRaises(ValueError):
            self.begin("resume", request="d" * 64)
        with self.assertRaises(ValueError):
            self.append(operation, "dispatch", {})
        self.assertEqual(before, self.files())

    def test_resolution_preserves_partial_observation_without_certifying_it(self):
        operation = self.dispatch(self.begin())
        slot = self.path / self.j._slot(1)
        path = slot / "ack-observed.json"
        path.write_bytes(b'{"truncated":')
        path.chmod(0o600)
        before = self.files()
        basis = self.call(self.j.capture_basis, self.owner)
        prepared = self.call(
            self.j.prepare_resolution,
            self.owner,
            self.anchor,
            self.head,
            self.j._digest(basis),
            {
                "phase": "os_quiesced",
                "current_sha256": "d" * 64,
                "worker_fence_sha256": "e" * 64,
            },
        )
        raw = self.j.state.canonical(prepared)
        pending = self.call(
            self.j.begin_resolution, self.owner, raw, self.j.state.sha256(raw)
        )
        result = self.call(self.j.complete_resolution, pending)
        self.assertTrue(result.metadata_resolution_recorded)
        self.assertFalse(result.native_action_dispatched)
        after = self.files()
        for name, identity in before.items():
            if Path(name).name != "HEAD.json":
                self.assertEqual(after[name], identity)
        self.assertFalse((slot / "ack.json").exists())
        self.assertFalse((slot / "result.json").exists())
        view = self.call(self.j._inspect, self.owner, result.head_sha256)
        self.assertEqual(view.intent["kind"], "resolve")

    def test_legacy_pending_namespace_and_version_cannot_be_adopted(self):
        old_owner = legacy.Binding(
            self.owner.pair_key, self.owner.authority_sha256, self.guest
        )
        old_head = self.call(legacy._initialize, old_owner)["head_sha256"]
        self.call(legacy._begin, old_owner, old_head, "shutdown", "d" * 64)
        before = {
            str(p): p.read_bytes()
            for p in legacy.RUNTIME_ROOT.rglob("*")
            if p.is_file()
        }
        with self.assertRaises(ValueError):
            self.call(self.j._inspect, self.owner, old_head)
        profile = self.path / "profile.json"
        raw = profile.read_bytes()
        value = json.loads(raw)
        value["schema_version"] = 3
        profile.write_bytes(self.j.state.canonical(value))
        with self.assertRaises(ValueError):
            self.call(self.j._inspect, self.owner, self.head)
        after = {
            str(p): p.read_bytes()
            for p in legacy.RUNTIME_ROOT.rglob("*")
            if p.is_file()
        }
        self.assertEqual(before, after)

    def test_versioned_binding_and_pending_types_cannot_cross_readers(self):
        old_owner = legacy.Binding(
            self.owner.pair_key, self.owner.authority_sha256, self.guest
        )
        old_head = self.call(legacy._initialize, old_owner)["head_sha256"]
        old_operation = self.call(
            legacy._begin, old_owner, old_head, "shutdown", "d" * 64
        )
        new_operation = self.begin()
        for function, argument in (
            (legacy._initialize, self.owner),
            (self.j._initialize, old_owner),
            (legacy._current_operation, new_operation),
            (self.j._current_operation, old_operation),
        ):
            with self.subTest(function=function.__module__), self.assertRaises(
                ValueError
            ):
                self.call(function, argument)

    def test_replaced_observation_file_or_operation_directory_refuses(self):
        operation = self.dispatch(self.begin())
        value = self.observation(operation)
        operation = self.append(operation, "ack-observed", value)
        slot = self.path / self.j._slot(1)
        path = slot / "ack-observed.json"
        raw = path.read_bytes()
        path.unlink()
        path.write_bytes(raw)
        path.chmod(0o600)
        with self.assertRaises(ValueError):
            self.append(operation, "ack", self.certified(operation, value))
        saved = self.root / "saved-slot"
        slot.rename(saved)
        slot.mkdir(mode=0o700)
        for previous in saved.iterdir():
            copied = slot / previous.name
            copied.write_bytes(previous.read_bytes())
            copied.chmod(0o600)
        with self.assertRaises(ValueError):
            self.append(operation, "ack", self.certified(operation, value))

    def test_pure_capture_binds_observation_envelope_and_file_descriptor(self):
        operation = self.through_ack(self.begin())
        intent = json.loads((self.path / self.j._slot(1) / "intent.json").read_bytes())
        records = {
            name: self.j.state.canonical(value)
            for name, value in operation.phases.records.items()
        }
        captured = self.j.validate_phase_capture(
            self.owner, intent, records, operation.phases.files
        )
        self.assertEqual(captured.sha256, operation.phases.sha256)
        for field, replacement in (
            ("predecessor_sha256", "f" * 64),
            ("schema_version", 3),
            ("sequence", 2),
        ):
            altered = copy.deepcopy(operation.phases.records["ack-observed.json"])
            altered[field] = replacement
            bad = {**records, "ack-observed.json": self.j.state.canonical(altered)}
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.j.validate_phase_capture(
                    self.owner, intent, bad, operation.phases.files
                )

    def test_observation_write_substitution_never_returns_a_new_token(self):
        operation = self.dispatch(self.begin())
        value = self.observation(operation)
        original = self.j._write

        def substitute(path, document):
            checksum = original(path, document)
            if path.name == "ack-observed.json":
                altered = copy.deepcopy(document)
                altered["payload"]["receive"] = None
                path.write_bytes(self.j.state.canonical(altered))
            return checksum

        with mock.patch.object(
            self.j, "_write", side_effect=substitute
        ), self.assertRaisesRegex(ValueError, "phase-write-changed"):
            self.append(operation, "ack-observed", value)
        self.assertFalse((self.path / self.j._slot(1) / "ack.json").exists())

    def test_capture_refuses_late_changes_to_each_original_input(self):
        operation = self.terminal(self.through_ack(self.begin()))
        intent = json.loads((self.path / self.j._slot(1) / "intent.json").read_bytes())
        records = {
            name: self.j.state.canonical(value)
            for name, value in operation.phases.records.items()
        }
        native_outcome = api.native_outcome
        for fault in (
            "descriptor",
            "intent",
            "record",
            "binding",
            "tuple",
            "bytearray",
        ):
            owner, supplied_intent, supplied_records, descriptors = copy.deepcopy(
                (self.owner, intent, records, operation.phases.files)
            )
            fired = []

            def drift(*args):
                result = native_outcome(*args)
                if fault == "descriptor":
                    descriptors["dispatch.json"]["identity"][3] = 12345
                if fault == "intent":
                    supplied_intent["prepared_sha256"] = "f" * 64
                if fault == "record":
                    supplied_records["dispatch.json"] = b"{}"
                if fault == "binding":
                    object.__setattr__(owner, "authority_sha256", "f" * 64)
                if fault == "tuple":
                    descriptors["dispatch.json"]["identity"] = tuple(
                        descriptors["dispatch.json"]["identity"]
                    )
                if fault == "bytearray":
                    supplied_records["dispatch.json"] = bytearray(
                        supplied_records["dispatch.json"]
                    )
                fired.append(True)
                return result

            with self.subTest(fault=fault), mock.patch.object(
                api, "native_outcome", side_effect=drift
            ):
                with self.assertRaises(ValueError):
                    self.j.validate_phase_capture(
                        owner, supplied_intent, supplied_records, descriptors
                    )
            self.assertTrue(fired)

    def test_capture_snapshot_preserves_strict_descriptor_types(self):
        operation = self.through_ack(self.begin())
        intent = json.loads((self.path / self.j._slot(1) / "intent.json").read_bytes())
        records = {
            name: self.j.state.canonical(value)
            for name, value in operation.phases.records.items()
        }
        for replacement in (
            tuple(operation.phases.files["dispatch.json"]["identity"]),
            [True] * 9,
        ):
            descriptors = copy.deepcopy(operation.phases.files)
            descriptors["dispatch.json"]["identity"] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                self.j.validate_phase_capture(self.owner, intent, records, descriptors)

    def test_filesystem_and_history_algorithms_keep_frozen_v3_behavior(self):
        def definitions(module):
            return {
                node.name: ast.dump(node, include_attributes=False)
                for node in ast.parse(Path(module.__file__).read_text()).body
                if isinstance(node, (ast.FunctionDef, ast.ClassDef))
            }

        old, new = definitions(legacy), definitions(self.j)
        self.assertEqual(set(old) | {"_validate_phase_capture_snapshot"}, set(new))
        self.assertEqual(
            old["validate_phase_capture"],
            new["_validate_phase_capture_snapshot"].replace(
                "name='_validate_phase_capture_snapshot'",
                "name='validate_phase_capture'",
                1,
            ),
        )
        for name in old.keys() - {"_phase_payload", "validate_phase_capture"}:
            with self.subTest(name=name):
                self.assertEqual(old[name], new[name])


if __name__ == "__main__":
    unittest.main()
