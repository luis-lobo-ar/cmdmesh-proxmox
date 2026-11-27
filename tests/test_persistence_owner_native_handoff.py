"""Synthetic semantic selection only; no native admission or managed calls."""

import base64
import copy
import importlib
import unittest
from unittest import mock

from test_persistence_owner_execution_admission import pure_call
import test_persistence_owner_semantics as semantic_fixture


class NativeHandoffTests(unittest.TestCase):
    def setUp(self):
        self.n = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils."
            "persistence_owner_native_handoff"
        )
        self.fixture = semantic_fixture.SemanticSelectionTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.case, self.r = self.fixture.case, self.fixture.r
        self.complete = self.case.candidate()
        (self.case.old.path / "complete.json").write_bytes(self.complete.raw)
        self.capture, capture_raw, capture_sha = self.fixture.capture()
        contract = self.case.contract_for(source_manifest_sha256="8" * 64)
        self.current = self.fixture.selected(
            contract_raw=contract.raw, contract_sha256=contract.sha256
        )
        self.arguments = dict(
            selection=self.current,
            original_contract_raw=self.case.contract.raw,
            original_contract_sha256=self.case.contract.sha256,
            complete_raw=self.complete.raw,
            complete_sha256=self.complete.sha256,
            capture_raw=capture_raw,
            capture_sha256=capture_sha,
        )

    def select(self, **changes):
        return pure_call(self.n.select_native_handoff, **{**self.arguments, **changes})

    def test_distinct_contracts_are_validated_without_io_or_native_permission(self):
        with mock.patch.object(
            self.n.codec.attempt,
            "inspect_attempt_v2",
            side_effect=AssertionError("live inspection forbidden"),
        ):
            selected = self.select()
            pure_call(selected.validate)
            description = self.r.observe.decode(pure_call(selected.describe))
        self.assertIs(selected.selection, self.current)
        self.assertEqual(selected.historical.contract_sha256, self.case.contract.sha256)
        self.assertNotEqual(
            selected.historical.contract_sha256, self.current.contract_sha256
        )
        self.assertEqual(description["complete_sha256"], self.complete.sha256)
        self.assertEqual(description["schema_version"], 1)
        for name in (
            "producer_authenticated",
            "current_lease_verified",
            "filesystem_qualified",
            "native_admission_authorized",
            "native_action_dispatched",
            "original_native_operation_qualified",
            "ack_recovered",
        ):
            self.assertIs(description[name], False)

    def test_journal_binding_is_v4_and_stable_across_executing_source_changes(self):
        selected = self.select()
        binding = pure_call(lambda: selected.journal_binding)
        self.assertIs(type(binding), self.n.journal.Binding)
        self.assertEqual(binding.pair_key, self.case.owner.pair_key)
        self.assertEqual(binding.guest, self.case.owner.guest)
        self.assertNotEqual(binding.authority_sha256, self.case.owner.authority_sha256)
        contract = self.case.contract_for(source_manifest_sha256="9" * 64)
        next_source = self.fixture.selected(
            contract_raw=contract.raw, contract_sha256=contract.sha256
        )
        other = self.select(selection=next_source)
        self.assertEqual(binding, pure_call(lambda: other.journal_binding))
        self.assertNotEqual(
            selected.selection.contract_sha256, other.selection.contract_sha256
        )

    def test_external_hashes_and_exact_byte_types_are_required(self):
        for changes in (
            dict(original_contract_sha256="a" * 64),
            dict(complete_sha256="a" * 64),
            dict(capture_sha256="a" * 64),
            dict(capture_raw=bytearray(self.arguments["capture_raw"])),
            dict(selection=object()),
        ):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ValueError):
                self.select(**changes)

    def test_current_contract_cannot_replace_original_h1_contract(self):
        with self.assertRaises(ValueError):
            self.select(
                original_contract_raw=self.current._contract_raw,
                original_contract_sha256=self.current.contract_sha256,
            )

    def test_legacy_h1_is_not_normalized_to_semantic_two(self):
        with self.assertRaises(ValueError):
            self.select(
                complete_raw=self.case.complete_v1.raw,
                complete_sha256=self.case.complete_v1.sha256,
            )

    def test_selected_capture_must_contain_exact_retained_h1(self):
        capture = copy.deepcopy(self.capture)
        path = next(
            path for path in capture["files"] if path.endswith("/complete.json")
        )
        capture["files"][path]["raw_base64"] = base64.b64encode(b"{}\n").decode()
        raw = self.r.state.canonical(capture)
        with self.assertRaises(ValueError):
            self.select(capture_raw=raw, capture_sha256=self.r.state.sha256(raw))

    def test_mutating_selected_inputs_or_protocol_configuration_refuses(self):
        selected = self.select()
        object.__setattr__(selected, "complete_raw", bytearray(self.complete.raw))
        with self.assertRaises(ValueError):
            pure_call(selected.validate)
        selected = self.select()
        with mock.patch.dict(self.n.journal.RUNTIME, schema_version=3):
            with self.assertRaises(ValueError):
                pure_call(selected.validate)
        self.current._private_checkpoint["completion"]["runtime"]["application"][
            "record_count"
        ] += 1
        with self.assertRaises(ValueError):
            pure_call(selected.validate)

    def test_action_profile_constant_drift_refuses_selection_and_revalidation(self):
        selected = self.select()
        with mock.patch.object(self.n.journal, "ACTION_PROFILE", "owner-os-action-v2"):
            with self.assertRaisesRegex(ValueError, "native-handoff-journal-profile"):
                pure_call(self.n._configuration)
            with self.assertRaisesRegex(ValueError, "native-handoff-journal-profile"):
                self.select()
            with self.assertRaisesRegex(ValueError, "native-handoff-journal-profile"):
                pure_call(selected.validate)


if __name__ == "__main__":
    unittest.main()
