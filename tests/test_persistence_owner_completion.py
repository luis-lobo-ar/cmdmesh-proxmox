"""Synthetic phase-aware metadata, never producer or native qualification."""

import copy
from dataclasses import asdict, replace
import importlib
import os
from types import SimpleNamespace
import unittest
from unittest import mock

import test_persistence_owner_admission as admission
import test_persistence_owner_journal as journal_fixture
import test_persistence_owner_retirement as historical
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_transition as transition,
    persistence_owner_storage_profile as storage,
)


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.codec = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils."
            "persistence_owner_completion"
        )
        self.model = admission.OwnerAdmissionTests("runTest")
        self.model.setUp()
        self.addCleanup(self.model.doCleanups)
        self.cp = self.model.authority
        self.owner = transition.binding(self.cp)
        original_setup = journal_fixture.OwnerJournalTests.setUp

        def setup(case):
            original_setup(case)
            case.binding = self.owner
            case.datasets = self.model.request["policy"]["datasets"]

        self.old = historical.RetirementTests("runTest")
        original_payloads = journal_fixture.phase_payloads

        def payloads(pending):
            # The older fixture hardcodes VMID102 in its synthetic UPID. Adapt
            # only modeled metadata to the checkpoint's actual synthetic VMID.
            guest = pending.binding.guest
            fake = SimpleNamespace(
                binding=replace(pending.binding, guest=replace(guest, vmid=102)),
                sequence=pending.sequence,
                kind=pending.kind,
                prepared_sha256=pending.prepared_sha256,
            )
            result = original_payloads(fake)
            result["dispatch"]["binding"] = asdict(guest)
            upid = result["ack"]["upid"].replace(":102:", f":{guest.vmid}:")
            result["ack"]["upid"] = upid
            task = result["terminal"]["task"]
            kind = "vzshutdown" if pending.kind == "shutdown" else "vzstart"
            task.update(journal_fixture.api.parse_upid(guest, upid, kind=kind))
            return result

        with mock.patch.object(
            journal_fixture.OwnerJournalTests, "setUp", setup
        ), mock.patch.object(journal_fixture, "phase_payloads", side_effect=payloads):
            self.old.setUp()
        self.addCleanup(self.old.doCleanups)
        self.enterContext(
            mock.patch.object(storage, "RUNTIME_ROOT", self.old.r.RUNTIME_ROOT)
        )
        if getattr(self, "prepare_old_completion", True):
            self.complete_v1 = self.old.complete()
        else:
            self.old.intent = self.old.prepare()
            self.old.h0, self.old.h0sha = self.old.encoded(self.old.intent)
        self.h0, self.h0sha = self.old.h0, self.old.h0sha
        self.old_doc = (
            self.old.r.validate_handoff(
                self.owner,
                self.h0,
                self.h0sha,
                self.complete_v1.raw,
                self.complete_v1.sha256,
            )
            if getattr(self, "prepare_old_completion", True)
            else None
        )
        self.cp_sha = self.old.r.digest(self.cp)
        self.source_sha = "7" * 64
        self.contract = self.contract_for()

    def contract_for(self, **changes):
        options = dict(
            binding=self.owner,
            checkpoint=self.cp,
            checkpoint_sha256=self.cp_sha,
            intent_raw=self.h0,
            intent_sha256=self.h0sha,
            source_manifest_sha256=self.source_sha,
        )
        options.update(changes)
        return self.codec.prepare_publication_contract(**options)

    def arguments(self):
        return dict(
            binding=self.owner,
            checkpoint=self.cp,
            checkpoint_sha256=self.cp_sha,
            intent_raw=self.h0,
            intent_sha256=self.h0sha,
            contract_raw=self.contract.raw,
            contract_sha256=self.contract.sha256,
        )

    def closing(self, phase="os_quiesced", new_epoch=False):
        from test_persistence_owner_phase_admission import admission_inputs

        evidence, entry, prior = admission_inputs(
            self.model, phase, new_epoch=new_epoch
        )
        return dict(
            phase=phase,
            host_epoch={
                key: evidence["observation"]["host"][key]
                for key in ("boot_id", "mount_namespace")
            },
            current=evidence,
            admission=dict(entry=entry, prior_runtime=prior),
            source_manifest_sha256=self.source_sha,
        )

    def candidate(self, **changes):
        options = dict(
            intent_file=copy.deepcopy(self.old_doc["intent_file"]),
            marker_file=copy.deepcopy(self.old_doc["marker_file"]),
            closing=self.closing(),
        )
        options.update(changes)
        return self.codec.prepare_completion(**self.arguments(), **options)

    def validate(self, document, **changes):
        raw = self.old.r.state.canonical(document)
        args = self.arguments()
        args.update(changes)
        return self.codec.validate_completion(
            **args, complete_raw=raw, complete_sha256=self.old.r.state.sha256(raw)
        )

    def test_contract_is_deterministic_storage_two_and_has_no_future_hash(self):
        result = self.contract_for()
        self.assertEqual(self.contract, result)
        value = self.old.r.observe.decode(result.raw)
        self.assertEqual(value["schema_version"], 2)
        self.assertEqual(value["completion_schema_version"], 2)
        self.assertEqual(
            value["runtime_profile_sha256"], self.old.r.digest(storage.RUNTIME)
        )
        self.assertEqual(
            value["historical_evidence_sha256"], self.old.r.digest(self.old.evidence)
        )
        self.assertNotIn("complete_sha256", value)
        self.assertNotIn("current_sha256", value)
        self.assertFalse(value["native_action_dispatched"])

    def test_running_stopped_and_new_boot_do_not_reuse_historical_epoch(self):
        before = copy.deepcopy((self.cp, self.old.intent, self.old.evidence))
        original_files = self.old.originals()
        for phase, new_epoch in (
            ("os_quiesced", False),
            ("stopped", False),
            ("os_quiesced", True),
            ("stopped", True),
        ):
            with self.subTest(phase=phase, new_epoch=new_epoch):
                result = self.candidate(closing=self.closing(phase, new_epoch))
                value = self.old.r.observe.decode(result.raw)
                self.assertEqual(self.validate(value), value)
                self.assertEqual(value["schema_version"], 2)
                self.assertFalse(value["original_native_operation_qualified"])
                self.assertFalse(value["native_action_dispatched"])
        self.assertEqual(before, (self.cp, self.old.intent, self.old.evidence))
        self.assertEqual(original_files, self.old.originals())

    def test_legacy_semantic_one_is_historical_only(self):
        self.old.r.validate_handoff(
            self.owner,
            self.h0,
            self.h0sha,
            self.complete_v1.raw,
            self.complete_v1.sha256,
        )
        with self.assertRaises(ValueError):
            self.validate(self.old_doc)

    def test_wrong_external_checkpoint_or_binding_refuses(self):
        with self.assertRaises(ValueError):
            self.contract_for(checkpoint_sha256="0" * 64)
        owner = self.old.r.legacy.Binding(
            self.owner.pair_key, "8" * 64, self.owner.guest
        )
        with self.assertRaises(ValueError):
            self.contract_for(binding=owner)

    def test_contract_schema_gates_source_and_historical_links_are_exact(self):
        original = self.old.r.observe.decode(self.contract.raw)
        for field, value in (
            ("schema_version", True),
            ("completion_schema_version", 1),
            ("runtime_profile_sha256", "0" * 64),
            ("intent_sha256", "0" * 64),
            ("historical_evidence_sha256", "0" * 64),
            ("historical_worker_fence_sha256", "0" * 64),
            ("required_gates", []),
            ("phase_policy", {}),
            ("native_action_dispatched", 0),
            ("unknown", False),
        ):
            value_doc = copy.deepcopy(original)
            value_doc[field] = value
            raw = self.old.r.state.canonical(value_doc)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.codec.load_publication_contract(
                    **{
                        **self.arguments(),
                        "contract_raw": raw,
                        "contract_sha256": self.old.r.state.sha256(raw),
                    }
                )

    def test_completion_exact_fields_flags_and_history_links(self):
        original = self.old.r.observe.decode(self.candidate().raw)
        for field, value in (
            ("schema_version", True),
            ("schema_version", 1),
            ("checkpoint_sha256", "0" * 64),
            ("publication_contract_sha256", "0" * 64),
            ("historical_evidence_sha256", "0" * 64),
            ("intent_sha256", "0" * 64),
            ("basis_sha256", "0" * 64),
            ("legacy_retired", 1),
            ("metadata_resolution_recorded", 1),
            ("original_native_operation_qualified", True),
            ("native_action_dispatched", True),
            ("unexpected", None),
        ):
            changed = copy.deepcopy(original)
            changed[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.validate(changed)

    def test_descriptor_path_identity_size_hash_and_marker_drift_refuse(self):
        original = self.old.r.observe.decode(self.candidate().raw)
        for field in ("intent_file", "marker_file"):
            for change in ("path", "sha256", "mode", "links", "size", "extra"):
                changed = copy.deepcopy(original)
                part = changed[field]
                if change == "path":
                    part["path"] += ".other"
                elif change == "sha256":
                    part["sha256"] = "0" * 64
                elif change == "mode":
                    part["identity"][2] |= 0o004
                elif change == "links":
                    part["identity"][5] = 2
                elif change == "size":
                    part["identity"][6] += 1
                else:
                    part["extra"] = True
                with self.subTest(field=field, change=change), self.assertRaises(
                    ValueError
                ):
                    self.validate(changed)
        changed = copy.deepcopy(original)
        changed["marker"]["schema_version"] = True
        with self.assertRaises(ValueError):
            self.validate(changed)

    def test_closing_epoch_source_phase_and_app_identity_cannot_be_substituted(self):
        original = self.old.r.observe.decode(self.candidate().raw)
        for fault in (
            "epoch",
            "phase",
            "source",
            "extra",
            "application",
            "entry",
            "prior",
        ):
            changed = copy.deepcopy(original)
            closing = changed["closing"]
            if fault == "epoch":
                closing["host_epoch"][
                    "boot_id"
                ] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            elif fault == "phase":
                closing["phase"] = "stopped"
            elif fault == "source":
                closing["source_manifest_sha256"] = "0" * 64
            elif fault == "extra":
                closing["callback_succeeded"] = True
            elif fault == "application":
                closing["current"]["observation"]["application"]["record_count"] += 1
            elif fault == "entry":
                closing["admission"]["entry"]["root"]["uuid"] = "foreign"
            else:
                closing["admission"]["prior_runtime"] = {"target_selected": True}
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.validate(changed)

    def test_input_hashes_canonical_bytes_and_size_are_bounded(self):
        result = self.candidate()
        for raw, sha in (
            (result.raw, "0" * 64),
            (result.raw + b"\n", self.old.r.state.sha256(result.raw + b"\n")),
            (b"x" * (self.old.r.LIMIT + 1), "0" * 64),
        ):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                self.codec.validate_completion(
                    **self.arguments(), complete_raw=raw, complete_sha256=sha
                )

    def test_no_filesystem_native_or_bootstrap_publication_is_used(self):
        closing = self.closing("stopped", True)
        original = self.old.originals()
        with mock.patch.object(
            self.old.r.os, "open", side_effect=AssertionError("file IO")
        ), mock.patch.object(
            transition.observe, "native", side_effect=AssertionError("native IO")
        ):
            result = self.candidate(closing=closing)
            self.validate(self.old.r.observe.decode(result.raw))
        self.assertEqual(original, self.old.originals())

    def test_late_checkpoint_binding_or_decoded_completion_change_refuses(self):
        document = self.old.r.observe.decode(self.candidate().raw)
        original = self.codec.admission.validate_phase_admission
        for fault in ("checkpoint", "binding", "decoded"):
            checkpoint = copy.deepcopy(self.cp)
            owner = self.owner

            def mutate(*args):
                original(*args)
                if fault == "checkpoint":
                    self.cp["completion"]["runtime"]["application"]["record_count"] += 1
                elif fault == "binding":
                    object.__setattr__(self.owner, "authority_sha256", "6" * 64)
                else:
                    args[2]["guest_image_verified"] = False

            with self.subTest(fault=fault), mock.patch.object(
                self.codec.admission, "validate_phase_admission", side_effect=mutate
            ), self.assertRaises(ValueError):
                self.validate(document)
            self.cp = checkpoint
            object.__setattr__(owner, "authority_sha256", self.cp_sha)

    def test_contract_constructor_recloses_binding_after_encoding(self):
        canonical = self.old.r.state.canonical
        owner = self.owner
        before = owner.authority_sha256

        def mutate(value):
            raw = canonical(value)
            if (
                type(value) is dict
                and value.get("document_type") == self.codec.CONTRACT_DOCUMENT
            ):
                object.__setattr__(owner, "authority_sha256", "f" * 64)
            return raw

        try:
            with mock.patch.object(
                self.old.r.state, "canonical", side_effect=mutate
            ), self.assertRaises(ValueError):
                self.contract_for()
        finally:
            object.__setattr__(owner, "authority_sha256", before)

    def test_completion_constructor_recloses_original_closing_after_validation(self):
        closing = self.closing()
        original = self.codec.admission.validate_phase_admission

        def mutate(*args):
            original(*args)
            closing["source_manifest_sha256"] = "0" * 64

        with mock.patch.object(
            self.codec.admission, "validate_phase_admission", side_effect=mutate
        ), self.assertRaises(ValueError):
            self.candidate(closing=closing)

    def test_contract_loader_recloses_decoded_view_after_reconstruction(self):
        decode, canonical = self.old.r._decode, self.old.r.state.canonical
        selected = []

        def track(raw, sha, *args):
            value = decode(raw, sha, *args)
            if raw == self.contract.raw:
                selected.append(value)
            return value

        def mutate(value):
            raw = canonical(value)
            if (
                selected
                and type(value) is dict
                and value.get("document_type") == self.codec.CONTRACT_DOCUMENT
            ):
                selected[-1]["native_action_dispatched"] = True
            return raw

        with mock.patch.object(
            self.old.r, "_decode", side_effect=track
        ), mock.patch.object(
            self.old.r.state, "canonical", side_effect=mutate
        ), self.assertRaises(
            ValueError
        ):
            self.codec.load_publication_contract(**self.arguments())
