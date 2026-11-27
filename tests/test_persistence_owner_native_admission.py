"""Pure native assertion joins; producer acceptance remains explicitly modeled.

Metadata fixture IO and the sibling protocol probe are real local operations.
Current/native providers and review/source qualification claims are modeled.
"""

import base64
import copy
import importlib
import os
import unittest
from unittest import mock

from test_persistence_owner_execution_admission import pure_call
import test_persistence_owner_execution_admission as admission_fixture
import test_persistence_owner_metadata_executor as metadata_fixture


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class NativeAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.n = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils."
            "persistence_owner_native_admission"
        )
        cls.fixture = metadata_fixture.MetadataExecutorTests("runTest")
        cls.addClassCleanup(cls.fixture.doCleanups)
        original_examples = admission_fixture.examples

        def examples(model, codec):
            # Select the synthetic native namespace before H0 is constructed;
            # changing it after selection correctly invalidates that authority.
            common = cls.fixture.r.legacy.RUNTIME_ROOT.parent
            cls.fixture.enterContext(
                mock.patch.object(
                    cls.n.storage.journal, "RUNTIME_ROOT", common / "native"
                )
            )
            cls.fixture.enterContext(
                mock.patch.object(cls.n.storage.journal, "ROOT_UID", os.geteuid())
            )
            return original_examples(model, codec)

        with mock.patch.object(admission_fixture, "examples", side_effect=examples):
            cls.fixture.setUp()
        f, n = cls.fixture, cls.n
        f.execute("begin")
        f.execute("publish-marker")
        f.execute("record-completion")
        cls.original = f.selection
        pair = f.executor.storage.RUNTIME_ROOT / cls.original._private_binding.pair_key
        cls.complete = (pair / "complete.json").read_bytes()
        with f.executor.attempt.inspect_attempt_v2(
            **cls.original._arguments()
        ) as observed:
            cls.capture = observed.raw
        f.admission("requalify-complete")
        cls.docs = copy.deepcopy(f.docs)
        cls.manifest = copy.deepcopy(cls.docs["producer_manifest"])
        for path in n.SDK_PATHS:
            cls.manifest["components"]["sdk"].setdefault(
                path,
                dict(
                    sha256=f.r.state.sha256(("modeled native source:" + path).encode()),
                    bytes=128,
                ),
            )
        cls.metadata, cls.handoff = cls.make_subject(cls.manifest)
        probe = n.storage.probe_protocol(allow_mutation=True)
        fs = f.r.observe.decode(cls.metadata.filesystem_qualification_raw)
        cls.review = dict(
            document_type=n.REVIEW_DOCUMENT,
            schema_version=1,
            checkpoint_sha256=cls.handoff.selection.checkpoint_sha256,
            intent_sha256=cls.handoff.selection._intent_sha256,
            complete_sha256=cls.handoff.complete_sha256,
            original_contract_sha256=cls.handoff.original_contract_sha256,
            capture_sha256=cls.handoff.capture_sha256,
            completion_acceptance_sha256="1" * 64,
            requalification_acceptance_sha256="2" * 64,
            original_native_operation_qualified=False,
            ack_recovered=False,
        )
        cls.qualification = dict(
            document_type=n.FILESYSTEM_DOCUMENT,
            schema_version=1,
            subject=fs["subject"],
            metadata_filesystem_sha256=cls.metadata.filesystem_qualification_sha256,
            producer_manifest_sha256=cls.metadata.producer_manifest_sha256,
            configuration_sha256=f.r.state.sha256(n.storage._configuration()),
            primitives={
                path: cls.manifest["components"]["sdk"][path]["sha256"]
                for path in n.PRIMITIVES
            },
            diagnostic_acceptance_sha256="3" * 64,
            logic_qualification_sha256="4" * 64,
            probe=dict(
                raw_base64=base64.b64encode(probe.raw).decode(),
                bytes=len(probe.raw),
                sha256=probe.sha256,
            ),
        )

    @classmethod
    def make_subject(cls, manifest):
        f, n = cls.fixture, cls.n
        r = f.r
        args = cls.original._arguments()
        contract_args = {
            key: value
            for key, value in args.items()
            if key not in {"contract_raw", "contract_sha256"}
        }
        contract = f.executor.completion.prepare_publication_contract(
            **contract_args,
            source_manifest_sha256=r.digest(manifest),
        )
        args.update(contract_raw=contract.raw, contract_sha256=contract.sha256)
        selection = f.executor.semantics.select(**args)
        docs = copy.deepcopy(cls.docs)
        docs["producer_manifest"] = manifest
        docs["admission"]["subject"]["publication_contract_sha256"] = contract.sha256
        docs["admission"]["execution"]["producer_manifest_sha256"] = r.digest(manifest)
        inputs = dict(selection=selection, action="requalify-complete")
        for key, value in docs.items():
            raw = r.state.canonical(value)
            inputs[key + "_raw"], inputs[key + "_sha256"] = raw, r.state.sha256(raw)
        metadata = n.base.load_execution_admission(**inputs)
        handoff = n.handoffs.select_native_handoff(
            selection=selection,
            original_contract_raw=cls.original._contract_raw,
            original_contract_sha256=cls.original.contract_sha256,
            complete_raw=cls.complete,
            complete_sha256=r.state.sha256(cls.complete),
            capture_raw=cls.capture,
            capture_sha256=r.state.sha256(cls.capture),
        )
        return metadata, handoff

    def arguments(self, *, review=None, qualification=None):
        r = self.fixture.r
        result = dict(metadata_admission=self.metadata, handoff=self.handoff)
        for key, value in (
            ("handoff_review", self.review if review is None else review),
            (
                "filesystem_qualification",
                self.qualification if qualification is None else qualification,
            ),
        ):
            raw = r.state.canonical(value)
            result[key + "_raw"], result[key + "_sha256"] = raw, r.state.sha256(raw)
        return result

    def load(self, **changes):
        return pure_call(
            self.n.load_native_admission, **{**self.arguments(), **changes}
        )

    def test_join_is_pure_and_grants_no_native_or_source_authority(self):
        value = self.load()
        pure_call(value.validate)
        description = self.fixture.r.observe.decode(pure_call(value.describe))
        self.assertIs(value.selection, self.metadata.selection)
        self.assertEqual(description["complete_sha256"], self.handoff.complete_sha256)
        for key in (
            "producer_authenticated",
            "filesystem_verified_live",
            "current_lease_verified",
            "native_action_dispatched",
            "original_native_operation_qualified",
            "ack_recovered",
        ):
            self.assertIs(description[key], False)

    def test_nominal_inputs_exact_bytes_and_external_hashes_are_required(self):
        for changes in (
            dict(metadata_admission=object()),
            dict(handoff=object()),
            dict(handoff_review_sha256="0" * 64),
            dict(filesystem_qualification_sha256="0" * 64),
            dict(handoff_review_raw=bytearray(self.arguments()["handoff_review_raw"])),
        ):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ValueError):
                self.load(**changes)

    def test_historical_review_is_joined_to_exact_h1_and_preserves_uncertainty(self):
        for key, value in (
            ("complete_sha256", "0" * 64),
            ("original_contract_sha256", "0" * 64),
            ("capture_sha256", "0" * 64),
            ("ack_recovered", True),
            ("original_native_operation_qualified", True),
        ):
            review = {**self.review, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                pure_call(self.n.load_native_admission, **self.arguments(review=review))

    def test_native_qualification_matches_executing_source_base_fs_and_configuration(
        self,
    ):
        for key in (
            "metadata_filesystem_sha256",
            "producer_manifest_sha256",
            "configuration_sha256",
        ):
            qualification = {**self.qualification, key: "0" * 64}
            with self.subTest(key=key), self.assertRaises(ValueError):
                pure_call(
                    self.n.load_native_admission,
                    **self.arguments(qualification=qualification),
                )

    def test_rehashed_probe_cannot_substitute_mount_epoch_or_file_ownership(self):
        r = self.fixture.r
        original = r.observe.decode(
            base64.b64decode(self.qualification["probe"]["raw_base64"])
        )
        for fault in ("mount", "epoch", "file", "parent", "removal", "permission"):
            probe = copy.deepcopy(original)
            if fault == "mount":
                probe["mount"]["mount_id"] += 1
            elif fault == "epoch":
                probe["host_epoch"]["boot_id"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            elif fault == "file":
                probe["replaced_file"][3] += 1
            elif fault == "parent":
                probe["parent"]["identity"][1] += 1
            elif fault == "removal":
                probe["scratch_removed"] = False
            else:
                probe["filesystem_qualified"] = True
            raw = r.state.canonical(probe)
            qualification = {
                **self.qualification,
                "probe": dict(
                    raw_base64=base64.b64encode(raw).decode(),
                    bytes=len(raw),
                    sha256=r.state.sha256(raw),
                ),
            }
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                pure_call(
                    self.n.load_native_admission,
                    **self.arguments(qualification=qualification),
                )

    def test_native_source_roles_are_required_even_when_metadata_accepts_the_manifest(
        self,
    ):
        manifest = copy.deepcopy(self.manifest)
        del manifest["components"]["sdk"][
            "plugins/module_utils/persistence_owner_native_executor.py"
        ]
        metadata, handoff = self.make_subject(manifest)
        pure_call(metadata.validate)
        pure_call(handoff.validate)
        with self.assertRaisesRegex(ValueError, "native-source-roles"):
            self.load(metadata_admission=metadata, handoff=handoff)

    def test_selected_state_and_protocol_drift_refuse_revalidation(self):
        value = self.load()
        original = value.filesystem_qualification_raw
        try:
            object.__setattr__(
                value, "filesystem_qualification_raw", bytearray(original)
            )
            with self.assertRaises(ValueError):
                pure_call(value.validate)
        finally:
            object.__setattr__(value, "filesystem_qualification_raw", original)
        with mock.patch.object(
            self.n.storage.journal,
            "RUNTIME_ROOT",
            self.n.storage.journal.RUNTIME_ROOT.with_name("other"),
        ):
            with self.assertRaises(ValueError):
                pure_call(value.validate)


if __name__ == "__main__":
    unittest.main()
