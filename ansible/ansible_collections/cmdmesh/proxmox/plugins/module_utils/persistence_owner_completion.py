"""Phase-aware completion semantics, without publication or native authority.

External hashes select accepted inputs. This pure codec validates their joins;
it cannot authenticate a producer, prove held leases or certify syscall success.
Legacy completion validation remains in persistence_owner_retirement.
"""

from dataclasses import dataclass

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_phase_admission as admission,
    persistence_owner_retirement as r,
    persistence_owner_storage_profile as storage,
    persistence_owner_transition as transition,
)

CONTRACT_DOCUMENT = "cmdmesh.proxmox.persistence.owner-publication-contract"
PHASE_POLICY = {
    "phases": ["os_quiesced", "stopped"],
    "epoch": "fresh-intrinsically-admitted",
    "stopped_prior": "externally-selected-last-accepted-os-quiesced",
}
REQUIRED_GATES = (
    "authenticated-source-and-closed-capture-provenance",
    "pair-exclusive-native-config-shared-application-exclusive-leases",
    "native-before-config-and-intrinsic-current-admission",
    "accepted-historical-fence-and-policy-matching-fresh-attempt",
    "qualified-managed-atomic-filesystem",
    "phase-aware-old-file-destination-and-database-observers",
    "post-publication-current-resource-lease-and-memory-closure",
)


@dataclass(frozen=True, slots=True)
class Document:
    raw: bytes
    sha256: str


def require(value, code):
    r.require(value, "completion-v2-" + code)


def _document(value):
    raw = r.state.canonical(value)
    require(0 < len(raw) <= r.LIMIT, "size")
    return Document(raw, r.state.sha256(raw))


def _inputs(binding, checkpoint, checkpoint_sha256, intent_raw, intent_sha256):
    r.state.digest(checkpoint_sha256)
    require(r.digest(checkpoint) == checkpoint_sha256, "checkpoint-hash")
    owner, binding_raw = r._binding(binding)
    expected = transition.binding(checkpoint)
    require(r.state.canonical(r.asdict(expected)) == binding_raw, "binding-checkpoint")
    intent = r._intent(owner, intent_raw, intent_sha256)
    r._close_binding(binding, owner, binding_raw)
    require(r.digest(checkpoint) == checkpoint_sha256, "checkpoint-changed")
    return owner, intent


def prepare_publication_contract(
    *,
    binding,
    checkpoint,
    checkpoint_sha256,
    intent_raw,
    intent_sha256,
    source_manifest_sha256,
):
    """Prepare a reviewable contract; its bytes alone grant no execution rights."""
    owner, intent = _inputs(
        binding, checkpoint, checkpoint_sha256, intent_raw, intent_sha256
    )
    r.state.digest(source_manifest_sha256)
    document = _document(
        {
            "document_type": CONTRACT_DOCUMENT,
            "schema_version": 2,
            "binding": r.asdict(owner),
            "checkpoint_sha256": checkpoint_sha256,
            "intent_sha256": intent_sha256,
            "historical_evidence_sha256": r.digest(intent["caller_evidence"]),
            "historical_worker_fence_sha256": intent["caller_evidence"][
                "worker_fence_sha256"
            ],
            "source_manifest_sha256": source_manifest_sha256,
            "completion_schema_version": 2,
            "runtime_profile_sha256": r.digest(storage.RUNTIME),
            "publication_protocol": storage.PROTOCOL,
            "phase_policy": PHASE_POLICY,
            "required_gates": list(REQUIRED_GATES),
            "native_action_dispatched": False,
        }
    )
    _inputs(binding, checkpoint, checkpoint_sha256, intent_raw, intent_sha256)
    return document


def load_publication_contract(
    *,
    binding,
    checkpoint,
    checkpoint_sha256,
    intent_raw,
    intent_sha256,
    contract_raw,
    contract_sha256,
):
    """Validate an externally selected contract, without observing its gates."""
    value = r._decode(contract_raw, contract_sha256)
    require("source_manifest_sha256" in value, "contract-source")
    expected = prepare_publication_contract(
        binding=binding,
        checkpoint=checkpoint,
        checkpoint_sha256=checkpoint_sha256,
        intent_raw=intent_raw,
        intent_sha256=intent_sha256,
        source_manifest_sha256=value["source_manifest_sha256"],
    )
    require(expected.raw == contract_raw, "contract")
    require(r.state.canonical(value) == contract_raw, "contract-decoded-changed")
    return value


def _closing(checkpoint, contract, closing):
    r.state.keys(
        closing,
        {"phase", "host_epoch", "current", "admission", "source_manifest_sha256"},
    )
    r.state.keys(closing["host_epoch"], {"boot_id", "mount_namespace"})
    r.state.keys(closing["admission"], {"entry", "prior_runtime"})
    require(
        closing["source_manifest_sha256"] == contract["source_manifest_sha256"],
        "closing-source",
    )
    admission.validate_phase_admission(
        checkpoint,
        closing["phase"],
        closing["current"],
        closing["admission"]["entry"],
        closing["admission"]["prior_runtime"],
    )
    host = closing["current"]["observation"]["host"]
    require(
        r.state.canonical(closing["host_epoch"])
        == r.state.canonical(
            {key: host[key] for key in ("boot_id", "mount_namespace")}
        ),
        "closing-epoch",
    )


def validate_completion(
    *,
    binding,
    checkpoint,
    checkpoint_sha256,
    intent_raw,
    intent_sha256,
    contract_raw,
    contract_sha256,
    complete_raw,
    complete_sha256,
):
    """Validate semantic2 metadata; acceptance still needs closed live provenance."""
    owner, intent = _inputs(
        binding, checkpoint, checkpoint_sha256, intent_raw, intent_sha256
    )
    contract = load_publication_contract(
        binding=binding,
        checkpoint=checkpoint,
        checkpoint_sha256=checkpoint_sha256,
        intent_raw=intent_raw,
        intent_sha256=intent_sha256,
        contract_raw=contract_raw,
        contract_sha256=contract_sha256,
    )
    value = r._decode(complete_raw, complete_sha256)
    r.state.keys(
        value,
        {
            "document_type",
            "schema_version",
            "intent_sha256",
            "intent_file",
            "marker",
            "marker_file",
            "basis_sha256",
            "checkpoint_sha256",
            "publication_contract_sha256",
            "historical_evidence_sha256",
            "closing",
            "legacy_retired",
            "metadata_resolution_recorded",
            "original_native_operation_qualified",
            "native_action_dispatched",
        },
    )
    require(
        value["document_type"] == r._document("complete")["document_type"]
        and type(value["schema_version"]) is int
        and value["schema_version"] == 2,
        "schema",
    )
    require(
        value["intent_sha256"] == intent_sha256
        and value["basis_sha256"] == r.digest(intent["basis"])
        and value["checkpoint_sha256"] == checkpoint_sha256
        and value["publication_contract_sha256"] == contract_sha256
        and value["historical_evidence_sha256"] == r.digest(intent["caller_evidence"]),
        "links",
    )
    r._descriptor(
        value["intent_file"], storage.RUNTIME_ROOT / owner.pair_key / "intent.json"
    )
    require(
        value["intent_file"]["sha256"] == intent_sha256
        and value["intent_file"]["identity"][6] == len(intent_raw),
        "intent-file",
    )
    marker = r._marker(owner, intent_sha256)
    r._descriptor(
        value["marker_file"],
        r.legacy.RUNTIME_ROOT / owner.pair_key / storage.MARKER,
        r.MARKER_LIMIT,
    )
    require(
        r.state.canonical(value["marker"]) == r.state.canonical(marker)
        and value["marker_file"]["sha256"] == r.digest(marker)
        and value["marker_file"]["identity"][6] == len(r.state.canonical(marker)),
        "marker",
    )
    require(
        value["legacy_retired"] is True
        and value["metadata_resolution_recorded"] is True
        and value["original_native_operation_qualified"] is False
        and value["native_action_dispatched"] is False,
        "flags",
    )
    _closing(checkpoint, contract, value["closing"])
    # Admission reuses trusted pure validators. Reclose every selected input
    # and the decoded output after those calls, rather than trusting an earlier
    # identity/hash check on mutable Python objects.
    load_publication_contract(
        binding=binding,
        checkpoint=checkpoint,
        checkpoint_sha256=checkpoint_sha256,
        intent_raw=intent_raw,
        intent_sha256=intent_sha256,
        contract_raw=contract_raw,
        contract_sha256=contract_sha256,
    )
    r._close_binding(binding, owner, r.state.canonical(r.asdict(owner)))
    require(r.state.canonical(value) == complete_raw, "decoded-changed")
    return value


def prepare_completion(
    *,
    binding,
    checkpoint,
    checkpoint_sha256,
    intent_raw,
    intent_sha256,
    contract_raw,
    contract_sha256,
    intent_file,
    marker_file,
    closing,
):
    """Prepare bounded H1 bytes. This function never publishes a file."""
    owner, intent = _inputs(
        binding, checkpoint, checkpoint_sha256, intent_raw, intent_sha256
    )
    value = r._document(
        "complete",
        intent_sha256=intent_sha256,
        intent_file=intent_file,
        marker=r._marker(owner, intent_sha256),
        marker_file=marker_file,
        basis_sha256=r.digest(intent["basis"]),
        checkpoint_sha256=checkpoint_sha256,
        publication_contract_sha256=contract_sha256,
        historical_evidence_sha256=r.digest(intent["caller_evidence"]),
        closing=closing,
        legacy_retired=True,
        metadata_resolution_recorded=True,
        original_native_operation_qualified=False,
        native_action_dispatched=False,
    )
    value["schema_version"] = 2
    document = _document(value)
    validate_completion(
        binding=binding,
        checkpoint=checkpoint,
        checkpoint_sha256=checkpoint_sha256,
        intent_raw=intent_raw,
        intent_sha256=intent_sha256,
        contract_raw=contract_raw,
        contract_sha256=contract_sha256,
        complete_raw=document.raw,
        complete_sha256=document.sha256,
    )
    require(r.state.canonical(value) == document.raw, "constructor-input-changed")
    return document
