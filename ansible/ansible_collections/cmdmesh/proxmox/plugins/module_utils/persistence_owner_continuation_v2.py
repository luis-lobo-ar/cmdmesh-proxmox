"""Finite contract2 plans; no executor or acceptance of legacy plan1."""

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_completion as completion,
    persistence_owner_continuation as previous,
    persistence_owner_attempt_codec as codec,
    persistence_owner_semantics as semantics,
)

r = completion.r


def prepare_continuation(
    *,
    binding,
    checkpoint,
    checkpoint_sha256,
    intent_raw,
    intent_sha256,
    contract_raw,
    contract_sha256,
    capture_raw,
    capture_sha256,
    action,
):
    """Bind an exact missing-record plan to fresh phase-aware admission policy.

    The storage classifier/projection is unchanged. Its historical epoch fields
    are deliberately replaced; neither old metadata nor this plan admits a
    current guest or authorizes a write.
    """
    selection = semantics.select(
        binding=binding,
        checkpoint=checkpoint,
        checkpoint_sha256=checkpoint_sha256,
        intent_raw=intent_raw,
        intent_sha256=intent_sha256,
        contract_raw=contract_raw,
        contract_sha256=contract_sha256,
    )
    contract = r._decode(contract_raw, contract_sha256)
    owner, binding_raw = r._binding(binding)
    policy_raw = r.state.canonical(previous.COMPARISON_POLICY)
    edges, limit = previous._EDGES, previous.OUTPUT_LIMIT
    body = codec.validate_capture_v2(
        binding=binding,
        checkpoint=checkpoint,
        checkpoint_sha256=checkpoint_sha256,
        intent_raw=intent_raw,
        intent_sha256=intent_sha256,
        contract_raw=contract_raw,
        contract_sha256=contract_sha256,
        capture_raw=capture_raw,
        capture_sha256=capture_sha256,
    )
    value = previous._storage_document(
        owner, intent_raw, intent_sha256, capture_sha256, body, action
    )
    value.update(
        schema_version=2,
        completion_schema_version=2,
        checkpoint_sha256=checkpoint_sha256,
        publication_contract_sha256=contract_sha256,
        historical_evidence_sha256=contract["historical_evidence_sha256"],
        historical_worker_fence_sha256=contract["historical_worker_fence_sha256"],
        phase_admission_policy=contract["phase_policy"],
    )
    raw = r.state.canonical(value)
    r.require(0 < len(raw) <= previous.OUTPUT_LIMIT, "continuation-v2-output-limit")
    selection.validate()
    r._close_binding(binding, owner, binding_raw)
    r.require(
        r.state.canonical(body) == capture_raw and r.state.canonical(value) == raw,
        "continuation-v2-decoded-changed",
    )
    r.require(
        r.state.canonical(previous.COMPARISON_POLICY) == policy_raw
        and previous._EDGES == edges
        and previous.OUTPUT_LIMIT == limit,
        "continuation-v2-policy-changed",
    )
    selection._memory()
    return previous.Plan(raw, r.state.sha256(raw))


def load_continuation(
    *,
    binding,
    checkpoint,
    checkpoint_sha256,
    intent_raw,
    intent_sha256,
    contract_raw,
    contract_sha256,
    capture_raw,
    capture_sha256,
    action,
    plan_raw,
    plan_sha256,
):
    """Reconstruct an externally selected plan; no observation authenticates itself."""
    value = r._decode(plan_raw, plan_sha256, previous.OUTPUT_LIMIT)
    expected = prepare_continuation(
        binding=binding,
        checkpoint=checkpoint,
        checkpoint_sha256=checkpoint_sha256,
        intent_raw=intent_raw,
        intent_sha256=intent_sha256,
        contract_raw=contract_raw,
        contract_sha256=contract_sha256,
        capture_raw=capture_raw,
        capture_sha256=capture_sha256,
        action=action,
    )
    r.require(plan_raw == expected.raw, "continuation-v2-plan")
    r.require(r.state.canonical(value) == plan_raw, "continuation-v2-decoded-changed")
    return value
