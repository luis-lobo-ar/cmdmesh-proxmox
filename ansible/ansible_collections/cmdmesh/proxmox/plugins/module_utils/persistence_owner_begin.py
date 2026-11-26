"""A clean-begin plan over a selected unused capture2, without execution."""

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_attempt_codec as codec,
    persistence_owner_bootstrap as bootstrap,
    persistence_owner_continuation as continuation,
    persistence_owner_semantics as semantics,
)

r, profile = semantics.r, semantics.storage


def require(value, code):
    r.require(value, "begin-plan-" + code)


def _publish(action, path, raw, source):
    return dict(
        operation="publish",
        action=action,
        path=str(path),
        payload_source=source,
        payload_sha256=r.state.sha256(raw),
        payload_size=len(raw),
        destination_must_remain_absent=True,
    )


def _mkdir(role, path):
    return dict(
        operation="mkdir",
        role=role,
        path=str(path),
        mode=0o700,
        destination_must_remain_absent=True,
    )


def prepare_begin(
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
):
    """Plan only root/runtime/pair/H0 creation, ending at H0-only.

    This is separate from the four interrupted-publication edges. It does not
    fabricate an observed partial prefix, create a namespace or grant admission.
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
    fixed = (
        profile.RUNTIME_ROOT,
        profile.PROTOCOL,
        bootstrap.LOCK_NAME,
        r.state.canonical(continuation.COMPARISON_POLICY),
        continuation.OUTPUT_LIMIT,
    )
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
    require(body["status"] == "unused", "stage")
    root = profile.RUNTIME_ROOT
    pair = root / selection._private_binding.pair_key
    missing_root = str(root) in body["absent"]
    runtime = r.state.canonical(profile.RUNTIME)
    operations = []
    mutex = None
    if missing_root:
        require(body["runtime_profile"] == "absent", "runtime")
        operations.extend(
            (
                _mkdir("runtime-root", root),
                _publish(
                    "finish-runtime", root / "runtime.json", runtime, "runtime-profile"
                ),
            )
        )
        lock = r._document(
            "bootstrap-lock",
            runtime_path=str(root),
            runtime_profile_sha256=r.state.sha256(runtime),
            publication_protocol=profile.PROTOCOL,
        )
        mutex = dict(
            path=str(root.parent / bootstrap.LOCK_NAME),
            payload_sha256=r.digest(lock),
            initialize_if_absent=True,
            release_before_current_worker=True,
        )
    else:
        require(
            body["runtime_profile"] == "current" and str(pair) in body["absent"],
            "runtime",
        )
    operations.extend(
        (
            _mkdir("pair", pair),
            _publish(
                "record-intent", pair / "intent.json", intent_raw, "accepted-intent"
            ),
        )
    )
    contract = r._decode(contract_raw, contract_sha256)
    value = r._document(
        "begin-plan",
        binding=r.asdict(selection._private_binding),
        checkpoint_sha256=checkpoint_sha256,
        accepted_intent_sha256=intent_sha256,
        publication_contract_sha256=contract_sha256,
        capture_sha256=capture_sha256,
        historical_evidence_sha256=contract["historical_evidence_sha256"],
        historical_worker_fence_sha256=contract["historical_worker_fence_sha256"],
        completion_schema_version=2,
        phase_admission_policy=contract["phase_policy"],
        stage="unused",
        action="begin",
        final_stage="h0-only",
        publication_protocol=profile.PROTOCOL,
        runtime_profile_sha256=r.state.sha256(runtime),
        operations=operations,
        bootstrap_mutex=mutex,
        comparison_policy_sha256=r.digest(continuation.COMPARISON_POLICY),
        expected_fresh_projection_sha256=r.digest(continuation._projection(body)),
        required_fresh_gates=list(semantics.codec.REQUIRED_GATES)
        + (["short-global-runtime-bootstrap-serialization"] if missing_root else []),
        candidate_only=True,
        producer_authenticated=False,
        current_admitted=False,
        publication_authorized=False,
        native_action_dispatched=False,
        metadata_resolution_recorded=False,
        successor_native_admission_authorized=False,
    )
    value["schema_version"] = 2
    raw = r.state.canonical(value)
    require(0 < len(raw) <= continuation.OUTPUT_LIMIT, "output-limit")
    selection.validate()
    require(
        r.state.canonical(body) == capture_raw and r.state.canonical(value) == raw,
        "decoded-changed",
    )
    selection._memory()
    require(
        (
            profile.RUNTIME_ROOT,
            profile.PROTOCOL,
            bootstrap.LOCK_NAME,
            r.state.canonical(continuation.COMPARISON_POLICY),
            continuation.OUTPUT_LIMIT,
        )
        == fixed,
        "policy-changed",
    )
    return continuation.Plan(raw, r.state.sha256(raw))


def load_begin(
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
    plan_raw,
    plan_sha256,
):
    """Reconstruct selected bytes; an unused observation grants no permission."""
    value = r._decode(plan_raw, plan_sha256, continuation.OUTPUT_LIMIT)
    expected = prepare_begin(
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
    require(plan_raw == expected.raw and r.state.canonical(value) == plan_raw, "plan")
    return value
