"""Pure, finite missing-record plans; no metadata executor or native authority."""

from dataclasses import dataclass

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_attempt_codec as codec,
)

r, profile = codec.r, codec.profile
OUTPUT_LIMIT = 16384
COMPARISON_POLICY = {
    "schema_version": 1,
    "files": "full-nine-and-sha256",
    "owned_directories": "full-nine",
    "shared_directories": "stable-five",
    "ancestors": "stable-five",
    "memberships": "exact-source-projection",
    "absence": "selected-fixed-path-or-absent-ancestor",
}
_EDGES = (
    ("bootstrap-incomplete", "finish-runtime"),
    ("empty-claim", "record-intent"),
    ("h0-only", "publish-marker"),
    ("h0-marker", "record-completion"),
)


@dataclass(frozen=True, slots=True)
class Plan:
    raw: bytes
    sha256: str


def require(value, code):
    r.require(value, "continuation-" + code)


def _projection(body):
    """Only role-validated observations enter the future matching contract."""
    return {
        "files": {
            path: {"identity": item["identity"], "sha256": item["sha256"]}
            for path, item in body["files"].items()
        },
        "directories": {
            path: identity[: body["directory_closure_fields"][path]]
            for path, identity in body["directories"].items()
        },
        "directory_closure_fields": body["directory_closure_fields"],
        "ancestors": body["ancestors"],
        "memberships": body["memberships"],
        "membership_policy": body["membership_policy"],
        "absent": body["absent"],
    }


def prepare_continuation(
    binding, intent_raw, intent_sha256, capture_raw, capture_sha256, action
):
    """Select one exact missing publication without authenticating its producer."""
    expected_policy = r.state.canonical(COMPARISON_POLICY)
    expected_profile = r.state.canonical(profile.RUNTIME)
    paths = (
        profile.RUNTIME_ROOT,
        profile.MARKER,
        profile.PROTOCOL,
        r.RUNTIME_ROOT,
        r.legacy.RUNTIME_ROOT,
    )
    edges, limit = _EDGES, OUTPUT_LIMIT
    require(type(action) is str and action in {name for _, name in edges}, "action")
    owner, binding_raw = r._binding(binding)
    intent = r._intent(owner, intent_raw, intent_sha256)
    body = codec.validate_capture(
        owner, intent_raw, intent_sha256, capture_raw, capture_sha256
    )
    require((body["status"], action) in edges, "stage-action")
    pair = profile.RUNTIME_ROOT / owner.pair_key
    if action == "finish-runtime":
        destination = profile.RUNTIME_ROOT / "runtime.json"
        payload, source = expected_profile, "runtime-profile"
    elif action == "record-intent":
        destination = pair / "intent.json"
        payload, source = intent_raw, "accepted-intent"
    elif action == "publish-marker":
        destination = r.legacy.RUNTIME_ROOT / owner.pair_key / profile.MARKER
        payload, source = (
            r.state.canonical(r._marker(owner, intent_sha256)),
            "derived-marker",
        )
    else:
        destination = pair / "complete.json"
        payload, source = None, "fresh-closing-evidence"
    require(str(destination) in body["absent"], "missing-destination")
    document = r._document(
        "continuation-plan",
        binding=r.asdict(owner),
        accepted_intent_sha256=intent_sha256,
        capture_sha256=capture_sha256,
        publication_protocol=profile.PROTOCOL,
        runtime_profile_sha256=r.state.sha256(expected_profile),
        stage=body["status"],
        action=action,
        destination=str(destination),
        destination_must_remain_absent=True,
        payload_source=source,
        payload_sha256=None if payload is None else r.state.sha256(payload),
        payload_size=None if payload is None else len(payload),
        comparison_policy_sha256=r.state.sha256(expected_policy),
        expected_fresh_projection_sha256=r.digest(_projection(body)),
        required_current_phase="os_quiesced",
        required_host_epoch=intent["caller_evidence"]["host_epoch"],
        required_worker_fence_sha256=intent["caller_evidence"]["worker_fence_sha256"],
        unsupported_phase_or_epoch="phase-aware-reconciliation-required",
        required_fresh_gates=[
            "authenticated-source-and-closed-capture-provenance",
            "pair-exclusive-native-config-shared-application-exclusive-leases",
            "native-before-config-and-intrinsic-current-admission",
            "accepted-historical-fence-and-policy-matching-fresh-attempt",
            "qualified-managed-atomic-filesystem",
            "phase-aware-old-file-destination-and-database-observers",
            "post-publication-current-resource-lease-and-memory-closure",
        ]
        + (
            ["short-global-runtime-bootstrap-serialization"]
            if action == "finish-runtime"
            else []
        ),
        candidate_only=True,
        producer_authenticated=False,
        current_admitted=False,
        publication_authorized=False,
        native_action_dispatched=False,
        metadata_resolution_recorded=False,
        successor_native_admission_authorized=False,
    )
    raw = r.state.canonical(document)
    require(0 < len(raw) <= limit, "output-limit")
    checksum = r.state.sha256(raw)
    r._close_binding(binding, owner, binding_raw)
    require(
        r.state.canonical(body) == capture_raw
        and r.state.canonical(intent) == intent_raw
        and r.state.canonical(document) == raw,
        "decoded-memory-changed",
    )
    require(
        r.state.canonical(COMPARISON_POLICY) == expected_policy
        and r.state.canonical(profile.RUNTIME) == expected_profile
        and paths
        == (
            profile.RUNTIME_ROOT,
            profile.MARKER,
            profile.PROTOCOL,
            r.RUNTIME_ROOT,
            r.legacy.RUNTIME_ROOT,
        )
        and edges == _EDGES
        and limit == OUTPUT_LIMIT,
        "profile-changed",
    )
    require(
        r.state.sha256(intent_raw) == intent_sha256
        and r.state.sha256(capture_raw) == capture_sha256,
        "input-changed",
    )
    return Plan(raw, checksum)
