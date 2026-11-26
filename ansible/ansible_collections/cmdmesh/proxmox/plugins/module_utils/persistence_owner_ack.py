"""Pure privacy-safe response capture and recorded owner ACK qualification.

An observation is forensic input, not permission or a certified native outcome.
This module performs no native calls, filesystem access, or clock reads.
"""

import copy
from dataclasses import asdict

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_guest_api as api,
    persistence_state as state,
)

DOCUMENT = "cmdmesh.proxmox.owner-native-ack-observation"
VERSION = 1
MAX_BODY = 262144
NS_PER_SECOND = 10**9
# Bound uncertainty of each local clock sample, not time spent before a request.
MAX_SAMPLE_UNCERTAINTY_NS = 100000000
SAFE_UPID = (
    r"UPID:[A-Za-z0-9][A-Za-z0-9.-]{0,62}:"
    r"[0-9A-Fa-f]{8,16}:[0-9A-Fa-f]{8,16}:[0-9A-Fa-f]{8,16}:"
    r"[a-z][a-z0-9-]{0,31}:[0-9]{1,9}:root@pam:"
)


def require(condition, code):
    state.require(condition, "persistence-owner-ack-" + code)


def keys(value, fields):
    require(type(value) is dict and set(value) == set(fields), "schema")


def epoch_shape(value):
    keys(value, {"boot_id", "mount_namespace"})
    require(
        state.matches(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value["boot_id"])
        and state.matches(r"mnt:\[[1-9][0-9]*\]", value["mount_namespace"]),
        "epoch",
    )


def clock_shape(value):
    keys(value, {"epoch", "wall_ns", "monotonic_before_ns", "monotonic_after_ns"})
    epoch_shape(value["epoch"])
    require(
        all(
            type(value[key]) is int and 0 <= value[key] < 2**63
            for key in ("wall_ns", "monotonic_before_ns", "monotonic_after_ns")
        ),
        "clock-type",
    )


def safe_body(raw):
    """Retain only exact JSON data/UPID responses, never arbitrary body fields."""
    try:
        value = api.observe.decode(raw)
        if (
            type(value) is dict
            and set(value) == {"data"}
            and state.matches(SAFE_UPID, value["data"])
        ):
            return raw.decode("utf-8")
    except (ValueError, UnicodeError, RecursionError):
        pass
    return None


def observe_response(
    binding,
    action,
    dispatch_sha256,
    send,
    receive,
    *,
    tls_verified,
    tls_peer_sha256,
    tls_version,
    http_status,
    content_type,
    body,
    body_complete=True,
):
    """Build an unqualified observation from bounded, already received material."""
    require(type(binding) is api.GuestBinding, "binding")
    require(type(action) is str and action in {"start", "shutdown"}, "action")
    state.digest(dispatch_sha256)
    clock_shape(send)
    if receive is not None:
        clock_shape(receive)
    require(type(tls_verified) is bool and type(body_complete) is bool, "flags")
    require(tls_version is None or type(tls_version) is str, "tls-version")
    require(content_type is None or type(content_type) is str, "content-type")
    require(
        body is None or (type(body) is bytes and len(body) <= MAX_BODY + 1),
        "body-limit",
    )
    complete = body is not None and body_complete and len(body) <= MAX_BODY
    value = {
        "document_type": DOCUMENT,
        "schema_version": VERSION,
        "binding": asdict(binding),
        "action": action,
        "dispatch_sha256": dispatch_sha256,
        "send": copy.deepcopy(send),
        "receive": copy.deepcopy(receive),
        "tls": {
            "verified": tls_verified,
            "peer_sha256": tls_peer_sha256,
            "version": tls_version if tls_version in {"TLSv1.2", "TLSv1.3"} else None,
        },
        "response": {
            "http_status": http_status,
            "is_json": content_type is not None
            and content_type.startswith("application/json"),
            "body_length": len(body) if body is not None else None,
            "body_sha256": state.sha256(body) if body is not None else None,
            "body_complete": complete,
            "safe_body": safe_body(body) if complete else None,
        },
    }
    validate_observation(value)
    return value


def validate_observation(value):
    """Check privacy/schema binding while allowing observed semantic failures."""
    keys(
        value,
        {
            "document_type",
            "schema_version",
            "binding",
            "action",
            "dispatch_sha256",
            "send",
            "receive",
            "tls",
            "response",
        },
    )
    require(
        value["document_type"] == DOCUMENT
        and type(value["schema_version"]) is int
        and value["schema_version"] == VERSION,
        "version",
    )
    keys(
        value["binding"],
        {"node", "vmid", "machine_id_sha256", "ca_sha256", "leaf_sha256"},
    )
    api.GuestBinding(**value["binding"])
    require(
        type(value["action"]) is str and value["action"] in {"start", "shutdown"},
        "action",
    )
    state.digest(value["dispatch_sha256"])
    clock_shape(value["send"])
    if value["receive"] is not None:
        clock_shape(value["receive"])
    tls = value["tls"]
    keys(tls, {"verified", "peer_sha256", "version"})
    require(type(tls["verified"]) is bool, "tls")
    require(
        tls["version"] is None
        or (type(tls["version"]) is str and tls["version"] in {"TLSv1.2", "TLSv1.3"}),
        "tls",
    )
    if tls["peer_sha256"] is not None:
        state.digest(tls["peer_sha256"])
    response = value["response"]
    keys(
        response,
        {
            "http_status",
            "is_json",
            "body_length",
            "body_sha256",
            "body_complete",
            "safe_body",
        },
    )
    require(
        response["http_status"] is None
        or (
            type(response["http_status"]) is int
            and 100 <= response["http_status"] <= 599
        ),
        "http-status",
    )
    require(
        type(response["is_json"]) is bool and type(response["body_complete"]) is bool,
        "response-flags",
    )
    if response["body_length"] is None:
        require(
            response["body_sha256"] is None
            and response["safe_body"] is None
            and response["body_complete"] is False,
            "missing-body",
        )
    else:
        require(
            type(response["body_length"]) is int
            and 0 <= response["body_length"] <= MAX_BODY + 1,
            "body-limit",
        )
        state.digest(response["body_sha256"])
        require(
            not response["body_complete"] or response["body_length"] <= MAX_BODY,
            "body-limit",
        )
    if response["safe_body"] is not None:
        raw = response["safe_body"]
        require(type(raw) is str and 0 < len(raw.encode()) <= MAX_BODY, "safe-body")
        raw = raw.encode()
        require(
            response["body_complete"] is True
            and len(raw) == response["body_length"]
            and state.sha256(raw) == response["body_sha256"]
            and safe_body(raw) == response["safe_body"],
            "safe-body",
        )


def validate_ack(binding, action, dispatch_sha256, expected_epoch, observation):
    """Qualify a recorded ACK without reading a current clock or native state."""
    require(type(binding) is api.GuestBinding, "binding")
    require(type(action) is str and action in {"start", "shutdown"}, "action")
    state.digest(dispatch_sha256)
    epoch_shape(expected_epoch)

    def inputs():
        try:
            raw = state.canonical({"epoch": expected_epoch, "observation": observation})
        except (TypeError, ValueError, RecursionError):
            require(False, "json")
        require(len(raw) <= 4 * MAX_BODY, "observation-limit")
        return raw

    original = inputs()
    snapshot = api.observe.decode(original)
    observed, epoch = snapshot["observation"], snapshot["epoch"]
    validate_observation(observed)
    require(
        observed["binding"] == asdict(binding)
        and observed["action"] == action
        and observed["dispatch_sha256"] == dispatch_sha256,
        "dispatch-binding",
    )
    tls, response = observed["tls"], observed["response"]
    require(
        tls["verified"] is True
        and tls["peer_sha256"] == binding.leaf_sha256
        and tls["version"] in {"TLSv1.2", "TLSv1.3"},
        "tls",
    )
    require(
        response["http_status"] == 200
        and response["is_json"] is True
        and response["body_complete"] is True
        and response["safe_body"] is not None,
        "response",
    )
    send, receive = observed["send"], observed["receive"]
    require(receive is not None, "receive-clock")
    require(send["epoch"] == receive["epoch"] == epoch, "epoch-changed")
    for sample in (send, receive):
        uncertainty = sample["monotonic_after_ns"] - sample["monotonic_before_ns"]
        require(0 <= uncertainty <= MAX_SAMPLE_UNCERTAINTY_NS, "sample-uncertainty")
    lower = receive["monotonic_before_ns"] - send["monotonic_after_ns"]
    upper = receive["monotonic_after_ns"] - send["monotonic_before_ns"]
    wall_elapsed = receive["wall_ns"] - send["wall_ns"]
    require(0 <= lower <= wall_elapsed <= upper, "clock-discontinuity")
    upid = api.observe.decode(response["safe_body"].encode())["data"]
    kind = "vzstart" if action == "start" else "vzshutdown"
    parsed = api.parse_upid(binding, upid, kind=kind)
    second = parsed["starttime"] * NS_PER_SECOND
    # PVE records integer seconds; require overlap with the observed interval.
    require(
        second + NS_PER_SECOND > send["wall_ns"] and second <= receive["wall_ns"],
        "task-clock",
    )
    result = {
        "upid": upid,
        "tls_verified": True,
        "observation_sha256": state.sha256(state.canonical(observed)),
    }
    require(inputs() == original, "inputs-changed")
    return result
