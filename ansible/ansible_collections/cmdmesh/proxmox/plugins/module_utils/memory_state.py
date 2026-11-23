"""Canonical typed memory evidence and fixed checks; no collection or mutation."""

import copy
import hashlib
import json
import re

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
HOST_HASHES = {"machine_id_sha256", "ca_certificate_sha256", "leaf_certificate_sha256"}
SUPPORTED_VERSIONS = {("9.2.21", "6.1.14")}
FIELDS = {
    "document_type",
    "schema_version",
    "request_id",
    "origin",
    "node",
    "host_profile",
    "host_boot_id_sha256",
    "kind",
    "vmid",
    "tags",
    "configuration",
    "runtime",
    "host_capacity",
    "versions",
    "observed_at_unix_ms",
    "complete",
    "warnings",
}


class MemoryEvidenceError(Exception):
    def __init__(self, code, outcome="incomplete"):
        self.code, self.outcome = code, outcome
        super().__init__(code)


def keys(value, fields, code="invalid-memory-evidence"):
    if not isinstance(value, dict) or value.keys() != fields:
        raise MemoryEvidenceError(code)


def integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise MemoryEvidenceError("invalid-memory-evidence")


def digest(value, size):
    if not isinstance(value, str) or not re.fullmatch(
        r"[a-f0-9]{" + str(size) + "}", value
    ):
        raise MemoryEvidenceError("invalid-memory-evidence")


def host_profile(value):
    keys(value, HOST_HASHES)
    for item in value.values():
        digest(item, 64)


def validate_request(value):
    try:
        keys(
            value,
            {"request_id", "selector", "host_profile", "owner_tag", "generation_tag"},
        )
        digest(value["request_id"], 32)
        selector = value["selector"]
        keys(selector, {"origin", "node", "kind", "vmid"})
        for field in ("origin", "node"):
            if not isinstance(selector[field], str) or not NAME.fullmatch(
                selector[field]
            ):
                raise MemoryEvidenceError("invalid-memory-request")
        if selector["kind"] != "proxmox.lxc":
            raise MemoryEvidenceError("invalid-memory-request")
        integer(selector["vmid"], 100, 999999999)
        host_profile(value["host_profile"])
        for field, prefix in (
            ("owner_tag", "cmdmesh-own-"),
            ("generation_tag", "cmdmesh-gen-"),
        ):
            item = value[field]
            if not isinstance(item, str) or not re.fullmatch(
                prefix + r"[a-f0-9]{32}", item
            ):
                raise MemoryEvidenceError("invalid-memory-request")
    except MemoryEvidenceError:
        raise MemoryEvidenceError("invalid-memory-request", "rejected") from None
    return value


def validate_evidence(value, expected, *, now_ms, max_age_seconds=30):
    """Validate assertions only; a live collector must establish their provenance."""
    validate_request(expected)
    integer(now_ms, 0, 2**63 - 1)
    integer(max_age_seconds, 1, 120)
    keys(value, FIELDS)
    if value["document_type"] != "cmdmesh.proxmox.lxc-memory.observation":
        raise MemoryEvidenceError("invalid-memory-evidence")
    if type(value["schema_version"]) is not int:
        raise MemoryEvidenceError("invalid-memory-evidence")
    if value["schema_version"] != 1:
        raise MemoryEvidenceError("memory-evidence-version-unsupported", "unsupported")
    digest(value["request_id"], 32)
    integer(value["vmid"], 100, 999999999)
    for field in ("origin", "node"):
        if not isinstance(value[field], str) or not NAME.fullmatch(value[field]):
            raise MemoryEvidenceError("invalid-memory-evidence")
    host_profile(value["host_profile"])
    digest(value["host_boot_id_sha256"], 64)
    config = value["configuration"]
    keys(
        config, {"digest", "memory_mb", "swap_mb", "other_sha256", "locked", "pending"}
    )
    digest(config["digest"], 40)
    digest(config["other_sha256"], 64)
    integer(config["memory_mb"], 16, 2**31 - 1)
    integer(config["swap_mb"], 0, 2**31 - 1)
    if type(config["locked"]) is not bool or type(config["pending"]) is not bool:
        raise MemoryEvidenceError("invalid-memory-evidence")
    runtime = value["runtime"]
    keys(
        runtime,
        {"status", "memory_limit_bytes", "init_start_ticks", "pid_namespace_inode"},
    )
    if runtime["status"] not in ("running", "stopped"):
        raise MemoryEvidenceError("invalid-memory-evidence")
    integer(runtime["memory_limit_bytes"], 0, 2**63 - 1)
    integer(runtime["init_start_ticks"], 1, 2**63 - 1)
    integer(runtime["pid_namespace_inode"], 1, 2**63 - 1)
    capacity = value["host_capacity"]
    keys(capacity, {"total_bytes", "available_bytes"})
    integer(capacity["total_bytes"], 1, 2**63 - 1)
    integer(capacity["available_bytes"], 0, capacity["total_bytes"])
    keys(value["versions"], {"pve-manager", "pve-container"})
    if not all(
        isinstance(item, str) and len(item) <= 128
        for item in value["versions"].values()
    ):
        raise MemoryEvidenceError("invalid-memory-evidence")
    integer(value["observed_at_unix_ms"], 0, 2**63 - 1)
    if type(value["complete"]) is not bool or not isinstance(value["warnings"], list):
        raise MemoryEvidenceError("invalid-memory-evidence")
    if len(value["warnings"]) > 32 or not all(
        isinstance(item, str) and len(item) <= 256 for item in value["warnings"]
    ):
        raise MemoryEvidenceError("invalid-memory-evidence")
    tags = value["tags"]
    if (
        not isinstance(tags, list)
        or len(tags) > 128
        or not all(isinstance(tag, str) and 0 < len(tag) <= 256 for tag in tags)
    ):
        raise MemoryEvidenceError("invalid-memory-evidence")

    wanted = {**expected["selector"], "request_id": expected["request_id"]}
    if any(value[field] != item for field, item in wanted.items()):
        raise MemoryEvidenceError("memory-identity-mismatch", "rejected")
    if value["host_profile"] != expected["host_profile"]:
        raise MemoryEvidenceError("memory-host-profile-mismatch", "rejected")
    required = {"cmdmesh-ansible", expected["owner_tag"], expected["generation_tag"]}
    if (
        not required <= set(tags)
        or len(set(tags)) != len(tags)
        or "cmdmesh-terraform" in tags
        or sum(tag.startswith("cmdmesh-own-") for tag in tags) != 1
        or sum(tag.startswith("cmdmesh-gen-") for tag in tags) != 1
    ):
        raise MemoryEvidenceError("memory-ownership-unqualified", "rejected")
    if not value["complete"] or value["warnings"]:
        raise MemoryEvidenceError("memory-evidence-incomplete")
    if not 0 <= now_ms - value["observed_at_unix_ms"] <= max_age_seconds * 1000:
        raise MemoryEvidenceError("memory-evidence-time-unqualified")
    versions = value["versions"]
    if (versions["pve-manager"], versions["pve-container"]) not in SUPPORTED_VERSIONS:
        raise MemoryEvidenceError("memory-version-unsupported", "unsupported")
    physical = {
        "ca_certificate_sha256": value["host_profile"]["ca_certificate_sha256"],
        "machine_id_sha256": value["host_profile"]["machine_id_sha256"],
        "node": value["node"],
        "kind": value["kind"],
        "vmid": value["vmid"],
    }
    result = copy.deepcopy(value)
    result.update(
        subject_key=hashlib.sha256(
            json.dumps(physical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        validation_scope="supplied-evidence-only",
        current_observation=False,
        mutation_authorized=False,
    )
    return result


def validate_observation(value, expected, *, now_ms, max_age_seconds=30):
    result = validate_evidence(
        value, expected, now_ms=now_ms, max_age_seconds=max_age_seconds
    )
    require_ready(result)
    return result


def require_ready(value):
    """Require readiness after typed evidence validation; grants no authority."""
    config, runtime = value["configuration"], value["runtime"]
    if config["locked"] or config["pending"]:
        raise MemoryEvidenceError("memory-configuration-unqualified")
    if (
        runtime["status"] != "running"
        or runtime["memory_limit_bytes"] != config["memory_mb"] * 1024**2
    ):
        raise MemoryEvidenceError("memory-runtime-unqualified")


def capacity_policy(value):
    try:
        keys(value, {"mode", "minimum_remaining_bytes"})
        if value["mode"] != "observed-available-headroom":
            raise MemoryEvidenceError("invalid-memory-policy")
        integer(value["minimum_remaining_bytes"], 0, 2**63 - 1)
    except MemoryEvidenceError:
        raise MemoryEvidenceError("invalid-memory-policy", "rejected") from None
    return value


def growth(desired, baseline):
    try:
        integer(desired, 16, 2**31 - 1)
    except MemoryEvidenceError:
        raise MemoryEvidenceError("invalid-memory-desired", "rejected") from None
    delta = desired - baseline["configuration"]["memory_mb"]
    if delta < 0:
        raise MemoryEvidenceError("memory-growth-required", "rejected")
    return delta * 1024**2


def check_capacity(desired, baseline, fresh, policy):
    delta = growth(desired, baseline)
    policy = capacity_policy(policy)
    if delta == 0:
        return
    required = delta + policy["minimum_remaining_bytes"]
    if required > fresh["host_capacity"]["available_bytes"]:
        raise MemoryEvidenceError("memory-capacity-insufficient", "rejected")


def prepare(request, observation, desired_memory_mb, policy, *, now_ms):
    """Freeze supplied assertions. The calling live facade owns provenance."""
    validated = validate_observation(observation, request, now_ms=now_ms)
    check_capacity(desired_memory_mb, observation, observation, policy)
    return copy.deepcopy(
        {
            "document_type": "cmdmesh.proxmox.lxc-memory.prepared",
            "schema_version": 1,
            "request": request,
            "subject_key": validated["subject_key"],
            "desired_memory_mb": desired_memory_mb,
            "change_required": desired_memory_mb
            != observation["configuration"]["memory_mb"],
            "capacity_policy": policy,
            "baseline": observation,
        }
    )


def validate_prepared(value):
    keys(
        value,
        {
            "document_type",
            "schema_version",
            "request",
            "subject_key",
            "desired_memory_mb",
            "change_required",
            "capacity_policy",
            "baseline",
        },
        "invalid-memory-prepared",
    )
    if (
        value["document_type"] != "cmdmesh.proxmox.lxc-memory.prepared"
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise MemoryEvidenceError("invalid-memory-prepared", "rejected")
    baseline = value["baseline"]
    if not isinstance(baseline, dict):
        raise MemoryEvidenceError("invalid-memory-prepared", "rejected")
    # A frozen historical baseline is validated at its own collection time.
    # Freshness is required separately for each current pre/post observation.
    validated = validate_observation(
        baseline, value["request"], now_ms=baseline.get("observed_at_unix_ms")
    )
    if value["subject_key"] != validated["subject_key"]:
        raise MemoryEvidenceError("invalid-memory-prepared", "rejected")
    check_capacity(
        value["desired_memory_mb"], baseline, baseline, value["capacity_policy"]
    )
    if type(value["change_required"]) is not bool or value["change_required"] != (
        value["desired_memory_mb"] != baseline["configuration"]["memory_mb"]
    ):
        raise MemoryEvidenceError("invalid-memory-prepared", "rejected")
    return value


def continuity(prepared, fresh, *, now_ms):
    validate_prepared(prepared)
    current = validate_observation(fresh, prepared["request"], now_ms=now_ms)
    before = prepared["baseline"]
    if fresh["observed_at_unix_ms"] < before["observed_at_unix_ms"]:
        raise MemoryEvidenceError("memory-evidence-time-unqualified")
    if fresh["host_boot_id_sha256"] != before["host_boot_id_sha256"]:
        raise MemoryEvidenceError("memory-host-boot-changed", "rejected")
    if any(
        fresh["runtime"][key] != before["runtime"][key]
        for key in ("init_start_ticks", "pid_namespace_inode")
    ):
        raise MemoryEvidenceError("memory-runtime-changed", "rejected")
    if (
        current["subject_key"] != prepared["subject_key"]
        or fresh["tags"] != before["tags"]
        or fresh["versions"] != before["versions"]
        or fresh["host_capacity"]["total_bytes"]
        != before["host_capacity"]["total_bytes"]
        or any(
            fresh["configuration"][key] != before["configuration"][key]
            for key in ("swap_mb", "other_sha256")
        )
    ):
        raise MemoryEvidenceError("memory-unrelated-state-changed", "rejected")
    return {
        "document_type": "cmdmesh.proxmox.lxc-memory.checks",
        "schema_version": 1,
        "subject_key": prepared["subject_key"],
        "change_required": prepared["change_required"],
        "checks": {
            "host-guest-identity": True,
            "ownership-generation": True,
            "host-boot-continuity": True,
            "runtime-continuity": True,
            "unchanged-state": True,
            "fresh-complete": True,
            "configuration-ready": True,
        },
        "validation_scope": "supplied-evidence-only",
        "current_observation": False,
        "mutation_authorized": False,
    }


def preflight(prepared, fresh, *, now_ms):
    result = continuity(prepared, fresh, now_ms=now_ms)
    if fresh["configuration"] != prepared["baseline"]["configuration"]:
        raise MemoryEvidenceError("memory-preimage-changed", "rejected")
    check_capacity(
        prepared["desired_memory_mb"],
        prepared["baseline"],
        fresh,
        prepared["capacity_policy"],
    )
    result["phase"] = "preflight"
    result["checks"].update({"configuration-preimage": True, "capacity-headroom": True})
    return result


def verify(prepared, fresh, *, now_ms):
    result = postconditions(prepared, fresh, now_ms=now_ms)
    for check, code in (
        ("host-boot-continuity", "memory-host-boot-changed"),
        ("runtime-continuity", "memory-runtime-changed"),
        ("unchanged-state", "memory-unrelated-state-changed"),
        ("configuration-ready", "memory-configuration-unqualified"),
        ("configuration-target", "memory-postcondition-failed"),
        ("enforced-memory-target", "memory-runtime-unqualified"),
        ("configuration-digest-transition", "memory-config-digest-unqualified"),
    ):
        if not result["checks"][check]:
            raise MemoryEvidenceError(code)
    return result


def postconditions(prepared, fresh, *, now_ms):
    """Compute all fixed checks over typed evidence, retaining known mismatches."""
    validate_prepared(prepared)
    current = validate_evidence(fresh, prepared["request"], now_ms=now_ms)
    before = prepared["baseline"]
    if fresh["observed_at_unix_ms"] < before["observed_at_unix_ms"]:
        raise MemoryEvidenceError("memory-evidence-time-unqualified")
    checks = {
        "host-guest-identity": current["subject_key"] == prepared["subject_key"],
        "ownership-generation": True,
        "fresh-complete": True,
        "host-boot-continuity": fresh["host_boot_id_sha256"]
        == before["host_boot_id_sha256"],
        "runtime-continuity": fresh["runtime"]["status"] == "running"
        and all(
            fresh["runtime"][key] == before["runtime"][key]
            for key in ("init_start_ticks", "pid_namespace_inode")
        ),
        "unchanged-state": fresh["tags"] == before["tags"]
        and fresh["versions"] == before["versions"]
        and fresh["host_capacity"]["total_bytes"]
        == before["host_capacity"]["total_bytes"]
        and all(
            fresh["configuration"][key] == before["configuration"][key]
            for key in ("swap_mb", "other_sha256")
        ),
        "configuration-ready": not fresh["configuration"]["locked"]
        and not fresh["configuration"]["pending"],
        "configuration-target": fresh["configuration"]["memory_mb"]
        == prepared["desired_memory_mb"],
        "enforced-memory-target": fresh["runtime"]["memory_limit_bytes"]
        == prepared["desired_memory_mb"] * 1024**2,
        "configuration-digest-transition": (
            fresh["configuration"]["digest"] != before["configuration"]["digest"]
        )
        == prepared["change_required"],
    }
    return {
        "document_type": "cmdmesh.proxmox.lxc-memory.checks",
        "schema_version": 1,
        "subject_key": prepared["subject_key"],
        "change_required": prepared["change_required"],
        "phase": "verify",
        "checks": checks,
        "satisfied": all(checks.values()),
        "validation_scope": "supplied-evidence-only",
        "current_observation": False,
        "mutation_authorized": False,
    }
