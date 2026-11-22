"""Finite Proxmox inspections. No repair, arbitrary command or mutation action."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_RESOURCES = 20000
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
KINDS = {"proxmox.node", "proxmox.lxc", "proxmox.vm"}
VERSION = "0.2.0"

GUIDANCE = {
    "origin-mismatch": (
        "The requested origin differs from the selected source",
        [
            "Compare input.selector.origin with source.origin (offline) or private config.origin (live)",
            "Verify the selected endpoint and trusted CA before choosing an identity",
        ],
        [
            "Correct the origin reference and recollect; do not search another installation implicitly"
        ],
    ),
    "invalid-selector": (
        "The selector is not an exact typed identity",
        [
            "Provide origin, node, kind and an integer vmid for guests; node kind has no vmid"
        ],
        [
            "Correct the explicit identity; do not substitute a guest name or first match"
        ],
    ),
    "duplicate-resource": (
        "The source repeats an exact resource identity",
        [
            "Inspect duplicate kind/id records in the private source and recollect the selected origin"
        ],
        ["Keep the target unresolved until the conflicting evidence is reconciled"],
    ),
    "inconsistent-identity": (
        "Resource properties disagree with the canonical node/vmid identity",
        [
            "Compare resource id with properties.node and properties.vmid, including numeric types"
        ],
        [
            "Correct or recollect the source; never relabel the target to make the check pass"
        ],
    ),
    "missing-node-evidence": (
        "A guest references a node absent from the source",
        ["Check the node collection and token visibility for the selected origin"],
        [
            "Recollect complete evidence; do not bootstrap privileges as an inspection side effect"
        ],
    ),
    "source-incomplete": (
        "One or more inventory collections are incomplete or warned",
        [
            "Check private source collection errors, effective API read privileges and transport limits"
        ],
        [
            "Recollect after the cause is resolved; a visible candidate does not establish complete scope"
        ],
    ),
    "api-authentication-failed": (
        "The configured API token was not authenticated",
        [
            "Check config.api.token_id_env and token_secret_env references in the private launch environment",
            "Verify the existing credential record without printing its values",
        ],
        [
            "Correct the reference or follow the existing credential recovery process; no automatic renewal"
        ],
    ),
    "api-permission-denied": (
        "The token lacks permission for a required read",
        ["Check effective token ACLs for the requested node and guest collections"],
        [
            "Resolve the declared read scope separately; inspection does not broaden privileges"
        ],
    ),
    "api-transport-or-trust-failed": (
        "The API transport or certificate validation failed",
        ["Check the selected endpoint, DNS/TCP path, trusted CA and certificate name"],
        [
            "Correct the explicit path or trust input; never disable verification as a fallback"
        ],
    ),
    "invalid-trust-file": (
        "The selected trust input is not a regular file",
        [
            "Check config.api.ca_file and its file type; FIFOs and devices are unsupported"
        ],
        [
            "Supply a verified regular PEM CA file without replacing the server certificate"
        ],
    ),
    "trust-unavailable": (
        "The configured CA trust cannot be loaded",
        ["Check the private CA path, permissions and PEM certificate format"],
        [
            "Recover the trust anchor over an already trusted channel; do not fetch and trust an unverified peer"
        ],
    ),
    "trust-input-changed": (
        "Trust configuration changed during collection",
        ["Compare the configured CA file before and after the operation"],
        [
            "Review the trust change and recollect; the interrupted evidence is not current verification"
        ],
    ),
    "target-not-observed": (
        "The exact target is absent from the reported complete scope",
        [
            "Check the selected origin, node, kind and vmid against expected inventory and API visibility"
        ],
        [
            "Correct or independently qualify that scope; do not infer deletion across other origins"
        ],
    ),
}


class InspectionError(Exception):
    def __init__(self, code, outcome="rejected"):
        self.code = code
        self.outcome = outcome


class InspectionDeadline(BaseException):
    pass


def keys(value, required, optional=(), code="invalid-input"):
    if (
        not isinstance(value, dict)
        or not set(required) <= set(value)
        or set(value) - set(required) - set(optional)
    ):
        raise InspectionError(code)


def name(value, code="invalid-selector"):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise InspectionError(code)


def integer(value, lower, upper, code="invalid-input"):
    if type(value) is not int or not lower <= value <= upper:
        raise InspectionError(code)


def response(operation, outcome, data=None, code=None):
    diagnostics = []
    if code:
        summary, checks, recovery = GUIDANCE.get(
            code,
            (
                code.replace("-", " "),
                [
                    "Use describe to inspect the supported request schema and the selected private source"
                ],
                [
                    "Correct or recollect the explicit input; do not repair or retry uncertain work automatically"
                ],
            ),
        )
        diagnostics.append(
            {
                "code": code,
                "summary": summary,
                "next_checks": list(checks),
                "recovery": list(recovery),
            }
        )
    return {
        "document_type": "cmdmesh.inspection.result",
        "schema_version": 1,
        "operation": operation,
        "outcome": outcome,
        "data": data or {},
        "diagnostics": diagnostics,
    }


def object_schema(properties, required):
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


def target_schema():
    identifier = {"type": "string", "pattern": NAME.pattern, "not": {"pattern": "\\s"}}
    common = {"origin": identifier, "node": identifier}
    node = object_schema(
        {**common, "kind": {"const": "proxmox.node"}}, ["origin", "node", "kind"]
    )
    guest = object_schema(
        {
            **common,
            "kind": {"enum": ["proxmox.lxc", "proxmox.vm"]},
            "vmid": {"type": "integer", "minimum": 100, "maximum": 999999999},
        },
        ["origin", "node", "kind", "vmid"],
    )
    inventory = object_schema(
        {
            "schema_version": {"const": 1},
            "complete": {"type": "boolean"},
            "resources": {
                "type": "array",
                "maxItems": MAX_RESOURCES,
                "items": object_schema(
                    {
                        "kind": {"enum": sorted(KINDS)},
                        "id": {"type": "string", "minLength": 1},
                        "properties": {"type": "object"},
                    },
                    ["kind", "id", "properties"],
                ),
            },
            "warnings": {
                "type": "array",
                "maxItems": 10000,
                "items": {"type": "string"},
            },
        },
        ["schema_version", "complete", "resources", "warnings"],
    )
    offline = object_schema(
        {
            "mode": {"const": "offline"},
            "origin": identifier,
            "snapshot": inventory,
            "observed_at_unix_ms": {"type": ["integer", "null"], "minimum": 0},
        },
        ["mode", "origin", "snapshot"],
    )
    live = object_schema({"mode": {"const": "live"}}, ["mode"])
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        **object_schema(
            {
                "source": {"oneOf": [offline, live]},
                "selector": {"oneOf": [node, guest]},
                "max_age_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 86400,
                    "default": 60,
                },
            },
            ["source", "selector"],
        ),
    }


def describe():
    return {
        "integration": "cmdmesh-proxmox",
        "version": VERSION,
        "actions": [
            {
                "id": "target-resolve",
                "aliases": ["find guest", "resolve exact proxmox target"],
                "input_schema": target_schema(),
                "required_input": {
                    "source": "Explicit offline snapshot and origin, or live mode with private API configuration",
                    "selector": "origin, node, kind and guest vmid; node kind has no vmid",
                },
                "expected_result": "One internally consistent exact identity, with source/freshness limits; no mutation authority",
                "known_failures": [
                    "origin-mismatch",
                    "invalid-snapshot",
                    "duplicate-resource",
                    "source-incomplete",
                    "target-not-observed",
                ],
                "recovery": "Correct or recollect the explicit source; never choose the first duplicate or disable TLS",
                "limits": [
                    "Offline assertions are never live observations",
                    "Collection completeness does not prove all token ACL visibility",
                ],
            }
        ],
    }


def selector(value):
    keys(value, {"origin", "node", "kind"}, {"vmid"}, "invalid-selector")
    name(value["origin"])
    name(value["node"])
    if not isinstance(value["kind"], str) or value["kind"] not in KINDS:
        raise InspectionError("invalid-selector")
    if value["kind"] == "proxmox.node":
        if "vmid" in value:
            raise InspectionError("invalid-selector")
        return value["node"]
    if "vmid" not in value:
        raise InspectionError("invalid-selector")
    integer(value["vmid"], 100, 999999999, "invalid-selector")
    return f"{value['node']}/{value['vmid']}"


def snapshot(value):
    keys(
        value,
        {"schema_version", "complete", "resources", "warnings"},
        code="invalid-snapshot",
    )
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or type(value["complete"]) is not bool
    ):
        raise InspectionError("invalid-snapshot")
    resources, warnings = value["resources"], value["warnings"]
    if (
        not isinstance(resources, list)
        or len(resources) > MAX_RESOURCES
        or not isinstance(warnings, list)
        or len(warnings) > 10000
        or not all(isinstance(warning, str) for warning in warnings)
    ):
        raise InspectionError("invalid-snapshot")
    seen, nodes, guest_nodes = set(), set(), set()
    for row in resources:
        keys(row, {"kind", "id", "properties"}, code="invalid-snapshot")
        kind, identity, properties = row["kind"], row["id"], row["properties"]
        if (
            not isinstance(kind, str)
            or kind not in KINDS
            or not isinstance(identity, str)
            or not isinstance(properties, dict)
        ):
            raise InspectionError("invalid-snapshot")
        if (kind, identity) in seen:
            raise InspectionError("duplicate-resource")
        seen.add((kind, identity))
        if kind == "proxmox.node":
            name(identity, "invalid-snapshot")
            if properties.get("node", identity) != identity or "vmid" in properties:
                raise InspectionError("inconsistent-identity")
            nodes.add(identity)
        else:
            node, vmid = properties.get("node"), properties.get("vmid")
            name(node, "inconsistent-identity")
            integer(vmid, 100, 999999999, "inconsistent-identity")
            if identity != f"{node}/{vmid}":
                raise InspectionError("inconsistent-identity")
            guest_nodes.add(node)
    if guest_nodes - nodes:
        raise InspectionError("missing-node-evidence")
    return resources


def freshness(source, now_ms, max_age):
    observed = source.get("observed_at_unix_ms")
    if observed is None:
        return {"status": "unknown", "age_seconds": None}
    integer(observed, 0, 2**63 - 1, "invalid-source-time")
    if observed > now_ms:
        return {"status": "invalid", "age_seconds": None}
    age = (now_ms - observed) / 1000
    recent = "recent" if source.get("mode") == "live" else "reported-recent"
    return {"status": recent if age <= max_age else "stale", "age_seconds": age}


def provider_config(value):
    keys(
        value,
        {"schema_version"},
        {"origin", "api", "controller", "ssh"},
        "invalid-provider-config",
    )
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise InspectionError("unsupported-provider-config", "unsupported")
    return value


def source_binding(api):
    material = {"api": api}
    if "ca_file" in api:
        if not isinstance(api["ca_file"], str) or not api["ca_file"]:
            raise InspectionError("invalid-trust-file")
        path = Path(api["ca_file"])
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError:
            raise InspectionError("trust-unavailable") from None
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise InspectionError("invalid-trust-file")
        with os.fdopen(descriptor, "rb") as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            raise InspectionError("trust-file-too-large")
        material["ca_sha256"] = hashlib.sha256(data).hexdigest()
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def collect_source(value, config, identity, now_ms):
    if not isinstance(value, dict):
        raise InspectionError("invalid-source")
    if value.get("mode") == "offline":
        keys(
            value,
            {"mode", "origin", "snapshot"},
            {"observed_at_unix_ms"},
            "invalid-source",
        )
        name(value["origin"], "invalid-source")
        if value["origin"] != identity["origin"]:
            raise InspectionError("origin-mismatch")
        return {
            "snapshot": value["snapshot"],
            "mode": "offline",
            "now_ms": now_ms,
            "observed_at_unix_ms": value.get("observed_at_unix_ms"),
            "info": {
                "mode": "offline",
                "origin": value["origin"],
                "provenance": "caller-asserted",
                "collection_scope": "caller-supplied-snapshot",
                "visibility_qualified": False,
            },
        }
    if value.get("mode") != "live":
        raise InspectionError("unsupported-source-mode", "unsupported")
    keys(value, {"mode"}, code="invalid-source")
    configured = provider_config(config)
    if "origin" not in configured or "api" not in configured:
        raise InspectionError("api-configuration-required")
    if not isinstance(configured["api"], dict):
        raise InspectionError("invalid-provider-config")
    name(configured["origin"], "invalid-provider-config")
    if configured["origin"] != identity["origin"]:
        raise InspectionError("origin-mismatch")
    # inventory is the unchanged public source embedded inside this zipapp.
    # No mutable sibling module or externally selected executable is imported.
    import inventory

    api = configured["api"]
    try:
        binding = source_binding(api)
        inventory.validate_config(api)
        started = time.time_ns() // 1000000
        monotonic_started = time.monotonic()
        observed = inventory.inventory(api)
        completed = time.time_ns() // 1000000
        elapsed = time.monotonic() - monotonic_started
        if source_binding(api) != binding:
            raise InspectionError("trust-input-changed", "unavailable")
    except inventory.InventoryError as error:
        diagnostic = {
            "API request failed with HTTP 401": "api-authentication-failed",
            "API request failed with HTTP 403": "api-permission-denied",
            "API transport or TLS validation failed": "api-transport-or-trust-failed",
            "Required credential environment value is unavailable or invalid": "credentials-unavailable",
            "Cannot load the configured CA trust": "trust-unavailable",
        }.get(str(error), "api-collection-failed")
        raise InspectionError(diagnostic, "unavailable") from None
    return {
        "snapshot": observed,
        "mode": "live",
        "now_ms": completed,
        "observed_at_unix_ms": started,
        "elapsed_seconds": elapsed,
        "info": {
            "mode": "live",
            "origin": configured["origin"],
            "provenance": "configured-provider-invocation",
            "configuration_sha256": binding,
            "collection_scope": "configured-api-endpoint",
            "visibility_qualified": False,
            "collection_started_at_unix_ms": started,
            "collection_completed_at_unix_ms": completed,
        },
    }


def resolve_target(value, config, now_ms):
    keys(value, {"source", "selector"}, {"max_age_seconds"})
    identity = value["selector"]
    resource_id = selector(identity)
    max_age = value.get("max_age_seconds", 60)
    integer(max_age, 1, 86400)
    source = collect_source(value["source"], config, identity, now_ms)
    resources = snapshot(source["snapshot"])
    selected = next(
        (
            row
            for row in resources
            if row["kind"] == identity["kind"] and row["id"] == resource_id
        ),
        None,
    )
    complete = source["snapshot"]["complete"] and not source["snapshot"]["warnings"]
    actual_identity = None
    if selected:
        actual_identity = {
            "origin": source["info"]["origin"],
            "kind": selected["kind"],
            "node": (
                selected["id"]
                if selected["kind"] == "proxmox.node"
                else selected["properties"]["node"]
            ),
        }
        if selected["kind"] != "proxmox.node":
            actual_identity["vmid"] = selected["properties"]["vmid"]
    source["info"]["snapshot_sha256"] = hashlib.sha256(
        json.dumps(source["snapshot"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    fresh = freshness(source, source["now_ms"], max_age)
    if source["mode"] == "live" and fresh["status"] != "invalid":
        fresh["age_seconds"] = max(fresh["age_seconds"], source["elapsed_seconds"])
        if fresh["age_seconds"] > max_age:
            fresh["status"] = "stale"
    data = {
        "resolution": "resolved" if selected else "absent",
        "identity": actual_identity,
        "source": source["info"],
        "freshness": fresh,
        "complete": complete,
        "current_observation": False,
        "mutation_authorized": False,
    }
    if not complete:
        data["resolution"] = "indeterminate"
        return response("target-resolve", "incomplete", data, "source-incomplete")
    if source["mode"] == "live" and fresh["status"] != "recent":
        data["resolution"] = "indeterminate"
        return response(
            "target-resolve", "incomplete", data, "source-time-not-qualified"
        )
    data["current_observation"] = source["mode"] == "live" and selected is not None
    return response(
        "target-resolve",
        "observed" if selected else "rejected",
        data,
        None if selected else "target-not-observed",
    )


def dispatch(request, now_ms=None):
    operation = (
        request.get("operation", "invalid-request")
        if isinstance(request, dict)
        else "invalid-request"
    )
    if not isinstance(operation, str) or not NAME.fullmatch(operation):
        operation = "invalid-request"
    try:
        keys(
            request,
            {"document_type", "schema_version", "operation", "input", "config"},
            code="invalid-request",
        )
        if (
            request["document_type"] != "cmdmesh.inspection.request"
            or type(request["schema_version"]) is not int
            or request["schema_version"] != 1
        ):
            raise InspectionError("unsupported-request-version", "unsupported")
        if not isinstance(request["input"], dict) or not isinstance(
            request["config"], dict
        ):
            raise InspectionError("invalid-request")
        if operation == "describe":
            keys(request["input"], set())
            return response(operation, "observed", describe())
        if operation == "target-resolve":
            return resolve_target(
                request["input"],
                request["config"],
                now_ms if now_ms is not None else time.time_ns() // 1000000,
            )
        raise InspectionError("unsupported-operation", "unsupported")
    except InspectionError as error:
        return response(operation, error.outcome, code=error.code)


def load_json(stream):
    raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise InspectionError("input-too-large")
    try:
        return json.loads(
            raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError())
        )
    except (ValueError, UnicodeError):
        raise InspectionError("invalid-json") from None


def load_file(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise InspectionError("input-not-regular-file")
    with os.fdopen(descriptor, "rb") as stream:
        return load_json(stream)


def deadline(_signal, _frame):
    raise InspectionDeadline()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version", action="version", version=f"cmdmesh-proxmox-inspect {VERSION}"
    )
    parser.add_argument("--input", type=Path)
    parser.add_argument("--config", type=Path)
    args = parser.parse_args()
    operation = "invalid-request"
    try:
        if hasattr(signal, "SIGALRM"):
            signal.signal(signal.SIGALRM, deadline)
            signal.alarm(120)
        if args.config and not args.input:
            raise InspectionError("config-requires-input-file")
        if args.input:
            request = load_file(args.input)
            keys(
                request,
                {"document_type", "schema_version", "operation", "input"},
                code="invalid-request",
            )
            request["config"] = load_file(args.config) if args.config else {}
        else:
            request = load_json(sys.stdin.buffer)
        if (
            isinstance(request, dict)
            and isinstance(request.get("operation"), str)
            and NAME.fullmatch(request["operation"])
        ):
            operation = request["operation"]
        result = dispatch(request)
    except InspectionDeadline:
        result = response(operation, "unavailable", code="inspection-deadline")
    except InspectionError as error:
        result = response(operation, error.outcome, code=error.code)
    except (OSError, ValueError, TypeError, RecursionError):
        result = response(operation, "rejected", code="invalid-inspection-input")
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)
    print(json.dumps(result, separators=(",", ":"), allow_nan=False))
    return 0 if result["outcome"] == "observed" else 1
