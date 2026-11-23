"""Fixed live memory preparation/preflight/verification; never dispatches changes."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
import zipimport

import memory_collect
import memory_remote
import memory_state
import probes

PROFILE_ID = "proxmox-lxc-memory"
COLLECTION = "ansible/ansible_collections/cmdmesh/proxmox/plugins/"
PROFILE_FILES = {
    COLLECTION + name
    for name in (
        "modules/lxc_memory.py",
        "module_utils/memory_state.py",
        "module_utils/memory_remote.py",
    )
}
MAX_REFERENCE_BYTES = 16 * 1024 * 1024
TOOL_REQUIREMENTS = {
    "ansible-playbook": {"minimum": "2.19.4", "maximum_exclusive": "2.21.0"},
    "ssh": {"minimum": "8.9.0", "maximum_exclusive": "11.0.0"},
}
GUIDANCE = {
    "memory-reference-changed": (
        "A referenced trust, identity or tool file changed during collection",
        "Compare the explicit reference paths and hashes; the CA must match the bytes actually loaded",
        "Stabilize the intended inputs and prepare again; no change was dispatched",
    ),
    "memory-profile-invalid": (
        "The bundled driver profile does not match its captured helper code",
        "Check the reviewed artifact digest and matching source checkout",
        "Rebuild or restore the qualified artifact; do not substitute a mutable metadata file",
    ),
    "memory-profile-unsupported": (
        "The bundled memory profile version is unsupported",
        "Use describe and the qualified profile/source version pair",
        "Select matching reviewed components before preparing a change",
    ),
    "memory-postconditions-failed": (
        "Current same-subject evidence failed required postconditions",
        "Inspect each false check and the retained observation/source receipt",
        "Stop dependent work and reconcile actual state; do not replay, shrink or restart automatically",
    ),
    "invalid-memory-procedure": (
        "The procedure phase or typed input is invalid",
        "Use prepare with a request/desired memory/policy, or pass its unchanged prepared intent to preflight/verify",
        "Correct the input; no after-snapshot or apply phase is accepted",
    ),
}


class PhaseError(Exception):
    def __init__(self, code, outcome="rejected"):
        self.code, self.outcome = code, outcome


def profile():
    if not isinstance(__loader__, zipimport.zipimporter):
        raise PhaseError("memory-profile-unavailable", "unavailable")
    try:
        value = memory_remote.load_json(__loader__.get_data("driver-profile.json"))
        if not isinstance(value, dict) or value.keys() != {
            "document_type",
            "schema_version",
            "profile_id",
            "profile_version",
            "files",
        }:
            raise ValueError()
        if (
            value["document_type"] != "cmdmesh.proxmox.driver-profile"
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or value["profile_id"] != PROFILE_ID
            or type(value["profile_version"]) is not int
            or value["profile_version"] != 1
        ):
            raise PhaseError("memory-profile-unsupported", "unsupported")
        files = value["files"]
        if (
            not isinstance(files, dict)
            or files.keys() != PROFILE_FILES
            or not all(
                isinstance(item, str) and re.fullmatch(r"[a-f0-9]{64}", item)
                for item in files.values()
            )
        ):
            raise ValueError()
        for name in ("memory_state.py", "memory_remote.py"):
            if (
                hashlib.sha256(__loader__.get_data(name)).hexdigest()
                != files[COLLECTION + "module_utils/" + name]
            ):
                raise ValueError()
        return value
    except (OSError, ValueError, KeyError, memory_remote.RemoteObservationError):
        raise PhaseError("memory-profile-invalid", "incomplete") from None


def reference(path):
    path = Path(path)
    if not path.is_absolute():
        path = Path.cwd() / path
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise PhaseError("memory-reference-unavailable", "unavailable")
        with os.fdopen(descriptor, "rb") as stream:
            data = stream.read(MAX_REFERENCE_BYTES + 1)
        if len(data) > MAX_REFERENCE_BYTES:
            raise PhaseError("memory-reference-unavailable", "unavailable")
        return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest()}
    except OSError:
        raise PhaseError("memory-reference-unavailable", "unavailable") from None


def references(config, *, driver):
    settings = config.get("ssh")
    probes.keys(
        settings,
        {"executable", "host", "port", "user", "identity_file", "known_hosts_file"},
    )
    if settings["user"] != "root":
        raise probes.ProbeError("invalid-probe-configuration")
    tls = config.get("tls")
    probes.tls_settings(tls)
    if "ca_file" not in tls:
        raise probes.ProbeError("memory-explicit-trust-required")
    paths = {
        "tls-ca": tls["ca_file"],
        "ssh-identity": probes.ssh_file(settings["identity_file"]),
        "ssh-known-hosts": probes.ssh_file(settings["known_hosts_file"]),
        "ssh-executable": probes.regular(settings["executable"], executable=True),
    }
    probes.scratch(config)
    if driver:
        tools = config["controller"].get("tools", {})
        if not isinstance(tools, dict) or tools.keys() - probes.VERSIONS.keys():
            raise probes.ProbeError("invalid-probe-configuration")
        paths["ansible-executable"] = probes.regular(
            tools.get("ansible-playbook"), executable=True
        )
    return {role: reference(path) for role, path in paths.items()}


def driver_context(config, bound):
    settings = config["ssh"]
    selected = copy.deepcopy(config)
    selected["controller"]["tools"] = {
        "ansible-playbook": bound["ansible-executable"]["path"],
        "ssh": settings["executable"],
    }
    checked = probes.controller(
        {
            "required_tools": TOOL_REQUIREMENTS,
            "minimum_free_bytes": 0,
        },
        selected,
    )
    return {
        "executable": bound["ansible-executable"]["path"],
        "executable_sha256": bound["ansible-executable"]["sha256"],
        "version": checked["tools"]["ansible-playbook"]["version"],
        "transport": {
            "policy": "strict-direct-ssh-v1",
            "ssh_executable": settings["executable"],
            "host": settings["host"],
            "port": settings["port"],
            "user": "root",
            "identity_file": settings["identity_file"],
            "known_hosts_file": settings["known_hosts_file"],
            "python_executable": "/usr/bin/python3",
        },
    }


def parse_input(value):
    if not isinstance(value, dict):
        raise PhaseError("invalid-memory-procedure")
    phase = value.get("phase")
    if phase == "prepare":
        memory_state.keys(
            value,
            {"phase", "request", "desired_memory_mb", "capacity_policy"},
            "invalid-memory-procedure",
        )
        wanted = copy.deepcopy(value["request"])
        if not isinstance(wanted, dict):
            raise PhaseError("invalid-memory-procedure")
        wanted.setdefault("request_id", secrets.token_hex(16))
        memory_state.validate_request(wanted)
        memory_state.integer(value["desired_memory_mb"], 16, 2**31 - 1)
        memory_state.capacity_policy(value["capacity_policy"])
        prepared = None
    elif phase in ("preflight", "verify"):
        memory_state.keys(value, {"phase", "prepared"}, "invalid-memory-procedure")
        prepared = memory_state.validate_prepared(value["prepared"])
        wanted = prepared["request"]
    else:
        raise PhaseError("invalid-memory-procedure")
    return phase, wanted, prepared


def assess(value, config):
    try:
        phase, wanted, prepared = parse_input(value)
    except memory_state.MemoryEvidenceError as error:
        raise PhaseError(error.code) from None
    if config.get("origin") != wanted["selector"]["origin"]:
        raise probes.ProbeError("origin-mismatch")
    manifest = profile()
    bound = references(config, driver=phase != "verify")
    driver = driver_context(config, bound) if phase != "verify" else None
    actual = memory_collect.collect_evidence(wanted, config)
    if (
        references(config, driver=phase != "verify") != bound
        or actual["source"]["trust"]["sha256"] != bound["tls-ca"]["sha256"]
    ):
        raise PhaseError("memory-reference-changed", "incomplete")
    now_ms = time.time_ns() // 1000000
    if phase == "prepare":
        prepared = memory_state.prepare(
            wanted,
            actual["observation"],
            value["desired_memory_mb"],
            value["capacity_policy"],
            now_ms=now_ms,
        )
    checks = (
        memory_state.postconditions(prepared, actual["observation"], now_ms=now_ms)
        if phase == "verify"
        else memory_state.preflight(prepared, actual["observation"], now_ms=now_ms)
    )["checks"]
    data = {
        "document_type": "cmdmesh.procedure.assessment",
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "profile_version": 1,
        "phase": phase,
        "subject_key": actual["subject_key"],
        "prepared_sha256": hashlib.sha256(
            json.dumps(
                prepared,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest(),
        "prepared": prepared,
        "checks": checks,
        "evidence": {
            "authenticated_current": True,
            "observation": actual["observation"],
            "source": actual["source"],
        },
        "driver": driver,
        "profile_files": manifest["files"],
        "references": bound,
        "mutation_authorized": False,
    }
    return data


def diagnostic(code):
    summary, check, recovery = GUIDANCE.get(
        code,
        memory_collect.GUIDANCE.get(
            code,
            probes.GUIDANCE.get(
                code,
                (
                    "The memory procedure assessment could not qualify the requested state",
                    "Check the fixed phase, unchanged prepared intent, profile files, explicit tools/access and current check results",
                    "Correct or recollect evidence separately; do not replay an uncertain change, shrink, restart or fabricate live state",
                ),
            ),
        ),
    )
    return {
        "code": code,
        "summary": summary,
        "next_checks": [check],
        "recovery": [recovery],
    }


def run(value, config):
    try:
        data = assess(value, config)
        satisfied = all(data["checks"].values())
        return {
            "outcome": "observed" if satisfied else "incomplete",
            "data": data,
            "diagnostics": (
                [] if satisfied else [diagnostic("memory-postconditions-failed")]
            ),
        }
    except (PhaseError, memory_state.MemoryEvidenceError, probes.ProbeError) as error:
        code, outcome = error.code, error.outcome
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        code, outcome = "invalid-memory-procedure", "rejected"
    return {"outcome": outcome, "data": {}, "diagnostics": [diagnostic(code)]}


def description():
    def obj(properties):
        return {
            "type": "object",
            "properties": properties,
            "required": list(properties),
            "additionalProperties": False,
        }

    prepared = {
        "type": "object",
        "description": "Opaque strict version-1 prepared intent returned by prepare; pass unchanged, never synthesize after evidence",
    }
    return {
        "id": "lxc-memory-procedure",
        "aliases": [
            "prepare owned memory growth",
            "check frozen memory intent",
            "verify actual memory postconditions",
        ],
        "input_schema": {
            "oneOf": [
                obj(
                    {
                        "phase": {"const": "prepare"},
                        "request": memory_collect.description()["input_schema"],
                        "desired_memory_mb": {
                            "type": "integer",
                            "minimum": 16,
                            "maximum": 2**31 - 1,
                        },
                        "capacity_policy": obj(
                            {
                                "mode": {"const": "observed-available-headroom"},
                                "minimum_remaining_bytes": {
                                    "type": "integer",
                                    "minimum": 0,
                                    "maximum": 2**63 - 1,
                                },
                            }
                        ),
                    }
                ),
                obj({"phase": {"enum": ["preflight", "verify"]}, "prepared": prepared}),
            ]
        },
        "required_configuration": "The memory observation TLS/root SSH/scratch profile; prepare/preflight additionally require controller.tools.ansible-playbook. Verify does not require Ansible.",
        "supported_tools": copy.deepcopy(TOOL_REQUIREMENTS),
        "expected_result": "Internally collected current evidence, frozen intent hash and fixed phase checks; no change dispatch or final procedure authority",
        "known_failures": [
            "invalid-memory-procedure",
            "memory-profile-invalid",
            "memory-profile-unsupported",
            "memory-reference-changed",
            "memory-postconditions-failed",
            "memory-capacity-insufficient",
        ],
        "recovery": "Inspect diagnostics/checks and reconcile actual state; no automatic apply, retry, restart, shrink or rollback",
        "limits": [
            "Planning reads remote state and local referenced file hashes; private keys are not copied or returned",
            "Driver byte identity must be matched against the collection by core before execution",
            "False checks retain current evidence with a negative result; source/identity loss cannot be upgraded to it",
        ],
    }
