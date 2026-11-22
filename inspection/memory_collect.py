"""Authenticated, fixed, read-only collection for the owned LXC memory profile."""

import copy
import hashlib
import json
import re
import secrets
import shlex
import time

import memory_remote
import memory_state
import probes


GUIDANCE = {
    "memory-explicit-trust-required": (
        "The memory profile requires one explicit private node CA",
        "Check tls.ca_file and the independently qualified host fingerprints",
        "Restore the intended private trust input; do not use runtime-default trust",
    ),
    "memory-host-profile-mismatch": (
        "The authenticated endpoint does not match the expected node profile",
        "Compare the pinned machine, private CA and standard node leaf fingerprints",
        "Requalify the intended host over an established channel; never replace pins from an unverified response",
    ),
    "memory-remote-failed": (
        "The fixed read-only remote collector could not complete",
        "Check the root identity, standard node certificates, package versions, native tools and selected running LXC",
        "Investigate the selected host separately; no repair or mutation was attempted",
    ),
    "memory-remote-evidence-invalid": (
        "The remote response is malformed, unexpected or does not match this collection",
        "Check the qualified collector, request correlation and collection time",
        "Recollect over the established channel; do not rewrite or reuse saved evidence as current",
    ),
    "invalid-memory-request": (
        "The requested memory observation is invalid",
        "Use describe and check the exact selector, host profile and ownership markers",
        "Correct the explicit request; offline frames and arbitrary commands are unsupported",
    ),
}


def collect(value, config):
    import inventory

    if not isinstance(value, dict):
        raise memory_state.MemoryEvidenceError("invalid-memory-request", "rejected")
    wanted = copy.deepcopy(value)
    wanted.setdefault("request_id", secrets.token_hex(16))
    memory_state.validate_request(wanted)
    if config.get("origin") != wanted["selector"]["origin"]:
        raise probes.ProbeError("origin-mismatch")
    settings = config.get("tls")
    if not isinstance(settings, dict) or "ca_file" not in settings:
        raise probes.ProbeError("memory-explicit-trust-required")
    probes.tls_settings(settings)
    if not isinstance(config.get("ssh"), dict) or config["ssh"].get("user") != "root":
        raise probes.ProbeError("invalid-probe-configuration")
    try:
        captured_ca = inventory.trust_snapshot(settings)
        if not re.fullmatch(
            rb"\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*",
            captured_ca,
        ):
            raise probes.ProbeError("memory-explicit-trust-required")
        context, trust = inventory.trust_context(captured_ca)
    except inventory.InventoryError:
        raise probes.ProbeError("tls-trust-unavailable", "unavailable") from None
    certificates = context.get_ca_certs(binary_form=True)
    profile = wanted["host_profile"]
    if len(certificates) != 1:
        raise probes.ProbeError("memory-explicit-trust-required")
    if hashlib.sha256(certificates[0]).hexdigest() != profile["ca_certificate_sha256"]:
        raise probes.ProbeError("memory-host-profile-mismatch")
    started = time.monotonic()
    started_ms = time.time_ns() // 1000000
    peer = probes.tls_handshake(settings, context, trust)
    if peer["peer_certificate_sha256"] != profile["leaf_certificate_sha256"]:
        raise probes.ProbeError("memory-host-profile-mismatch")
    source = memory_remote.__loader__.get_source(memory_remote.__name__)
    envelope = {"request": wanted, "observed_at_unix_ms": started_ms}
    command = (
        "/usr/bin/python3 -I -B -c "
        + shlex.quote(source)
        + " "
        + shlex.quote(json.dumps(envelope, sort_keys=True, separators=(",", ":")))
    )
    status, output = probes.ssh_command(
        config, command, timeout_seconds=30, strict_output=True
    )
    completed_ms = time.time_ns() // 1000000
    if time.monotonic() - started > 30:
        raise probes.ProbeError("probe-deadline", "unavailable")
    if status != 0:
        raise probes.ProbeError("memory-remote-failed", "unavailable")
    try:
        frame = memory_remote.load_json(output)
    except memory_remote.RemoteObservationError:
        raise probes.ProbeError(
            "memory-remote-evidence-invalid", "incomplete"
        ) from None
    if not isinstance(frame, dict) or frame.get("observed_at_unix_ms") != started_ms:
        raise probes.ProbeError("memory-remote-evidence-invalid", "incomplete")
    validated = memory_state.validate_observation(frame, wanted, now_ms=completed_ms)
    return {
        "observation": {key: validated[key] for key in memory_state.FIELDS},
        "subject_key": validated["subject_key"],
        "source": {
            "mode": "live",
            "collector_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "started_at_unix_ms": started_ms,
            "completed_at_unix_ms": completed_ms,
            "trust": trust,
            "tls_peer_sha256": peer["peer_certificate_sha256"],
            "ssh_host_key_checking": "strict",
        },
        "current_observation": True,
        "mutation_authorized": False,
    }


def run(value, config):
    try:
        return {
            "outcome": "observed",
            "data": collect(value, config),
            "diagnostics": [],
        }
    except (memory_state.MemoryEvidenceError, probes.ProbeError) as error:
        code, outcome = error.code, error.outcome
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        code, outcome = "invalid-memory-request", "rejected"
    summary, check, recovery = GUIDANCE.get(
        code,
        probes.GUIDANCE.get(
            code,
            (
                "The selected LXC memory evidence does not qualify",
                "Check the exact node, owner/generation, running state, configuration, enforced memory and supported versions",
                "Investigate or recollect the selected state; do not retry a change or accept partial evidence",
            ),
        ),
    )
    return {
        "outcome": outcome,
        "data": {},
        "diagnostics": [
            {
                "code": code,
                "summary": summary,
                "next_checks": [check],
                "recovery": [recovery],
            }
        ],
    }


def description():
    def obj(properties, required=None):
        return {
            "type": "object",
            "properties": properties,
            "required": list(properties) if required is None else required,
            "additionalProperties": False,
        }

    identifier = {"type": "string", "pattern": memory_state.NAME.pattern}
    digest = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
    return {
        "id": "lxc-memory-observe",
        "aliases": ["check owned container memory", "observe enforced LXC memory"],
        "input_schema": obj(
            {
                "request_id": {"type": "string", "pattern": "^[a-f0-9]{32}$"},
                "selector": obj(
                    {
                        "origin": identifier,
                        "node": identifier,
                        "kind": {"const": "proxmox.lxc"},
                        "vmid": {
                            "type": "integer",
                            "minimum": 100,
                            "maximum": 999999999,
                        },
                    }
                ),
                "host_profile": obj(
                    {key: digest for key in sorted(memory_state.HOST_HASHES)}
                ),
                "owner_tag": {
                    "type": "string",
                    "pattern": "^cmdmesh-own-[a-f0-9]{32}$",
                },
                "generation_tag": {
                    "type": "string",
                    "pattern": "^cmdmesh-gen-[a-f0-9]{32}$",
                },
            },
            ["selector", "host_profile", "owner_tag", "generation_tag"],
        ),
        "required_configuration": "origin, controller.scratch_root, explicit strict root ssh settings and tls settings with one explicit private node CA",
        "expected_result": "Live authenticated node/configuration/cgroup evidence for one owned running LXC; no resize or application health claim",
        "known_failures": sorted(GUIDANCE),
        "recovery": "Qualify the intended host and owner/generation over established access; no insecure retry, guest command, repair or mutation",
        "limits": [
            "PVE manager 9.2.21 / pve-container 6.1.14 candidate profile only",
            "Standard direct node TLS certificate required; custom proxy certificates unsupported",
            "A current observation is historical after collection, not mutation authorization",
        ],
    }
