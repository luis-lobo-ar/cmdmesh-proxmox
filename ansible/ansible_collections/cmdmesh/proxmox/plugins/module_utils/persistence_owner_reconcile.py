"""Admission/builders for one known pre-retirement owner-guard refusal.

These functions do not resume the original controller or write any metadata.
Live parent, source and history validation remain required before publication.
"""

import copy
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_observe as observe,
    persistence_owner_publish as original,
    persistence_backup as backup,
    persistence_state as state,
)

RUNTIME_ROOT = Path("/var/lib/cmdmesh/reference-owner-reconciliation")
GUARD_SHA = observe.FIXED_HANDOFF_GUARD_SHA256
PREPARED = "cmdmesh.proxmox.persistence.prepared-owner-reconciliation"
PROFILE = {
    "document_type": "cmdmesh.proxmox.persistence.owner-reconciliation-runtime",
    "schema_version": 1,
}
PARENT_RECORDS = (
    "intent.json",
    "write-possible.json",
    "stage-dispatch.json",
    "stage-result.json",
    "guard-dispatch.json",
    "failed.json",
)
PARENT_ABSENT = (
    "guard-result.json",
    "retire-dispatch.json",
    "retire-result.json",
    "legacy-guard.py",
    "complete.json",
)


def require(value, code):
    state.require(value, "persistence-owner-reconcile-" + code)


def load_guard_source(raw):
    require(
        type(raw) is bytes and 0 < len(raw) <= 65536 and state.sha256(raw) == GUARD_SHA,
        "guard-source",
    )
    namespace = {"__name__": "cmdmesh_pinned_corrected_owner_guard"}
    exec(compile(raw, "<cmdmesh-corrected-owner-guard>", "exec"), namespace)
    return SimpleNamespace(**namespace)


def request_of(parent):
    return parent["attachment_prepared"]["recipient_prepared"]["request"]


def claim_path(parent):
    return RUNTIME_ROOT / state.pair_key(
        request_of(parent)["source_request"]["policy"]["datasets"]
    )


def source_from(parent, guard):
    source = copy.deepcopy(parent["source_request"])
    request = request_of(parent)
    require(
        source["policy"] == parent["policy"]
        and source["reference_guard"]
        == {
            "path": str(original.claim_path(request) / "guard.py"),
            "sha256": original.GUARD_SHA,
        },
        "parent-source",
    )
    source["reference_guard"] = {
        "path": str(claim_path(parent) / "guard.py"),
        "sha256": GUARD_SHA,
    }
    observe.validate_request(source, guard)
    paths = (RUNTIME_ROOT, claim_path(parent), Path(source["reference_guard"]["path"]))
    require(all(observe.absolute(str(path)) for path in paths), "control-path")
    for dataset in source["policy"]["datasets"].values():
        mount = Path(dataset["mountpoint"])
        require(
            all(path != mount and mount not in path.parents for path in paths),
            "control-inside-retained-state",
        )
    return source


def validate_failure_records(parent, trusted, records):
    """Validate immutable raw parent history, independently of current state."""
    state.digest(trusted)
    require(state.sha256(state.canonical(parent)) == trusted, "parent-changed")
    state.keys(records, set(PARENT_RECORDS))
    request = request_of(parent)
    expected = {
        "intent.json": {"prepared": parent, "prepared_sha256": trusted},
        "write-possible.json": {"pair_key": original.claim_path(request).name},
        "stage-dispatch.json": {"guard_sha256": original.GUARD_SHA},
        "guard-dispatch.json": {"argv": original.guard_argv(parent)},
        "failed.json": {"error_code": "persistence-owner-publish-guard-refused"},
    }
    decoded, checksums = {}, {}
    for name in PARENT_RECORDS:
        raw = records[name]
        require(type(raw) is bytes and 0 < len(raw) <= 4194304, "parent-record-size")
        value = observe.decode(raw)
        require(raw == state.canonical(value), "parent-record-canonical")
        if name in expected:
            require(value == expected[name], "parent-record-changed")
        decoded[name] = value
        checksums[name] = state.sha256(raw)
    stage = decoded["stage-result.json"]
    state.keys(stage, {"files", "controls"})
    require(
        type(stage["files"]) is dict and type(stage["controls"]) is dict, "parent-stage"
    )
    return state.sha256(state.canonical(checksums)), stage


def unused(parent):
    if os.path.lexists(RUNTIME_ROOT):
        backup.private_directory(RUNTIME_ROOT)
        require(
            backup.read_private(RUNTIME_ROOT / "profile.json")[1]
            == state.canonical(PROFILE),
            "runtime-profile",
        )
    require(not os.path.lexists(claim_path(parent)), "pair-consumed")


def load_parent(raw, trusted):
    preliminary = original.decode_prepared(raw, trusted)
    directory = original.claim_path(request_of(preliminary))
    backup.private_directory(directory)
    old_guard_raw = original.file_info(directory / "guard.py")[1]
    old_guard = original.load_guard_source(old_guard_raw)
    return original.load_prepared(raw, trusted, old_guard), old_guard


def parent_history(parent, trusted, expected):
    state.digest(expected)
    backup.private_directory(original.RUNTIME_ROOT)
    require(
        backup.read_private(original.RUNTIME_ROOT / "profile.json")[1]
        == state.canonical(original.PROFILE),
        "parent-runtime-profile",
    )
    directory = original.claim_path(request_of(parent))
    backup.private_directory(directory)
    require(
        set(path.name for path in directory.iterdir())
        == set(PARENT_RECORDS)
        | {"guard.py", "policy.json", "target-blank-0.conf", "target-blank-1.conf"},
        "parent-membership",
    )
    require(
        all(not os.path.lexists(directory / name) for name in PARENT_ABSENT),
        "parent-phase",
    )
    records = {
        name: backup.read_private(directory / name)[1] for name in PARENT_RECORDS
    }
    checksum, stage = validate_failure_records(parent, trusted, records)
    require(checksum == expected, "parent-history-changed")
    return stage


def current_parent(parent, trusted, history_sha, old_guard):
    stage = parent_history(parent, trusted, history_sha)
    original.retained_history(parent)
    current = original.published_files(parent, old_guard, legacy_retired=False)
    require(state.canonical(current) == state.canonical(stage), "parent-stage-changed")
    require(
        state.canonical(parent_history(parent, trusted, history_sha))
        == state.canonical(stage),
        "parent-history-changed",
    )
    original.retained_history(parent)
    original.seal_publication(original.claim_path(request_of(parent)), current)
    require(
        original.file_info(Path(parent["legacy_reference"]["path"]), private=False)[0]
        == parent["legacy_reference"],
        "parent-legacy-changed",
    )
    return current


def probe_candidate(parent, guard_raw):
    load_guard_source(guard_raw)
    path = original.claim_path(request_of(parent)) / "policy.json"
    argv = [
        "/usr/bin/python3",
        "-I",
        "-S",
        "-B",
        "-c",
        guard_raw.decode(),
        "--manifest",
        str(path),
        "--vmid",
        str(parent["policy"]["vmid"]),
    ]
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=180,
            env=observe.ENV,
            umask=0o077,
        )
        code, out, err = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        return {
            "exit_code": None,
            "payload": {"outcome": "refused", "reason": "timeout"},
            "stdout_sha256": state.sha256(error.stdout or b""),
            "stderr_bytes": len(error.stderr or b""),
            "stderr_sha256": state.sha256(error.stderr or b""),
        }
    payload = {"outcome": "refused", "reason": "unqualified-output"}
    if len(out) <= 65536:
        try:
            parsed = observe.decode(out)
            if parsed == {"outcome": "qualified"} or (
                type(parsed) is dict
                and set(parsed) == {"outcome", "reason"}
                and parsed["outcome"] == "refused"
                and state.matches(r"[a-z0-9-]{1,120}", parsed["reason"])
            ):
                payload = parsed
        except state.PersistenceError:
            pass
    return {
        "exit_code": code,
        "payload": payload,
        "stdout_sha256": state.sha256(out),
        "stderr_bytes": len(err),
        "stderr_sha256": state.sha256(err),
    }


def require_qualified(result):
    state.keys(
        result,
        {"exit_code", "payload", "stdout_sha256", "stderr_bytes", "stderr_sha256"},
    )
    state.digest(result["stdout_sha256"])
    state.digest(result["stderr_sha256"])
    require(
        type(result["exit_code"]) is int
        and result["exit_code"] == 0
        and type(result["stderr_bytes"]) is int
        and result["stderr_bytes"] == 0
        and result["stderr_sha256"] == state.sha256(b"")
        and result["payload"] == {"outcome": "qualified"},
        "guard-refused",
    )


def prepare(parent_raw, parent_sha, failure_sha, guard_raw):
    guard = load_guard_source(guard_raw)
    parent, old_guard = load_parent(parent_raw, parent_sha)
    unused(parent)
    parent_history(parent, parent_sha, failure_sha)
    source = source_from(parent, guard)
    require(
        guard.owner_document(parent["policy"])
        == old_guard.owner_document(parent["policy"])
        and guard.owner_path(parent["policy"])
        == old_guard.owner_path(parent["policy"]),
        "owner-contract-changed",
    )
    request = request_of(parent)
    with original.leases(request):
        unused(parent)
        with observe.source_state(
            request["source_request"], require_stopped=True
        ) as before:
            original.attach.source_check(
                parent["attachment_prepared"]["recipient_prepared"], before
            )
            require(
                state.sha256(state.canonical(before))
                == parent["original_source_sha256"]
                and before["application"] == parent["original_application"],
                "source-changed",
            )
            current = current_parent(parent, parent_sha, failure_sha, old_guard)
            command = probe_candidate(parent, guard_raw)
            require_qualified(command)
            require(
                current_parent(parent, parent_sha, failure_sha, old_guard) == current,
                "preflight-changed",
            )
            source_before = copy.deepcopy(before)
        require(
            current_parent(parent, parent_sha, failure_sha, old_guard) == current,
            "preflight-changed",
        )
    return {
        "document_type": PREPARED,
        "schema_version": 1,
        "parent_prepared": parent,
        "parent_prepared_sha256": parent_sha,
        "parent_failure_sha256": failure_sha,
        "guard_sha256": GUARD_SHA,
        "source_request": source,
        "source_before": source_before,
        "parent_stage": current,
        "candidate_probe": command,
    }
