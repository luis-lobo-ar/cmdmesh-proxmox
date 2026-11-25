"""Reconcile one known pre-retirement owner-guard refusal under a new claim.

Preparation is read-only. Apply preserves the failed journal and every start
denial, then publishes the corrected stopped reference without replaying its parent.
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

ROOT_UID = 0
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


def runtime_profile():
    backup.private_directory(RUNTIME_ROOT)
    info, raw = original.file_info(RUNTIME_ROOT / "profile.json")
    require(raw == state.canonical(PROFILE), "runtime-profile")
    return info


def unused(parent):
    if os.path.lexists(RUNTIME_ROOT):
        runtime_profile()
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
    return execute_guard(argv)


def execute_guard(argv):
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
    except OSError as error:
        return {
            "exit_code": None,
            "payload": {
                "outcome": "refused",
                "reason": "execution-unavailable",
                "errno": error.errno,
            },
            "stdout_sha256": state.sha256(b""),
            "stderr_bytes": 0,
            "stderr_sha256": state.sha256(b""),
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


def decode_prepared(raw, trusted):
    state.digest(trusted)
    require(
        type(raw) is bytes and 0 < len(raw) <= 4194304 and state.sha256(raw) == trusted,
        "prepared-changed",
    )
    value = observe.decode(raw)
    state.keys(
        value,
        {
            "document_type",
            "schema_version",
            "parent_prepared",
            "parent_prepared_sha256",
            "parent_failure_sha256",
            "guard_sha256",
            "source_request",
            "source_before",
            "parent_stage",
            "candidate_probe",
        },
    )
    require(
        raw == state.canonical(value)
        and value["document_type"] == PREPARED
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["guard_sha256"] == GUARD_SHA,
        "prepared-version",
    )
    return value


def load_prepared(raw, trusted, guard):
    value = decode_prepared(raw, trusted)
    parent, old_guard = load_parent(
        state.canonical(value["parent_prepared"]), value["parent_prepared_sha256"]
    )
    stage = parent_history(
        parent, value["parent_prepared_sha256"], value["parent_failure_sha256"]
    )
    require(
        state.canonical(stage) == state.canonical(value["parent_stage"])
        and state.canonical(source_from(parent, guard))
        == state.canonical(value["source_request"]),
        "prepared-parent-changed",
    )
    require(
        state.sha256(state.canonical(value["source_before"]))
        == parent["original_source_sha256"]
        and value["source_before"]["application"] == parent["original_application"],
        "prepared-source-changed",
    )
    require_qualified(value["candidate_probe"])
    return value, old_guard


def guard_argv(prepared):
    directory = claim_path(prepared["parent_prepared"])
    return [
        "/usr/bin/python3",
        "-I",
        "-S",
        "-B",
        str(directory / "guard.py"),
        "--manifest",
        str(directory / "policy.json"),
        "--vmid",
        str(prepared["source_request"]["policy"]["vmid"]),
    ]


def dropin_body(prepared):
    argv = guard_argv(prepared)
    return ("[Service]\nExecStartPre=" + " ".join([*argv[:-1], "%i"]) + "\n").encode()


def run_guard(prepared):
    return execute_guard(guard_argv(prepared))


def create_claim(prepared, trusted):
    backup.private_directory(RUNTIME_ROOT.parent)
    try:
        RUNTIME_ROOT.mkdir(mode=0o700)
    except FileExistsError:
        backup.private_directory(RUNTIME_ROOT)
        require(
            backup.read_private(RUNTIME_ROOT / "profile.json")[1]
            == state.canonical(PROFILE),
            "runtime-profile",
        )
    else:
        backup.write_private(RUNTIME_ROOT / "profile.json", PROFILE)
        backup.sync_directory(RUNTIME_ROOT.parent)
    directory = claim_path(prepared["parent_prepared"])
    directory.mkdir(mode=0o700)
    backup.sync_directory(RUNTIME_ROOT)
    backup.write_private(
        directory / "intent.json", {"prepared": prepared, "prepared_sha256": trusted}
    )
    backup.write_private(
        directory / "write-possible.json", {"pair_key": directory.name}
    )
    return directory


def stage(prepared, guard_raw, directory):
    parent = prepared["parent_prepared"]
    request = request_of(parent)
    backup.write_private(
        directory / "stage-dispatch.json",
        {
            "guard_sha256": GUARD_SHA,
            "parent_failure_sha256": prepared["parent_failure_sha256"],
        },
    )
    original.write_raw(directory / "guard.py", guard_raw)
    backup.write_private(directory / "policy.json", parent["policy"])
    for index, unit in enumerate(original.attach.unit_names(request["target"]["vmid"])):
        target = original.attach.UNIT_ROOT / (unit + ".d") / "50-cmdmesh-reference.conf"
        expected = prepared["parent_stage"]["controls"][unit]["files"][target.name]
        require(original.file_info(target)[0] == expected, "target-reference-changed")
        pending = directory / ("replacement-target-" + str(index) + ".conf")
        archive = directory / ("previous-target-" + str(index) + ".conf")
        original.write_raw(pending, dropin_body(prepared))
        backup.write_private(
            directory / ("target-" + str(index) + "-dispatch.json"),
            {"previous": expected, "next_sha256": state.sha256(dropin_body(prepared))},
        )
        require(original.file_info(target)[0] == expected, "target-reference-changed")
        os.rename(target, archive)
        backup.sync_directory(target.parent)
        backup.sync_directory(directory)
        archived = original.file_info(archive)[0]
        require(
            archived["sha256"] == expected["sha256"]
            and archived["identity"][:8] == expected["identity"][:8],
            "target-archive-changed",
        )
        require(not os.path.lexists(target), "target-reference-raced")
        os.rename(pending, target)
        backup.sync_directory(target.parent)
        backup.sync_directory(directory)
        backup.write_private(
            directory / ("target-" + str(index) + "-result.json"),
            {"archive": archived, "current": original.file_info(target)[0]},
        )
    original.reload_units()


def parent_artifacts(prepared):
    parent = prepared["parent_prepared"]
    require(
        parent_history(
            parent,
            prepared["parent_prepared_sha256"],
            prepared["parent_failure_sha256"],
        )
        == prepared["parent_stage"],
        "parent-history-changed",
    )
    original.retained_history(parent)
    for path, expected in prepared["parent_stage"]["files"].items():
        require(
            original.file_info(Path(path))[0] == expected, "parent-artifact-changed"
        )


def current_files(prepared, guard, *, retired=True):
    profile = runtime_profile()
    parent = prepared["parent_prepared"]
    request = request_of(parent)
    directory = claim_path(parent)
    owner = str(guard.owner_path(parent["policy"]))
    expected = {
        str(directory / "guard.py"): GUARD_SHA,
        str(directory / "policy.json"): state.sha256(state.canonical(parent["policy"])),
        owner: prepared["parent_stage"]["files"][owner]["sha256"],
    }
    files = {profile["path"]: profile}
    for path, checksum in expected.items():
        info = original.file_info(Path(path))[0]
        require(info["sha256"] == checksum, "current-file-changed")
        files[path] = info
    require(files[owner] == prepared["parent_stage"]["files"][owner], "owner-changed")
    controls = original.controls(request, published=True)
    source = request["source_request"]["policy"]["vmid"]
    for vmid in (source, request["target"]["vmid"]):
        for unit in original.attach.unit_names(vmid):
            actual = controls[unit]["files"]
            before = prepared["parent_stage"]["controls"][unit]["files"]
            require(
                actual[original.attach.DENIAL_NAME]
                == before[original.attach.DENIAL_NAME],
                "denial-changed",
            )
            if vmid == source:
                require(
                    actual["50-cmdmesh-reference.conf"]
                    == before["50-cmdmesh-reference.conf"],
                    "source-dropin-changed",
                )
            else:
                require(
                    actual["50-cmdmesh-reference.conf"]["sha256"]
                    == state.sha256(dropin_body(prepared)),
                    "target-dropin-changed",
                )
    for index, unit in enumerate(original.attach.unit_names(request["target"]["vmid"])):
        path = directory / ("previous-target-" + str(index) + ".conf")
        archived = original.file_info(path)[0]
        old = prepared["parent_stage"]["controls"][unit]["files"][
            "50-cmdmesh-reference.conf"
        ]
        require(
            archived["sha256"] == old["sha256"]
            and archived["identity"][:8] == old["identity"][:8],
            "target-archive-changed",
        )
        files[str(path)] = archived
    legacy = Path(parent["legacy_reference"]["path"])
    if retired:
        stub, raw = original.file_info(legacy)
        archive = original.file_info(directory / "legacy-guard.py", private=False)[0]
        require(
            raw == original.RETIRED_STUB
            and archive["sha256"] == parent["legacy_reference"]["sha256"]
            and archive["identity"][:8] == parent["legacy_reference"]["identity"][:8],
            "legacy-retirement-changed",
        )
        files.update({str(legacy): stub, str(directory / "legacy-guard.py"): archive})
    else:
        require(
            original.file_info(legacy, private=False)[0] == parent["legacy_reference"],
            "legacy-changed",
        )
    require(
        original.current_target(parent["attachment_prepared"])
        == parent["attachment"]["target"]
        and original.current_generated(request) == parent["attachment"]["generated"],
        "target-changed",
    )
    current = {"files": files, "controls": controls}
    parent_artifacts(prepared)
    original.seal_publication(directory, current)
    if not retired:
        require(
            original.file_info(legacy, private=False)[0] == parent["legacy_reference"],
            "legacy-changed",
        )
    return current


def phase_journal(prepared, trusted, guard, current, directory):
    profile = runtime_profile()
    require(profile == current["files"][profile["path"]], "runtime-profile-changed")
    parent = prepared["parent_prepared"]
    require(not os.path.lexists(directory / "failed.json"), "failed-or-uncertain")
    expected = {
        "intent.json": {"prepared": prepared, "prepared_sha256": trusted},
        "write-possible.json": {"pair_key": directory.name},
        "stage-dispatch.json": {
            "guard_sha256": GUARD_SHA,
            "parent_failure_sha256": prepared["parent_failure_sha256"],
        },
        "guard-dispatch.json": {"argv": guard_argv(prepared)},
        "retire-dispatch.json": parent["legacy_reference"],
    }
    request = request_of(parent)
    for index, unit in enumerate(original.attach.unit_names(request["target"]["vmid"])):
        before = prepared["parent_stage"]["controls"][unit]["files"][
            "50-cmdmesh-reference.conf"
        ]
        expected["target-" + str(index) + "-dispatch.json"] = {
            "previous": before,
            "next_sha256": state.sha256(dropin_body(prepared)),
        }
        expected["target-" + str(index) + "-result.json"] = {
            "archive": current["files"][
                str(directory / ("previous-target-" + str(index) + ".conf"))
            ],
            "current": current["controls"][unit]["files"]["50-cmdmesh-reference.conf"],
        }
    expected["retire-result.json"] = {
        "stub": current["files"][parent["legacy_reference"]["path"]],
        "archive": current["files"][str(directory / "legacy-guard.py")],
    }
    hashes = {}
    for name, value in expected.items():
        actual, raw = backup.read_private(directory / name)
        require(
            raw == state.canonical(actual) == state.canonical(value), "journal-changed"
        )
        hashes[name] = state.sha256(raw)
    command, raw = backup.read_private(directory / "guard-result.json")
    require_qualified(command)
    require(raw == state.canonical(command), "journal-changed")
    hashes["guard-result.json"] = state.sha256(raw)
    for name in (
        "guard.py",
        "policy.json",
        "previous-target-0.conf",
        "previous-target-1.conf",
        "legacy-guard.py",
    ):
        info = original.file_info(directory / name, private=name != "legacy-guard.py")[
            0
        ]
        require(info == current["files"][str(directory / name)], "journal-file-changed")
        hashes[name] = info["sha256"]
    parent_artifacts(prepared)
    require(runtime_profile() == profile, "runtime-profile-changed")
    original.seal_publication(directory, current)
    return state.sha256(state.canonical(hashes))


def result_document(prepared, trusted, source, current, journal_sha):
    return {
        "prepared_sha256": trusted,
        "parent_failure_sha256": prepared["parent_failure_sha256"],
        "phase": "owner-reconciled-starts-denied",
        "source_request": prepared["source_request"],
        "source_observed": source,
        "publication": current,
        "phase_journal_sha256": journal_sha,
        "owner_reconciliation_verified": True,
        "owner_publication_verified": True,
        "legacy_source_refused": True,
        **original.FLAGS,
    }


def apply(raw, trusted, guard_raw):
    decode_prepared(raw, trusted)
    guard = load_guard_source(guard_raw)
    prepared, old_guard = load_prepared(raw, trusted, guard)
    parent = prepared["parent_prepared"]
    request = request_of(parent)
    require(os.geteuid() == ROOT_UID, "root-required")
    unused(parent)
    require(
        state.canonical(
            prepare(
                state.canonical(parent),
                prepared["parent_prepared_sha256"],
                prepared["parent_failure_sha256"],
                guard_raw,
            )
        )
        == raw,
        "preflight-changed",
    )
    directory = None
    try:
        with original.leases(request):
            unused(parent)
            with observe.source_state(
                request["source_request"], require_stopped=True
            ) as before:
                require(
                    state.canonical(before)
                    == state.canonical(prepared["source_before"]),
                    "source-changed",
                )
                require(
                    current_parent(
                        parent,
                        prepared["parent_prepared_sha256"],
                        prepared["parent_failure_sha256"],
                        old_guard,
                    )
                    == prepared["parent_stage"],
                    "parent-stage-changed",
                )
                directory = create_claim(prepared, trusted)
                stage(prepared, guard_raw, directory)
                current_files(prepared, guard, retired=False)
                installed = observe.load_guard(
                    prepared["source_request"]["reference_guard"]
                )
                observe.validate_request(prepared["source_request"], installed)
                backup.write_private(
                    directory / "guard-dispatch.json", {"argv": guard_argv(prepared)}
                )
                command = run_guard(prepared)
                backup.write_private(directory / "guard-result.json", command)
                require_qualified(command)
            original.retire(parent, directory)
            original.old_source_refused(request)
            with observe.source_state(
                prepared["source_request"], require_stopped=True
            ) as successor:
                require(
                    successor["application"] == parent["original_application"],
                    "application-changed",
                )
                source = copy.deepcopy(successor)
            current = current_files(prepared, guard)
            journal_sha = phase_journal(prepared, trusted, guard, current, directory)
            result = result_document(prepared, trusted, source, current, journal_sha)
            checksum = backup.write_private(directory / "complete.json", result)
            require(
                current_files(prepared, guard) == current
                and phase_journal(prepared, trusted, guard, current, directory)
                == journal_sha,
                "completion-changed",
            )
        return {**result, "completion_sha256": checksum}
    except BaseException as error:
        if directory is not None:
            try:
                backup.write_private(
                    directory / "failed.json",
                    {
                        "error_code": getattr(
                            error, "code", "persistence-owner-reconcile-interrupted"
                        )
                    },
                )
            except OSError:
                pass
        raise


def status(raw, trusted):
    preliminary = decode_prepared(raw, trusted)
    runtime_profile()
    directory = claim_path(preliminary["parent_prepared"])
    backup.private_directory(directory)
    intent, _ = backup.read_private(directory / "intent.json")
    require(
        intent == {"prepared": preliminary, "prepared_sha256": trusted},
        "retained-intent",
    )
    guard = load_guard_source(original.file_info(directory / "guard.py")[1])
    prepared, _ = load_prepared(raw, trusted, guard)
    parent = prepared["parent_prepared"]
    require(not os.path.lexists(directory / "failed.json"), "failed-or-uncertain")
    _, complete_raw = backup.read_private(directory / "complete.json")
    request = request_of(parent)
    with original.leases(request):
        original.old_source_refused(request)
        with observe.source_state(
            prepared["source_request"], require_stopped=True
        ) as successor:
            require(
                successor["application"] == parent["original_application"],
                "application-changed",
            )
            source = copy.deepcopy(successor)
        current = current_files(prepared, guard)
        journal_sha = phase_journal(prepared, trusted, guard, current, directory)
        result = result_document(prepared, trusted, source, current, journal_sha)
        require(state.canonical(result) == complete_raw, "completion-changed")
    return {**result, "completion_sha256": state.sha256(complete_raw)}
