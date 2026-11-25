"""Once-only stopped owner publication; every managed start remains denied."""

import copy
from contextlib import contextmanager, ExitStack
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_attach as attach,
    persistence_backup as backup,
    persistence_config_lock as config_lock,
    persistence_pair_lock as pair_lock,
    persistence_observe as observe,
    persistence_recipient as recipient,
    persistence_state as state,
)

ROOT_UID = 0
SYSTEM_ROOT = Path("/")
RUNTIME_ROOT = Path("/var/lib/cmdmesh/reference-owner-publication")
GUARD_SHA = "68a40e2c9f696d5535085c94d4f55bc93d5b03644dfcbe254e0b5629403eb270"
RETIRED_STUB = b"raise SystemExit(1)\n"
PREPARED = "cmdmesh.proxmox.persistence.prepared-owner-publication"
PROFILE = {
    "document_type": "cmdmesh.proxmox.persistence.owner-publication-runtime",
    "schema_version": 1,
}
FLAGS = {"boot_verified": False, "rebuild_verified": False, "restore_verified": False}


def require(value, code):
    state.require(value, "persistence-owner-publish-" + code)


def load_guard_source(raw):
    require(
        type(raw) is bytes and 0 < len(raw) <= 65536 and state.sha256(raw) == GUARD_SHA,
        "guard-source",
    )
    namespace = {"__name__": "cmdmesh_pinned_owner_guard"}
    exec(compile(raw, "<cmdmesh-owner-guard-v3>", "exec"), namespace)
    return SimpleNamespace(**namespace)


def claim_path(request):
    return RUNTIME_ROOT / state.pair_key(
        request["source_request"]["policy"]["datasets"]
    )


def policy_from(request, attached, guard):
    recipient.validate_request(request)
    old = request["source_request"]["policy"]
    require(
        type(old.get("schema_version")) is int
        and old["schema_version"] == 2
        and request["source_request"]["reference_guard"]["sha256"]
        == observe.REFERENCE_GUARD_SHA256,
        "legacy-source-required",
    )
    require(
        type(attached["target"]["vmid"]) is int
        and attached["target"]["vmid"] == request["target"]["vmid"],
        "target-identity",
    )
    preserved = [
        attached["controls"][name]["files"]["50-cmdmesh-reference.conf"]["sha256"]
        for name in attach.unit_names(old["vmid"])
    ]
    for checksum in preserved:
        state.digest(checksum)
    require(preserved[0] == preserved[1], "retired-guard-mismatch")
    image = attached["target"]["rootfs"]
    policy = copy.deepcopy(old)
    policy.update(
        schema_version=3,
        vmid=request["target"]["vmid"],
        generation_tag=request["target"]["generation_tag"],
        rootfs={
            "volume": image["volume"],
            "path": image["path"],
            "bytes": image["identity"][6],
            "inode": image["identity"][1],
            "uuid": image["uuid"],
        },
        generated_config_stable_sha256=attached["generated"]["stable_sha256"],
        retired_guest={
            "vmid": old["vmid"],
            "generation_tag": old["generation_tag"],
            "preserved_dropin_sha256": preserved[0],
        },
    )
    guard.validate_policy(policy)
    validate_control_paths(request, policy, guard)
    return policy


def validate_control_paths(request, policy, guard):
    legacy = request["source_request"]["reference_guard"]["path"]
    require(observe.absolute(legacy), "legacy-reference-path")
    controls = [
        RUNTIME_ROOT,
        claim_path(request),
        Path(legacy),
        guard.owner_path(policy).parent,
    ]
    for vmid in (
        request["source_request"]["policy"]["vmid"],
        request["target"]["vmid"],
    ):
        controls.extend(
            attach.UNIT_ROOT / (unit + ".d") for unit in attach.unit_names(vmid)
        )
    for item in policy["datasets"].values():
        mount = Path(item["mountpoint"])
        require(
            all(path != mount and mount not in path.parents for path in controls),
            "control-inside-retained-state",
        )


def source_from(request, policy):
    source = copy.deepcopy(request["source_request"])
    source["source"]["selector"]["vmid"] = policy["vmid"]
    source["source"]["generation_tag"] = policy["generation_tag"]
    source["policy"] = copy.deepcopy(policy)
    source["reference_guard"] = {
        "path": str(claim_path(request) / "guard.py"),
        "sha256": GUARD_SHA,
    }
    return source


def unit_state(unit):
    return attach.unit_state(unit)


def reload_units():
    attach.reload_units()


def current_target(prepared):
    return attach.verify_target(prepared, "protect")


def current_generated(request):
    return attach.generated(request)


def safe_parents(path):
    parent = path.parent
    require(SYSTEM_ROOT == parent or SYSTEM_ROOT in parent.parents, "control-root")
    while True:
        require(parent.resolve(strict=True) == parent, "control-parent-path")
        info = parent.lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid in {0, ROOT_UID}
            and not info.st_mode & 0o022,
            "control-parent",
        )
        if parent == SYSTEM_ROOT:
            break
        parent = parent.parent


def file_info(path, *, private=True):
    safe_parents(path)
    raw, info = observe.read_regular(path, 65536)
    require(
        info.st_uid == ROOT_UID
        and not info.st_mode & 0o7022
        and (not private or stat.S_IMODE(info.st_mode) == 0o600),
        "control-file",
    )
    return {
        "path": str(path),
        "sha256": state.sha256(raw),
        "identity": list(observe.stable(info)),
    }, raw


def controls(request, *, published):
    result = {}
    source = request["source_request"]["policy"]["vmid"]
    for vmid in (source, request["target"]["vmid"]):
        name = (
            "50-cmdmesh-reference.conf"
            if published or vmid == source
            else "50-cmdmesh-blank-prestart.conf"
        )
        for unit in attach.unit_names(vmid):
            directory = attach.UNIT_ROOT / (unit + ".d")
            safe_parents(directory / name)
            require(
                set(path.name for path in directory.iterdir())
                == {name, attach.DENIAL_NAME},
                "unit-membership",
            )
            files = {
                part: file_info(directory / part)[0]
                for part in (name, attach.DENIAL_NAME)
            }
            require(
                (directory / attach.DENIAL_NAME).read_bytes() == attach.DENIAL,
                "denial-bytes",
            )
            fields = unit_state(unit)
            require(
                fields["LoadState"] == "loaded"
                and fields["ActiveState"] in {"inactive", "failed"}
                and fields["MainPID"] == "0"
                and fields["DropInPaths"]
                == sorted(value["path"] for value in files.values()),
                "unit-state",
            )
            commands = fields["commands"]
            require(
                type(commands) is list
                and len(commands) == 1
                and commands[0]["path"] == "/usr/bin/false"
                and commands[0]["argv"] == ["/usr/bin/false"]
                and commands[0]["ignore_errors"] is False,
                "unit-not-denied",
            )
            result[unit] = {"files": files, "unit": fields}
    return result


def attachment_history(frozen, trusted, completion_sha):
    request = frozen["recipient_prepared"]["request"]
    directory = attach.claim_path(request)
    backup.private_directory(directory)
    complete, raw = backup.read_private(directory / "complete.json")
    require(
        state.sha256(raw) == completion_sha
        and complete["prepared_sha256"] == trusted
        and complete["attachment_verified"] is True
        and all(complete[key] is False for key in FLAGS),
        "attachment-history",
    )
    checksum, target, generated = attach.phase_journal(frozen, trusted, directory)
    require(
        checksum == complete["phase_journal_sha256"]
        and target == complete["target"]
        and generated == complete["generated"],
        "attachment-chain",
    )
    return complete


def unused(request):
    if os.path.lexists(RUNTIME_ROOT):
        backup.private_directory(RUNTIME_ROOT)
        _, raw = backup.read_private(RUNTIME_ROOT / "profile.json")
        require(raw == state.canonical(PROFILE), "runtime-profile")
    require(not os.path.lexists(claim_path(request)), "pair-consumed")


@contextmanager
def leases(request):
    with ExitStack() as stack:
        stack.enter_context(
            pair_lock.locked_pair(request["source_request"]["policy"]["datasets"])
        )
        for vmid in (
            request["source_request"]["policy"]["vmid"],
            request["target"]["vmid"],
        ):
            stack.enter_context(config_lock.read_guest(vmid))
        yield


def initial_state(frozen, accepted):
    request = frozen["recipient_prepared"]["request"]
    require(
        current_target(frozen) == accepted["target"]
        and current_generated(request) == accepted["generated"]
        and controls(request, published=False) == accepted["controls"],
        "attachment-changed",
    )


def owner_absent(policy, guard):
    path = guard.owner_path(policy)
    if os.path.lexists(path.parent.parent):
        backup.private_directory(path.parent.parent)
    require(not os.path.lexists(path.parent), "owner-already-exists")


def prepare(attachment_raw, attachment_sha, completion_sha, guard_raw):
    frozen = attach.load_prepared(attachment_raw, attachment_sha)
    state.digest(completion_sha)
    guard = load_guard_source(guard_raw)
    request = frozen["recipient_prepared"]["request"]
    unused(request)
    status = attach.status(attachment_raw, attachment_sha)
    accepted = attachment_history(frozen, attachment_sha, completion_sha)
    require(
        status["completion_sha256"] == completion_sha
        and state.canonical({key: status[key] for key in accepted})
        == state.canonical(accepted),
        "attachment-unqualified",
    )
    policy = policy_from(request, accepted, guard)
    source = source_from(request, policy)
    observe.validate_request(source, guard)
    with leases(request):
        unused(request)
        owner_absent(policy, guard)
        with observe.source_state(
            request["source_request"], require_stopped=True
        ) as before:
            attach.source_check(frozen["recipient_prepared"], before)
            require(
                attach.backup_history(request, before) == frozen["backup_history"],
                "backup-history-changed",
            )
            initial_state(frozen, accepted)
            legacy, _ = file_info(
                Path(request["source_request"]["reference_guard"]["path"]),
                private=False,
            )
            require(
                legacy["sha256"] == observe.REFERENCE_GUARD_SHA256,
                "legacy-reference-changed",
            )
            application = copy.deepcopy(before["application"])
            source_sha = state.sha256(state.canonical(before))
        initial_state(frozen, accepted)
        require(
            file_info(Path(legacy["path"]), private=False)[0] == legacy,
            "legacy-reference-changed",
        )
    return {
        "document_type": PREPARED,
        "schema_version": 1,
        "attachment_prepared": frozen,
        "attachment_sha256": attachment_sha,
        "attachment_completion_sha256": completion_sha,
        "attachment": accepted,
        "guard_sha256": GUARD_SHA,
        "policy": policy,
        "source_request": source,
        "original_application": application,
        "original_source_sha256": source_sha,
        "legacy_reference": legacy,
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
            "attachment_prepared",
            "attachment_sha256",
            "attachment_completion_sha256",
            "attachment",
            "guard_sha256",
            "policy",
            "source_request",
            "original_application",
            "original_source_sha256",
            "legacy_reference",
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
    frozen = attach.load_prepared(
        state.canonical(value["attachment_prepared"]), value["attachment_sha256"]
    )
    request = frozen["recipient_prepared"]["request"]
    require(
        state.sha256(state.canonical(value["attachment"]))
        == value["attachment_completion_sha256"]
        and value["attachment"]["prepared_sha256"] == value["attachment_sha256"],
        "attachment-proof",
    )
    require(
        policy_from(request, value["attachment"], guard) == value["policy"]
        and source_from(request, value["policy"]) == value["source_request"],
        "successor-proof",
    )
    observe.validate_request(value["source_request"], guard)
    state.digest(value["original_source_sha256"])
    require(
        value["legacy_reference"]["path"]
        == request["source_request"]["reference_guard"]["path"]
        and value["legacy_reference"]["sha256"] == observe.REFERENCE_GUARD_SHA256,
        "legacy-reference-proof",
    )
    return value


def write_raw(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        pending = memoryview(raw)
        while pending:
            written = os.write(fd, pending)
            require(written > 0, "control-write")
            pending = pending[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    backup.sync_directory(path.parent)


def claim(prepared, trusted):
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
    directory = claim_path(
        prepared["attachment_prepared"]["recipient_prepared"]["request"]
    )
    directory.mkdir(mode=0o700)
    backup.sync_directory(RUNTIME_ROOT)
    backup.write_private(
        directory / "intent.json", {"prepared": prepared, "prepared_sha256": trusted}
    )
    backup.write_private(
        directory / "write-possible.json", {"pair_key": directory.name}
    )
    return directory


def guard_argv(prepared):
    request = prepared["attachment_prepared"]["recipient_prepared"]["request"]
    directory = claim_path(request)
    return [
        "/usr/bin/python3",
        "-I",
        "-S",
        "-B",
        str(directory / "guard.py"),
        "--manifest",
        str(directory / "policy.json"),
        "--vmid",
        str(request["target"]["vmid"]),
    ]


def dropin_body(prepared):
    argv = guard_argv(prepared)
    return ("[Service]\nExecStartPre=" + " ".join([*argv[:-1], "%i"]) + "\n").encode()


def stage(prepared, guard_raw, guard, directory):
    request = prepared["attachment_prepared"]["recipient_prepared"]["request"]
    backup.write_private(directory / "stage-dispatch.json", {"guard_sha256": GUARD_SHA})
    write_raw(directory / "guard.py", guard_raw)
    backup.write_private(directory / "policy.json", prepared["policy"])
    owner = guard.owner_path(prepared["policy"])
    if not os.path.lexists(owner.parent.parent):
        owner.parent.parent.mkdir(mode=0o700)
        backup.sync_directory(owner.parent.parent.parent)
    backup.private_directory(owner.parent.parent)
    owner.parent.mkdir(mode=0o700)
    backup.sync_directory(owner.parent.parent)
    backup.write_private(owner, guard.owner_document(prepared["policy"]))
    for index, unit in enumerate(attach.unit_names(request["target"]["vmid"])):
        parent = attach.UNIT_ROOT / (unit + ".d")
        old = parent / "50-cmdmesh-blank-prestart.conf"
        before, raw = file_info(old)
        require(
            before == prepared["attachment"]["controls"][unit]["files"][old.name],
            "blank-file-changed",
        )
        write_raw(directory / ("target-blank-" + str(index) + ".conf"), raw)
        write_raw(parent / "50-cmdmesh-reference.conf", dropin_body(prepared))
        require(file_info(old)[0] == before, "blank-file-changed")
        old.unlink()
        backup.sync_directory(parent)
    reload_units()
    value = published_files(prepared, guard, legacy_retired=False)
    backup.write_private(directory / "stage-result.json", value)
    return value


def guard_cli(prepared):
    result = subprocess.run(
        guard_argv(prepared),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=120,
        env=observe.ENV,
        umask=0o077,
    )
    require(
        result.returncode == 0
        and not result.stderr
        and len(result.stdout) <= 65536
        and observe.decode(result.stdout) == {"outcome": "qualified"},
        "guard-refused",
    )
    return {"exit_code": 0, "stdout_sha256": state.sha256(result.stdout)}


def validate_guard_result(value):
    state.keys(value, {"exit_code", "stdout_sha256"})
    require(
        type(value["exit_code"]) is int and value["exit_code"] == 0, "guard-refused"
    )
    state.digest(value["stdout_sha256"])


def published_files(prepared, guard, *, legacy_retired=True):
    request = prepared["attachment_prepared"]["recipient_prepared"]["request"]
    directory = claim_path(request)
    paths = [
        directory / "guard.py",
        directory / "policy.json",
        guard.owner_path(prepared["policy"]),
    ]
    expected = [
        GUARD_SHA,
        state.sha256(state.canonical(prepared["policy"])),
        state.sha256(state.canonical(guard.owner_document(prepared["policy"]))),
    ]
    for index, unit in enumerate(attach.unit_names(request["target"]["vmid"])):
        paths.append(directory / ("target-blank-" + str(index) + ".conf"))
        expected.append(
            prepared["attachment"]["controls"][unit]["files"][
                "50-cmdmesh-blank-prestart.conf"
            ]["sha256"]
        )
    files = {}
    for path, checksum in zip(paths, expected):
        info, _ = file_info(path)
        require(info["sha256"] == checksum, "published-file-changed")
        files[str(path)] = info
    result = controls(request, published=True)
    source = request["source_request"]["policy"]["vmid"]
    for vmid in (source, request["target"]["vmid"]):
        for unit in attach.unit_names(vmid):
            values = result[unit]["files"]
            require(
                values[attach.DENIAL_NAME]
                == prepared["attachment"]["controls"][unit]["files"][
                    attach.DENIAL_NAME
                ],
                "denial-changed",
            )
            if vmid == source:
                require(
                    values["50-cmdmesh-reference.conf"]
                    == prepared["attachment"]["controls"][unit]["files"][
                        "50-cmdmesh-reference.conf"
                    ],
                    "source-guard-changed",
                )
            else:
                require(
                    values["50-cmdmesh-reference.conf"]["sha256"]
                    == state.sha256(dropin_body(prepared)),
                    "successor-guard-changed",
                )
    legacy = Path(prepared["legacy_reference"]["path"])
    if legacy_retired:
        stub, raw = file_info(legacy)
        archive, _ = file_info(directory / "legacy-guard.py", private=False)
        require(
            raw == RETIRED_STUB and archive["sha256"] == observe.REFERENCE_GUARD_SHA256,
            "legacy-retirement-changed",
        )
        files.update({str(legacy): stub, str(directory / "legacy-guard.py"): archive})
    else:
        require(
            file_info(legacy, private=False)[0] == prepared["legacy_reference"],
            "legacy-reference-changed",
        )
    require(
        current_target(prepared["attachment_prepared"])
        == prepared["attachment"]["target"]
        and current_generated(request) == prepared["attachment"]["generated"],
        "target-changed",
    )
    result = {"files": files, "controls": result}
    seal_publication(directory, result)
    return result


def seal_publication(directory, current):
    # Native and journal reads may be slow. Close every filesystem proof afterwards.
    for path, expected_info in current["files"].items():
        require(
            file_info(Path(path), private=path != str(directory / "legacy-guard.py"))[0]
            == expected_info,
            "closing-file-changed",
        )
    for unit, fields in current["controls"].items():
        parent = attach.UNIT_ROOT / (unit + ".d")
        require(
            set(path.name for path in parent.iterdir()) == set(fields["files"]),
            "closing-unit-membership",
        )
        for info in fields["files"].values():
            require(
                file_info(Path(info["path"]))[0] == info, "closing-unit-file-changed"
            )


def publication_journal(prepared, trusted, directory, current):
    """Validate the retained phase records and bind their actual raw bytes."""
    backup.private_directory(directory)
    require(not os.path.lexists(directory / "failed.json"), "failed-or-uncertain")
    expected = {
        "intent.json": {"prepared": prepared, "prepared_sha256": trusted},
        "write-possible.json": {"pair_key": directory.name},
        "stage-dispatch.json": {"guard_sha256": GUARD_SHA},
        "guard-dispatch.json": {"argv": guard_argv(prepared)},
        "retire-dispatch.json": prepared["legacy_reference"],
    }
    legacy = prepared["legacy_reference"]["path"]
    archived = str(directory / "legacy-guard.py")
    expected["stage-result.json"] = {
        "files": {
            path: info
            for path, info in current["files"].items()
            if path not in {legacy, archived}
        },
        "controls": current["controls"],
    }
    expected["retire-result.json"] = {
        "stub": current["files"][legacy],
        "archive": current["files"][archived],
    }
    checksums = {}
    for name, value in expected.items():
        actual, raw = backup.read_private(directory / name)
        require(
            raw == state.canonical(actual) == state.canonical(value),
            "phase-journal-changed",
        )
        checksums[name] = state.sha256(raw)
    command, raw = backup.read_private(directory / "guard-result.json")
    validate_guard_result(command)
    require(raw == state.canonical(command), "phase-journal-changed")
    checksums["guard-result.json"] = state.sha256(raw)
    for name in (
        "guard.py",
        "policy.json",
        "target-blank-0.conf",
        "target-blank-1.conf",
        "legacy-guard.py",
    ):
        info, _ = file_info(directory / name, private=name != "legacy-guard.py")
        require(
            info == current["files"][str(directory / name)], "phase-journal-changed"
        )
        checksums[name] = info["sha256"]
    seal_publication(directory, current)
    return state.sha256(state.canonical(checksums))


def retained_history(prepared):
    frozen = prepared["attachment_prepared"]
    request = frozen["recipient_prepared"]["request"]
    facts = {
        "source": request["source_request"]["source"],
        "application": prepared["original_application"],
    }
    require(
        attach.backup_history(request, facts) == frozen["backup_history"],
        "backup-history-changed",
    )
    require(
        attachment_history(
            frozen,
            prepared["attachment_sha256"],
            prepared["attachment_completion_sha256"],
        )
        == prepared["attachment"],
        "attachment-history-changed",
    )


def retire(prepared, directory):
    legacy = Path(prepared["legacy_reference"]["path"])
    require(
        file_info(legacy, private=False)[0] == prepared["legacy_reference"],
        "legacy-reference-changed",
    )
    backup.write_private(
        directory / "retire-dispatch.json", prepared["legacy_reference"]
    )
    os.rename(legacy, directory / "legacy-guard.py")
    backup.sync_directory(legacy.parent)
    backup.sync_directory(directory)
    write_raw(legacy, RETIRED_STUB)
    backup.write_private(
        directory / "retire-result.json",
        {
            "stub": file_info(legacy)[0],
            "archive": file_info(directory / "legacy-guard.py", private=False)[0],
        },
    )


def old_source_refused(request):
    try:
        observe.load_guard(request["source_request"]["reference_guard"])
    except state.PersistenceError as error:
        require(error.code == "persistence-guard-changed", "legacy-refusal-unqualified")
    else:
        raise state.PersistenceError(
            "persistence-owner-publish-legacy-source-still-accepted"
        )


def apply(raw, trusted, guard_raw):
    guard = load_guard_source(guard_raw)
    prepared = load_prepared(raw, trusted, guard)
    request = prepared["attachment_prepared"]["recipient_prepared"]["request"]
    require(os.geteuid() == ROOT_UID, "root-required")
    unused(request)
    require(
        state.canonical(
            prepare(
                state.canonical(prepared["attachment_prepared"]),
                prepared["attachment_sha256"],
                prepared["attachment_completion_sha256"],
                guard_raw,
            )
        )
        == raw,
        "preflight-changed",
    )
    directory = None
    try:
        with leases(request):
            unused(request)
            owner_absent(prepared["policy"], guard)
            attachment_history(
                prepared["attachment_prepared"],
                prepared["attachment_sha256"],
                prepared["attachment_completion_sha256"],
            )
            with observe.source_state(
                request["source_request"], require_stopped=True
            ) as before:
                attach.source_check(
                    prepared["attachment_prepared"]["recipient_prepared"], before
                )
                require(
                    state.sha256(state.canonical(before))
                    == prepared["original_source_sha256"]
                    and before["application"] == prepared["original_application"],
                    "source-changed",
                )
                initial_state(prepared["attachment_prepared"], prepared["attachment"])
                retained_history(prepared)
                directory = claim(prepared, trusted)
                stage(prepared, guard_raw, guard, directory)
                backup.write_private(
                    directory / "guard-dispatch.json", {"argv": guard_argv(prepared)}
                )
                command = guard_cli(prepared)
                validate_guard_result(command)
                backup.write_private(directory / "guard-result.json", command)
            retire(prepared, directory)
            old_source_refused(request)
            with observe.source_state(
                prepared["source_request"], require_stopped=True
            ) as successor:
                require(
                    successor["application"] == prepared["original_application"],
                    "application-changed",
                )
                source = copy.deepcopy(successor)
            current = published_files(prepared, guard)
            retained_history(prepared)
            journal_sha = publication_journal(prepared, trusted, directory, current)
            result = {
                "prepared_sha256": trusted,
                "phase": "owner-published-starts-denied",
                "source_request": prepared["source_request"],
                "source_observed": source,
                "publication": current,
                "phase_journal_sha256": journal_sha,
                "owner_publication_verified": True,
                "legacy_source_refused": True,
                **FLAGS,
            }
            checksum = backup.write_private(directory / "complete.json", result)
            require(
                published_files(prepared, guard) == current, "completion-state-changed"
            )
            retained_history(prepared)
            require(
                publication_journal(prepared, trusted, directory, current)
                == journal_sha,
                "completion-journal-changed",
            )
        return {**result, "completion_sha256": checksum}
    except BaseException as error:
        if directory is not None:
            try:
                backup.write_private(
                    directory / "failed.json",
                    {
                        "error_code": getattr(
                            error, "code", "persistence-owner-publish-interrupted"
                        )
                    },
                )
            except OSError:
                pass
        raise


def status(raw, trusted):
    preliminary = decode_prepared(raw, trusted)
    request = preliminary["attachment_prepared"]["recipient_prepared"]["request"]
    directory = claim_path(request)
    backup.private_directory(directory)
    intent, _ = backup.read_private(directory / "intent.json")
    require(
        state.canonical(intent)
        == state.canonical({"prepared": preliminary, "prepared_sha256": trusted}),
        "retained-intent",
    )
    guard_raw = file_info(directory / "guard.py")[1]
    guard = load_guard_source(guard_raw)
    prepared = load_prepared(raw, trusted, guard)
    require(not os.path.lexists(directory / "failed.json"), "failed-or-uncertain")
    complete, complete_raw = backup.read_private(directory / "complete.json")
    with leases(request):
        old_source_refused(request)
        with observe.source_state(
            prepared["source_request"], require_stopped=True
        ) as successor:
            require(
                successor["application"] == prepared["original_application"],
                "application-changed",
            )
            source = copy.deepcopy(successor)
        current = published_files(prepared, guard)
        retained_history(prepared)
        journal_sha = publication_journal(prepared, trusted, directory, current)
        expected = {
            "prepared_sha256": trusted,
            "phase": "owner-published-starts-denied",
            "source_request": prepared["source_request"],
            "source_observed": source,
            "publication": current,
            "phase_journal_sha256": journal_sha,
            "owner_publication_verified": True,
            "legacy_source_refused": True,
            **FLAGS,
        }
        require(state.canonical(expected) == complete_raw, "completion-changed")
    return {**expected, "completion_sha256": state.sha256(complete_raw)}
