"""Attach exactly two retained binds while both managed guests remain denied.

This is a once-only stopped configuration operation. It never starts, mounts,
initializes, changes ownership, publishes an allowing guard, or claims recovery.
Uncertain native writes retain the claim and all installed start denials.
"""

from contextlib import ExitStack
import os
from pathlib import Path
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_backup as backup,
    persistence_blank_stage as stage,
    persistence_config_lock as config_lock,
    persistence_observe as observe,
    persistence_pair_lock as pair_lock,
    persistence_recipient as recipient,
    persistence_state as state,
    systemd_exec as execution,
)

ROOT_UID = 0
ROOT_GID = 0
UNIT_ROOT = Path("/etc/systemd/system")
RUNTIME_ROOT = Path("/var/lib/cmdmesh/reference-attachments")
PREPARED = "cmdmesh.proxmox.persistence.prepared-attachment"
PROFILE = {
    "document_type": "cmdmesh.proxmox.persistence.attachment-runtime",
    "schema_version": 1,
}
DENIAL_NAME = "99-cmdmesh-retired-prestart.conf"
DENIAL = b"[Service]\nExecStartPre=\nExecStartPre=/usr/bin/false\n"
PHASES = ("unprotect", "attach", "protect")
FLAGS = {"boot_verified": False, "rebuild_verified": False, "restore_verified": False}


def require(value, code):
    state.require(value, "persistence-attach-" + code)


def unit_names(vmid):
    state.integer(vmid, 100, 999999)
    return tuple(
        kind + "@" + str(vmid) + ".service"
        for kind in ("pve-container", "pve-container-debug")
    )


def preserved_name(source):
    return "50-cmdmesh-reference.conf" if source else "50-cmdmesh-blank-prestart.conf"


def bind_parameters(request):
    recipient.validate_request(request)
    result = {}
    paths = []
    for index, (role, destination) in enumerate(
        (("data", "/var/lib/reference-ledger"), ("config", "/etc/reference-ledger"))
    ):
        path = request["source_request"]["policy"]["datasets"][role]["mountpoint"]
        require(
            observe.absolute(path) and state.matches(r"/[A-Za-z0-9_./-]+", path),
            "bind-path",
        )
        paths.append(Path(path))
        result["mp" + str(index)] = path + ",mp=" + destination + ",backup=0"
    require(
        paths[0] != paths[1]
        and paths[0] not in paths[1].parents
        and paths[1] not in paths[0].parents,
        "bind-alias",
    )
    return result


def validate_phase_config(request, config, phase):
    require(phase in ("initial", *PHASES), "phase")
    require(
        type(config) is dict and state.matches(r"[a-f0-9]{40}", config.get("digest")),
        "config-digest",
    )
    projected = dict(config)
    if phase in ("attach", "protect"):
        for key, expected in bind_parameters(request).items():
            require(projected.pop(key, None) == expected, "bind-config")
    if phase in ("unprotect", "attach"):
        require(
            type(projected.get("protection")) is int and projected["protection"] == 0,
            "temporary-protection",
        )
        projected["protection"] = 1
    return recipient.validate_target_config(request, projected)


def validate_bound_config(request, config):
    return validate_phase_config(request, config, "protect")


def target_state(request, phase="initial"):
    # Explicit phase validation sees the real config, including binds/protection.
    return recipient.observe_target(
        request, lambda req, cfg: validate_phase_config(req, cfg, phase)
    )


def generated(request):
    # The fixed stopped profile has no features/NIC/raw mount entries. Its bind
    # mounts are consumed by the later native pre-start hook, not this file.
    return stage.generated(request)


def control_directory(path):
    require(path.resolve(strict=True) == path, "control-path")
    info = path.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == ROOT_UID
        and info.st_gid == ROOT_GID
        and not info.st_mode & 0o022,
        "control-directory",
    )


def control_file(path):
    raw, info = observe.read_regular(path, 65536)
    require(
        info.st_uid == ROOT_UID
        and info.st_gid == ROOT_GID
        and stat.S_IMODE(info.st_mode) == 0o600,
        "control-file",
    )
    return {
        "path": str(path),
        "sha256": state.sha256(raw),
        "identity": list(observe.stable(info)),
    }, raw


def unit_state(unit):
    raw = observe.native(
        [
            "/usr/bin/systemctl",
            "show",
            unit,
            "-p",
            "LoadState,ActiveState,MainPID,DropInPaths",
        ]
    )
    fields = {}
    for line in raw.decode().splitlines():
        key, separator, value = line.partition("=")
        require(separator == "=" and key not in fields, "unit-fields")
        fields[key] = value
    state.keys(fields, {"LoadState", "ActiveState", "MainPID", "DropInPaths"})
    fields["DropInPaths"] = fields["DropInPaths"].split()
    fields["commands"] = execution.commands(unit)
    return fields


def control_files(request, *, denied):
    control_directory(UNIT_ROOT)
    result = {}
    old = request["source_request"]["source"]["selector"]["vmid"]
    for vmid in (old, request["target"]["vmid"]):
        name = preserved_name(vmid == old)
        for unit in unit_names(vmid):
            directory = UNIT_ROOT / (unit + ".d")
            control_directory(directory)
            expected = {name, DENIAL_NAME} if denied else {name}
            require(
                set(path.name for path in directory.iterdir()) == expected,
                "dropin-membership",
            )
            files = {name: control_file(directory / name)[0]}
            if denied:
                info, raw = control_file(directory / DENIAL_NAME)
                require(raw == DENIAL, "denial-bytes")
                files[DENIAL_NAME] = info
            result[unit] = files
    return result


def control_state(request, *, denied):
    files = control_files(request, denied=denied)
    result = {}
    for unit, values in files.items():
        fields = unit_state(unit)
        state.keys(
            fields, {"LoadState", "ActiveState", "MainPID", "DropInPaths", "commands"}
        )
        require(
            fields["LoadState"] == "loaded"
            and fields["ActiveState"] in {"inactive", "failed"}
            and fields["MainPID"] == "0"
            and fields["DropInPaths"]
            == sorted(value["path"] for value in values.values()),
            "unit-state",
        )
        if denied:
            commands = fields["commands"]
            require(
                type(commands) is list
                and len(commands) == 1
                and commands[0].get("path") == "/usr/bin/false"
                and commands[0].get("argv") == ["/usr/bin/false"]
                and commands[0].get("ignore_errors") is False,
                "managed-start-not-denied",
            )
        result[unit] = {"files": values, "unit": fields}
    require(
        state.canonical(control_files(request, denied=denied))
        == state.canonical(files),
        "control-files-changed",
    )
    return result


def reload_units():
    observe.native(["/usr/bin/systemctl", "daemon-reload"])


def write_denials(request):
    # Every parent and original file was admitted before this exclusive create.
    for unit in control_files(request, denied=False):
        path = UNIT_ROOT / (unit + ".d") / DENIAL_NAME
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            pending = memoryview(DENIAL)
            while pending:
                written = os.write(fd, pending)
                require(written > 0, "denial-write")
                pending = pending[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        backup.sync_directory(path.parent)


def pair_key(request):
    return state.pair_key(request["source_request"]["policy"]["datasets"])


def backup_history(request, facts):
    root = pair_lock.existing_runtime()
    operations = root / "operations"
    backup.private_directory(operations)
    entries = list(operations.iterdir())
    require(len(entries) <= 4096, "history-limit")
    key, result, matching = pair_key(request), {}, False
    for entry in entries:
        require(state.matches(r"[a-f0-9]{64}", entry.name), "foreign-history")
        backup.private_directory(entry)
        intent, raw = backup.read_private(entry / "intent.json")
        state.keys(intent, {"pair_key", "prepared_sha256", "prepared"})
        frozen = backup.load_prepared(
            state.canonical(intent["prepared"]), intent["prepared_sha256"]
        )
        require(
            intent["pair_key"]
            == state.pair_key(frozen["request"]["source_request"]["policy"]["datasets"])
            and frozen["request"]["operation_id"] == entry.name,
            "history-identity",
        )
        if intent["pair_key"] != key:
            continue
        require(not os.path.lexists(entry / "failed.json"), "unfinished-backup")
        completed, completed_raw = backup.read_private(entry / "complete.json")
        backup.validate_completion(completed, intent, raw, entry.name)
        manifest = completed["manifest"]
        if (
            manifest["source"] == facts["source"]
            and manifest["application"] == facts["application"]
            and all(
                all(
                    manifest["datasets"][role][field]
                    == request["source_request"]["policy"]["datasets"][role][field]
                    for field in ("name", "guid")
                )
                for role in ("data", "config")
            )
        ):
            matching = True
        result[entry.name] = {
            "intent_sha256": state.sha256(raw),
            "completion_sha256": state.sha256(completed_raw),
        }
    require(matching, "matching-closed-backup-required")
    return result


def claim_path(request):
    return RUNTIME_ROOT / pair_key(request)


def unused(request):
    if os.path.lexists(RUNTIME_ROOT):
        backup.private_directory(RUNTIME_ROOT)
        _, raw = backup.read_private(RUNTIME_ROOT / "profile.json")
        require(raw == state.canonical(PROFILE), "runtime-profile")
    require(not os.path.lexists(claim_path(request)), "pair-consumed")


def source_check(frozen, facts):
    require(
        state.canonical(
            recipient.collect_preflight(frozen["request"], facts, exclude_target=True)
        )
        == state.canonical(frozen["preflight"]),
        "source-changed",
    )


def prepare(recipient_raw, recipient_sha256):
    frozen = recipient.load_prepared(recipient_raw, recipient_sha256)
    request = frozen["request"]
    bind_parameters(request)
    unused(request)
    with ExitStack() as stack:
        stack.enter_context(
            pair_lock.locked_pair(request["source_request"]["policy"]["datasets"])
        )
        stack.enter_context(
            config_lock.read_guest(
                request["source_request"]["source"]["selector"]["vmid"]
            )
        )
        stack.enter_context(config_lock.read_guest(request["target"]["vmid"]))
        facts = stack.enter_context(
            observe.source_state(request["source_request"], require_stopped=True)
        )
        source_check(frozen, facts)
        history = backup_history(request, facts)
        target = target_state(request)
        stage.validate_target(request, target)
        output = generated(request)
        controls = control_state(request, denied=False)
        require(
            state.canonical(target_state(request)) == state.canonical(target)
            and state.canonical(backup_history(request, facts))
            == state.canonical(history)
            and state.canonical(control_state(request, denied=False))
            == state.canonical(controls)
            and generated(request) == output,
            "closing-state-changed",
        )
    return {
        "document_type": PREPARED,
        "schema_version": 1,
        "recipient_prepared": frozen,
        "recipient_sha256": recipient_sha256,
        "target": target,
        "generated": output,
        "controls": controls,
        "backup_history": history,
    }


def load_prepared(raw, trusted):
    state.digest(trusted)
    require(
        type(raw) is bytes and 0 < len(raw) <= 2097152 and state.sha256(raw) == trusted,
        "prepared-changed",
    )
    value = observe.decode(raw)
    state.keys(
        value,
        {
            "document_type",
            "schema_version",
            "recipient_prepared",
            "recipient_sha256",
            "target",
            "generated",
            "controls",
            "backup_history",
        },
    )
    require(
        raw == state.canonical(value)
        and value["document_type"] == PREPARED
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1,
        "prepared-version",
    )
    frozen = recipient.load_prepared(
        state.canonical(value["recipient_prepared"]), value["recipient_sha256"]
    )
    stage.validate_target(frozen["request"], value["target"])
    bind_parameters(frozen["request"])
    return value


def claim(prepared, trusted):
    backup.private_directory(RUNTIME_ROOT.parent)
    try:
        RUNTIME_ROOT.mkdir(mode=0o700)
    except FileExistsError:
        backup.private_directory(RUNTIME_ROOT)
        require(
            backup.read_private(RUNTIME_ROOT / "profile.json")[0] == PROFILE,
            "runtime-profile",
        )
    else:
        backup.write_private(RUNTIME_ROOT / "profile.json", PROFILE)
        backup.sync_directory(RUNTIME_ROOT.parent)
    path = claim_path(prepared["recipient_prepared"]["request"])
    path.mkdir(mode=0o700)
    backup.sync_directory(RUNTIME_ROOT)
    backup.write_private(
        path / "intent.json", {"prepared": prepared, "prepared_sha256": trusted}
    )
    backup.write_private(path / "write-possible.json", {"pair_key": path.name})
    return path


def native_step(request, phase, digest):
    require(
        phase in PHASES and state.matches(r"[a-f0-9]{40}", digest), "native-selector"
    )
    node = request["source_request"]["source"]["selector"]["node"]
    recipient.validate_request(request)
    argv = [
        "/usr/bin/pvesh",
        "set",
        f"/nodes/{node}/lxc/{request['target']['vmid']}/config",
        "--digest",
        digest,
    ]
    if phase == "attach":
        argv.extend(["--cores", "1", "--cpulimit", "1"])
        for key, value in bind_parameters(request).items():
            argv.extend(["--" + key, value])
    else:
        argv.extend(["--protection", "0" if phase == "unprotect" else "1"])
    output = observe.native(argv)
    return {"exit_code": 0, "stdout_sha256": state.sha256(output)}


def verify_target(prepared, phase):
    request = prepared["recipient_prepared"]["request"]
    value = target_state(request, phase)
    return validate_target_state(prepared, phase, value)


def validate_target_state(prepared, phase, value):
    request = prepared["recipient_prepared"]["request"]
    state.keys(value, {"vmid", "config", "rootfs", "status", "pending"})
    # Compare base configuration explicitly, retaining digest and temporary state
    # as observed evidence rather than presenting the guest as blank.
    validate_phase_config(request, value["config"], phase)
    before = prepared["target"]
    require(
        value["rootfs"] == before["rootfs"]
        and type(value["vmid"]) is int
        and value["vmid"] == before["vmid"],
        "target-root-changed",
    )
    expected = dict(before["config"])
    expected["digest"] = value["config"]["digest"]
    if phase in ("unprotect", "attach"):
        expected["protection"] = 0
    if phase in ("attach", "protect"):
        expected.update(bind_parameters(request))
    require(value["config"] == expected, "target-config-changed")
    require(
        type(value["status"]) is dict
        and value["status"].get("status") == "stopped"
        and type(value["status"].get("pid", 0)) is int
        and value["status"].get("pid", 0) == 0
        and type(value["status"].get("uptime")) is int
        and value["status"].get("uptime", 0) == 0,
        "target-running",
    )
    recipient.ordered_pending(value["pending"])
    return value


def phase_journal(prepared, trusted, directory):
    """Validate the finite dispatch/result chain; never reconstruct missing work."""
    expected = {"intent.json", "write-possible.json", "complete.json", "failed.json"}
    expected.update(
        phase + suffix
        for phase in PHASES
        for suffix in ("-dispatch.json", "-result.json", "-observed.json")
    )
    require(
        set(path.name for path in directory.iterdir()) <= expected, "foreign-journal"
    )
    require(not os.path.lexists(directory / "failed.json"), "failed-or-uncertain")
    intent, intent_raw = backup.read_private(directory / "intent.json")
    require(
        state.canonical(intent)
        == state.canonical({"prepared": prepared, "prepared_sha256": trusted}),
        "retained-intent",
    )
    possible, possible_raw = backup.read_private(directory / "write-possible.json")
    require(
        possible == {"pair_key": pair_key(prepared["recipient_prepared"]["request"])},
        "retained-write-intent",
    )
    seals = {
        "intent.json": state.sha256(intent_raw),
        "write-possible.json": state.sha256(possible_raw),
    }
    current = prepared["target"]
    for phase in PHASES:
        dispatch, raw = backup.read_private(directory / (phase + "-dispatch.json"))
        require(
            dispatch == {"phase": phase, "config_digest": current["config"]["digest"]},
            "dispatch-chain",
        )
        seals[phase + "-dispatch.json"] = state.sha256(raw)
        command, raw = backup.read_private(directory / (phase + "-result.json"))
        state.keys(command, {"exit_code", "stdout_sha256"})
        require(
            type(command["exit_code"]) is int and command["exit_code"] == 0,
            "native-result",
        )
        state.digest(command["stdout_sha256"])
        seals[phase + "-result.json"] = state.sha256(raw)
        observed, raw = backup.read_private(directory / (phase + "-observed.json"))
        state.keys(observed, {"target", "generated"})
        validate_target_state(prepared, phase, observed["target"])
        require(
            observed["target"]["config"]["digest"] != current["config"]["digest"],
            "unchanged-phase-digest",
        )
        current = observed["target"]
        seals[phase + "-observed.json"] = state.sha256(raw)
    return state.sha256(state.canonical(seals)), current, observed["generated"]


def preserved_controls(prepared, controls):
    require(set(controls) == set(prepared["controls"]), "control-set")
    for unit, original in prepared["controls"].items():
        for name, info in original["files"].items():
            require(
                controls[unit]["files"].get(name) == info, "preserved-guard-changed"
            )


def apply(raw, trusted):
    prepared = load_prepared(raw, trusted)
    frozen = prepared["recipient_prepared"]
    request = frozen["request"]
    require(os.geteuid() == ROOT_UID, "root-required")
    require(
        state.canonical(prepare(state.canonical(frozen), prepared["recipient_sha256"]))
        == raw,
        "preflight-changed",
    )
    directory = None
    try:
        with ExitStack() as stack:
            stack.enter_context(
                pair_lock.locked_pair(request["source_request"]["policy"]["datasets"])
            )
            stack.enter_context(
                config_lock.read_guest(
                    request["source_request"]["source"]["selector"]["vmid"]
                )
            )
            source_scope = stack.enter_context(ExitStack())
            facts = source_scope.enter_context(
                observe.source_state(request["source_request"], require_stopped=True)
            )
            unused(request)
            source_check(frozen, facts)
            require(
                backup_history(request, facts) == prepared["backup_history"],
                "backup-history-changed",
            )
            with config_lock.read_guest(request["target"]["vmid"]):
                require(
                    target_state(request) == prepared["target"]
                    and control_state(request, denied=False) == prepared["controls"]
                    and generated(request) == prepared["generated"],
                    "admission-changed",
                )
                directory = claim(prepared, trusted)
                write_denials(request)
                reload_units()
                controls = control_state(request, denied=True)
                preserved_controls(prepared, controls)
                current = verify_target(prepared, "initial")
            for phase in PHASES:
                require(
                    control_state(request, denied=True) == controls, "denials-changed"
                )
                config_lock.require_write_available(request["target"]["vmid"])
                backup.write_private(
                    directory / (phase + "-dispatch.json"),
                    {"phase": phase, "config_digest": current["config"]["digest"]},
                )
                command = native_step(request, phase, current["config"]["digest"])
                state.keys(command, {"exit_code", "stdout_sha256"})
                require(
                    type(command["exit_code"]) is int and command["exit_code"] == 0,
                    "native-result",
                )
                state.digest(command["stdout_sha256"])
                backup.write_private(directory / (phase + "-result.json"), command)
                with config_lock.read_guest(request["target"]["vmid"]):
                    current = verify_target(prepared, phase)
                    output = generated(request)
                    require(
                        control_state(request, denied=True) == controls,
                        "denials-changed",
                    )
                    backup.write_private(
                        directory / (phase + "-observed.json"),
                        {"target": current, "generated": output},
                    )
            source_check(frozen, facts)
            require(
                backup_history(request, facts) == prepared["backup_history"],
                "backup-history-changed",
            )
            # Complete the source's SQL/storage closure while pair/source leases
            # remain held, then close the replacement again after that slow work.
            source_scope.close()
            with config_lock.read_guest(request["target"]["vmid"]):
                require(
                    verify_target(prepared, "protect") == current
                    and control_state(request, denied=True) == controls
                    and generated(request) == output,
                    "final-state-changed",
                )
                journal_sha256, recorded, recorded_generated = phase_journal(
                    prepared, trusted, directory
                )
                require(
                    recorded == current and recorded_generated == output,
                    "journal-target-changed",
                )
                result = {
                    "prepared_sha256": trusted,
                    "phase": "retained-attached-starts-denied",
                    "target": current,
                    "generated": output,
                    "controls": controls,
                    "attachment_verified": True,
                    "phase_journal_sha256": journal_sha256,
                    **FLAGS,
                }
                checksum = backup.write_private(directory / "complete.json", result)
                require(
                    verify_target(prepared, "protect") == current
                    and control_state(request, denied=True) == controls
                    and generated(request) == output
                    and phase_journal(prepared, trusted, directory)
                    == (journal_sha256, current, output),
                    "completion-state-changed",
                )
        return {**result, "completion_sha256": checksum}
    except BaseException as error:
        if directory is not None:
            try:
                backup.write_private(
                    directory / "failed.json",
                    {
                        "error_code": getattr(
                            error, "code", "persistence-attach-interrupted"
                        )
                    },
                )
            except OSError:
                pass
        raise


def status(raw, trusted):
    prepared = load_prepared(raw, trusted)
    request = prepared["recipient_prepared"]["request"]
    directory = claim_path(request)
    backup.private_directory(directory)
    intent, _ = backup.read_private(directory / "intent.json")
    require(
        state.canonical(intent)
        == state.canonical({"prepared": prepared, "prepared_sha256": trusted}),
        "retained-intent",
    )
    require(not os.path.lexists(directory / "failed.json"), "failed-or-uncertain")
    complete, complete_raw = backup.read_private(directory / "complete.json")
    with ExitStack() as stack:
        stack.enter_context(
            pair_lock.locked_pair(request["source_request"]["policy"]["datasets"])
        )
        stack.enter_context(
            config_lock.read_guest(
                request["source_request"]["source"]["selector"]["vmid"]
            )
        )
        stack.enter_context(config_lock.read_guest(request["target"]["vmid"]))
        source_scope = stack.enter_context(ExitStack())
        facts = source_scope.enter_context(
            observe.source_state(request["source_request"], require_stopped=True)
        )
        source_check(prepared["recipient_prepared"], facts)
        require(
            backup_history(request, facts) == prepared["backup_history"],
            "backup-history-changed",
        )
        current = verify_target(prepared, "protect")
        output = generated(request)
        controls = control_state(request, denied=True)
        preserved_controls(prepared, controls)
        source_scope.close()
        require(
            verify_target(prepared, "protect") == current
            and control_state(request, denied=True) == controls
            and generated(request) == output,
            "closing-state-changed",
        )
        journal_sha256, recorded, recorded_generated = phase_journal(
            prepared, trusted, directory
        )
        require(
            recorded == current and recorded_generated == output,
            "journal-target-changed",
        )
        expected = {
            "prepared_sha256": trusted,
            "phase": "retained-attached-starts-denied",
            "target": current,
            "generated": output,
            "controls": controls,
            "attachment_verified": True,
            "phase_journal_sha256": journal_sha256,
            **FLAGS,
        }
        require(
            state.canonical(complete) == state.canonical(expected), "completion-changed"
        )
    return {**expected, "completion_sha256": state.sha256(complete_raw)}
