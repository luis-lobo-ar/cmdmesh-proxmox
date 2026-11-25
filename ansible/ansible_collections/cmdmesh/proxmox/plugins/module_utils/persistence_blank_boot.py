"""Publish one checked blank guard and start the same isolated OS once."""

import inspect
import os
from pathlib import Path
import stat
import time

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_backup as backup,
    persistence_blank_guard as guard,
    persistence_blank_runtime as runtime,
    persistence_blank_stage as stage,
    persistence_observe as observe,
    persistence_recipient as recipient,
    persistence_state as state,
    systemd_exec as execution,
)

ROOT_UID = 0
RUNTIME_ROOT = Path("/var/lib/cmdmesh/reference-blank-boot")
PREPARED = "cmdmesh.proxmox.persistence.prepared-blank-boot"
PROFILE = {
    "document_type": "cmdmesh.proxmox.persistence.blank-boot-runtime",
    "schema_version": 1,
}
GUARD_SHA256 = "baa0e36edb88720b8ff7a47e072864199435718aee40bc8895092d3fe57a4cfd"
FLAGS = {"boot_verified": False, "rebuild_verified": False, "restore_verified": False}


def require(value, code):
    state.require(value, "persistence-blank-boot-" + code)


def guard_source():
    raw = inspect.getsource(guard).encode()
    require(0 < len(raw) <= 65536 and state.sha256(raw) == GUARD_SHA256, "guard-source")
    return raw


def request_of(prepared):
    return prepared["stage_prepared"]["recipient_prepared"]["request"]


def claim_path(prepared):
    request = request_of(prepared)
    source = request["source_request"]["source"]
    return RUNTIME_ROOT / state.sha256(
        state.canonical(
            [source["host_profile"]["machine_id_sha256"], request["target"]["vmid"]]
        )
    )


def allowing_dropin(request, unit):
    return stage.dropin_path(request, unit).with_name("50-cmdmesh-blank-prestart.conf")


def guard_argv(prepared):
    directory = claim_path(prepared)
    return [
        "/usr/bin/python3",
        "-I",
        "-S",
        "-B",
        str(directory / "guard.py"),
        "--manifest",
        str(directory / "policy.json"),
        "--vmid",
        str(prepared["policy"]["vmid"]),
    ]


def dropin_body(prepared):
    argv = guard_argv(prepared)
    return ("[Service]\nExecStartPre=" + " ".join([*argv[:-1], "%i"]) + "\n").encode()


def cpu_available():
    path = Path("/sys/fs/cgroup/lxc/cpuset.cpus.effective")
    if not path.exists():
        path = Path("/sys/fs/cgroup/cpuset.cpus.effective")
    require(path.resolve(strict=True) == path, "cpu-parent-path")
    return guard.cpu_list(path.read_text().strip())


def policy_from(stage_prepared, complete, allowed):
    request = stage_prepared["recipient_prepared"]["request"]
    source = request["source_request"]["source"]
    target = complete["target"]
    image = target["rootfs"]
    policy = {
        "schema_version": 1,
        "machine_id_sha256": source["host_profile"]["machine_id_sha256"],
        "node": source["selector"]["node"],
        "vmid": request["target"]["vmid"],
        "source_vmid": source["selector"]["vmid"],
        "config": target["config"],
        "rootfs": {
            "path": image["path"],
            "identity": image["identity"][:7],
            "uuid": image["uuid"],
        },
        "generated_config_stable_sha256": complete["generated"]["stable_sha256"],
        "cpu_policy": {"allowed": allowed, "count": 1},
    }
    guard.validate_policy(policy)
    return policy


def denial_facts(request):
    result = {}
    for unit in stage.unit_names(request):
        path = stage.dropin_path(request, unit)
        require(
            not os.path.lexists(allowing_dropin(request, unit)),
            "existing-allowing-file",
        )
        raw, info = observe.read_regular(path, 4096)
        require(
            raw == stage.DENY
            and info.st_uid == ROOT_UID
            and stat.S_IMODE(info.st_mode) == 0o600,
            "deny-file",
        )
        result[unit] = {
            "path": str(path),
            "sha256": state.sha256(raw),
            "identity": list(observe.stable(info)),
        }
    return result


def prepare(stage_raw, stage_sha256, stage_completion_sha256):
    frozen = stage.load_prepared(stage_raw, stage_sha256)
    state.digest(stage_completion_sha256)
    complete, raw = backup.read_private(stage.claim_path(frozen) / "complete.json")
    require(
        state.sha256(raw) == stage_completion_sha256
        and raw == state.canonical(complete),
        "stage-completion",
    )
    observed = stage.status(stage_raw, stage_sha256)
    require(
        complete["prepared_sha256"] == stage_sha256
        and state.canonical({key: complete[key] for key in observed})
        == state.canonical(observed),
        "stage-changed",
    )
    request = frozen["recipient_prepared"]["request"]
    value = {
        "document_type": PREPARED,
        "schema_version": 1,
        "profile_version": 1,
        "stage_prepared": frozen,
        "stage_sha256": stage_sha256,
        "stage_complete": complete,
        "stage_completion_sha256": stage_completion_sha256,
        "policy": policy_from(frozen, complete, cpu_available()),
        "denials": denial_facts(request),
        "guard_sha256": GUARD_SHA256,
    }
    require(not os.path.lexists(claim_path(value)), "target-consumed")
    guard_source()
    load_prepared(state.canonical(value), state.sha256(state.canonical(value)))
    return value


def load_prepared(raw, trusted):
    state.digest(trusted)
    require(
        type(raw) is bytes and 0 < len(raw) <= 1048576 and state.sha256(raw) == trusted,
        "prepared-changed",
    )
    value = observe.decode(raw)
    state.keys(
        value,
        {
            "document_type",
            "schema_version",
            "profile_version",
            "stage_prepared",
            "stage_sha256",
            "stage_complete",
            "stage_completion_sha256",
            "policy",
            "denials",
            "guard_sha256",
        },
    )
    require(
        value["document_type"] == PREPARED
        and raw == state.canonical(value)
        and all(
            type(value[key]) is int and value[key] == 1
            for key in ("schema_version", "profile_version")
        )
        and value["guard_sha256"] == GUARD_SHA256,
        "prepared-version",
    )
    frozen = stage.load_prepared(
        state.canonical(value["stage_prepared"]), value["stage_sha256"]
    )
    complete = value["stage_complete"]
    state.keys(
        complete,
        {
            "prepared_sha256",
            "phase",
            "target",
            "units",
            "generated",
            "denied_generation_verified",
            "boot_verified",
            "rebuild_verified",
            "restore_verified",
        },
    )
    require(
        state.sha256(state.canonical(complete)) == value["stage_completion_sha256"]
        and complete["prepared_sha256"] == value["stage_sha256"]
        and complete["phase"] == "blank-generation-denied"
        and complete["denied_generation_verified"] is True
        and all(complete[key] is False for key in FLAGS)
        and state.canonical(complete["target"]) == state.canonical(frozen["target"]),
        "stage-proof",
    )
    request = request_of(value)
    stage.validate_target(request, complete["target"])
    state.keys(complete["units"], set(stage.unit_names(request)))
    for unit, fields in complete["units"].items():
        state.keys(
            fields,
            {"LoadState", "ActiveState", "MainPID", "DropInPaths", "ExecStartPre"},
        )
        require(
            fields["LoadState"] == "loaded"
            and fields["ActiveState"] == "inactive"
            and fields["MainPID"] == "0"
            and fields["DropInPaths"] == str(stage.dropin_path(request, unit))
            and state.matches(
                r"\{ path=/usr/bin/false ; argv\[\]=/usr/bin/false ; ignore_errors=no ; start_time=\[[^\]\r\n]*\] ; stop_time=\[[^\]\r\n]*\] ; pid=0 ; code=\(null\) ; status=0/0 \}",
                fields["ExecStartPre"],
            ),
            "stage-unit-proof",
        )
    generated = complete["generated"]
    state.keys(
        generated,
        {"path", "text", "sha256", "stable_sha256", "identity", "cpu_selection"},
    )
    require(
        generated["path"]
        == str(stage.LXC_ROOT / str(request["target"]["vmid"]) / "config")
        and type(generated["text"]) is str
        and state.sha256(generated["text"].encode()) == generated["sha256"],
        "generated-proof",
    )
    checksum, selection = guard.generated_fingerprint(generated["text"].encode())
    require(
        checksum == generated["stable_sha256"]
        and selection == generated["cpu_selection"],
        "generated-proof",
    )
    parts = generated["identity"]
    require(
        type(parts) is list
        and len(parts) == 9
        and all(type(part) is int and part >= 0 for part in parts)
        and parts[1] > 0
        and stat.S_ISREG(parts[2])
        and not parts[2] & 0o022
        and parts[3] == ROOT_UID
        and parts[5] == 1
        and parts[6] == len(generated["text"].encode()),
        "generated-identity-proof",
    )
    guard.validate_policy(value["policy"])
    require(
        state.canonical(value["policy"])
        == state.canonical(
            policy_from(frozen, complete, value["policy"]["cpu_policy"]["allowed"])
        ),
        "policy-proof",
    )
    require(
        len(selection) <= 1
        and set(selection) <= set(value["policy"]["cpu_policy"]["allowed"]),
        "generated-cpu-proof",
    )
    state.keys(value["denials"], set(stage.unit_names(request)))
    for unit, fact in value["denials"].items():
        state.keys(fact, {"path", "sha256", "identity"})
        require(
            fact["path"] == str(stage.dropin_path(request, unit))
            and fact["sha256"] == state.sha256(stage.DENY),
            "denial-proof",
        )
        parts = fact["identity"]
        require(
            type(parts) is list
            and len(parts) == 9
            and all(type(part) is int and part >= 0 for part in parts)
            and parts[1] > 0
            and stat.S_ISREG(parts[2])
            and stat.S_IMODE(parts[2]) == 0o600
            and parts[3] == ROOT_UID
            and parts[5] == 1
            and parts[6] == len(stage.DENY),
            "denial-proof",
        )
    return value


def claim(prepared, trusted):
    backup.private_directory(RUNTIME_ROOT.parent)
    try:
        RUNTIME_ROOT.mkdir(mode=0o700)
    except FileExistsError:
        backup.private_directory(RUNTIME_ROOT)
        profile, _ = backup.read_private(RUNTIME_ROOT / "profile.json")
        require(profile == PROFILE, "runtime-profile")
    else:
        backup.write_private(RUNTIME_ROOT / "profile.json", PROFILE)
        backup.sync_directory(RUNTIME_ROOT.parent)
    directory = claim_path(prepared)
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        raise state.PersistenceError("persistence-blank-boot-target-consumed") from None
    backup.sync_directory(RUNTIME_ROOT)
    backup.write_private(
        directory / "intent.json", {"prepared": prepared, "prepared_sha256": trusted}
    )
    backup.write_private(
        directory / "write-possible.json", {"vmid": prepared["policy"]["vmid"]}
    )
    return directory


def write_blob(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    backup.sync_directory(path.parent)


def reload_units():
    observe.native(["/usr/bin/systemctl", "daemon-reload"])


def unit_facts(prepared):
    result = {}
    for unit in stage.unit_names(request_of(prepared)):
        raw = observe.native(
            [
                "/usr/bin/systemctl",
                "show",
                unit,
                "-p",
                "LoadState,ActiveState,MainPID,DropInPaths",
            ]
        ).decode()
        fields = {}
        for line in raw.splitlines():
            key, separator, value = line.partition("=")
            require(separator == "=" and key not in fields, "unit-shape")
            fields[key] = value
        state.keys(fields, {"LoadState", "ActiveState", "MainPID", "DropInPaths"})
        require(state.matches(r"0|[1-9][0-9]*", fields["MainPID"]), "unit-pid")
        fields["MainPID"] = int(fields["MainPID"])
        fields["DropInPaths"] = fields["DropInPaths"].split()
        fields["commands"] = execution.commands(unit)
        result[unit] = fields
    return result


def publication(prepared, *, denied=False, running=False):
    directory = claim_path(prepared)
    backup.private_directory(directory)
    raw, guard_info = observe.read_regular(directory / "guard.py", 65536)
    require(
        state.sha256(raw) == GUARD_SHA256
        and guard_info.st_uid == ROOT_UID
        and stat.S_IMODE(guard_info.st_mode) == 0o600,
        "guard-file",
    )
    policy, policy_raw = backup.read_private(directory / "policy.json")
    require(
        policy_raw == state.canonical(prepared["policy"])
        and state.canonical(policy) == state.canonical(prepared["policy"]),
        "policy-file",
    )
    request = request_of(prepared)
    units = unit_facts(prepared)
    require(set(units) == set(stage.unit_names(request)), "unit-membership")
    for index, unit in enumerate(stage.unit_names(request)):
        old, path = stage.dropin_path(request, unit), allowing_dropin(request, unit)
        expected_paths = [str(old), str(path)] if denied else [str(path)]
        require(
            {p.name for p in path.parent.iterdir()}
            == {Path(name).name for name in expected_paths},
            "unit-directory",
        )
        body, info = observe.read_regular(path, 4096)
        require(
            body == dropin_body(prepared)
            and info.st_uid == ROOT_UID
            and stat.S_IMODE(info.st_mode) == 0o600,
            "allowing-file",
        )
        fields = units[unit]
        require(
            fields["LoadState"] == "loaded"
            and fields["DropInPaths"] == expected_paths
            and fields["ActiveState"]
            == ("active" if running and index == 0 else "inactive")
            and type(fields["MainPID"]) is int
            and (
                fields["MainPID"] > 1
                if running and index == 0
                else fields["MainPID"] == 0
            ),
            "unit-state",
        )
        expected_argv = (
            [["/usr/bin/false"], guard_argv(prepared)]
            if denied
            else [guard_argv(prepared)]
        )
        require(
            type(fields["commands"]) is list
            and len(fields["commands"]) == len(expected_argv),
            "unit-commands",
        )
        for command, argv in zip(fields["commands"], expected_argv):
            require(
                command["path"] == argv[0]
                and command["argv"] == argv
                and command["ignore_errors"] is False,
                "unit-command",
            )
    # D-Bus/systemctl reads above may be slow. Close named artifacts afterwards.
    closing_guard, closing_info = observe.read_regular(directory / "guard.py", 65536)
    closing_policy, closing_policy_raw = backup.read_private(directory / "policy.json")
    require(
        closing_guard == raw
        and observe.stable(closing_info) == observe.stable(guard_info)
        and closing_policy_raw == policy_raw
        and state.canonical(closing_policy) == state.canonical(policy),
        "closing-artifacts-changed",
    )
    for unit in stage.unit_names(request):
        body, info = observe.read_regular(allowing_dropin(request, unit), 4096)
        require(
            body == dropin_body(prepared)
            and info.st_uid == ROOT_UID
            and stat.S_IMODE(info.st_mode) == 0o600,
            "closing-allowing-file",
        )
    return units


def check_guard(prepared):
    result = observe.decode(observe.native(guard_argv(prepared)))
    require(result == {"outcome": "blank-os-only"}, "guard-check")


def publish(prepared, directory):
    write_blob(directory / "guard.py", guard_source())
    backup.write_private(directory / "policy.json", prepared["policy"])
    request = request_of(prepared)
    for unit in stage.unit_names(request):
        write_blob(allowing_dropin(request, unit), dropin_body(prepared))
    reload_units()
    publication(prepared, denied=True)
    check_guard(prepared)
    for unit in stage.unit_names(request):
        path = stage.dropin_path(request, unit)
        raw, info = observe.read_regular(path, 4096)
        require(
            raw == stage.DENY
            and list(observe.stable(info)) == prepared["denials"][unit]["identity"],
            "denial-changed",
        )
        path.unlink()
        backup.sync_directory(path.parent)
    reload_units()
    publication(prepared)
    check_guard(prepared)


def history(units, prepared, clock):
    normal = stage.unit_names(request_of(prepared))[0]
    commands = units[normal]["commands"]
    command = commands[0]
    if command["code"] == 1:
        execution.require_success(
            commands, guard_argv(prepared), clock, int(time.time())
        )
        return "observed-success"
    require(
        all(
            type(command[key]) is int and command[key] == 0
            for key in (
                "pid",
                "code",
                "status",
                "start_real_us",
                "stop_real_us",
                "start_monotonic_us",
                "stop_monotonic_us",
            )
        ),
        "guard-history",
    )
    return "cleared-or-unobserved"


def observe_attempt(prepared, directory):
    acknowledgement = directory / "acknowledgement.json"
    if not os.path.lexists(acknowledgement):
        return {**FLAGS, "phase": "boot-uncertain"}
    ack, _ = backup.read_private(acknowledgement)
    require(ack.get("tls_verified") is True, "acknowledgement")
    request = request_of(prepared)
    expected = recipient.parse_upid(request, ack.get("upid"), kind="vzstart")
    dispatch, _ = backup.read_private(directory / "dispatch.json")
    require(
        type(dispatch.get("clock")) is int
        and dispatch["clock"] - 2 <= expected["starttime"] <= dispatch["clock"] + 60,
        "task-clock",
    )
    task, log = recipient.task_state(request, ack["upid"], kind="vzstart")
    outcome = recipient.native_outcome(task, log)
    result = {
        **FLAGS,
        "phase": "boot-starting" if task["status"] == "running" else "boot-unqualified",
        "task": task,
        "log": log,
        "native_outcome": outcome,
    }
    if task["status"] != "stopped" or not outcome["accepted"]:
        return result
    units = publication(prepared, running=True)
    observed = runtime.collect(prepared["policy"])
    runtime.validate(prepared["policy"], observed)
    closing_units = publication(prepared, running=True)
    require(
        {unit: fields["MainPID"] for unit, fields in units.items()}
        == {unit: fields["MainPID"] for unit, fields in closing_units.items()},
        "closing-unit-process-changed",
    )
    units = closing_units
    result.update(
        phase="blank-os-runtime-verified",
        boot_verified=True,
        runtime=observed,
        units=units,
        guard_execution_history=history(units, prepared, dispatch["clock"]),
    )
    return result


def identity(result):
    value = result["runtime"]
    kernel = {key: value[key] for key in ("init", "rootfs", "security")}
    kernel["cgroup"] = {
        key: value["cgroup"][key] for key in value["cgroup"] if key != "cpus"
    }
    guest = {key: value["guest"][key] for key in value["guest"] if key != "affinity"}
    return {
        "kernel": kernel,
        "guest": guest,
        "config": value["config"],
        "status": value["status"],
        "unit_pids": {
            unit: fields["MainPID"] for unit, fields in result["units"].items()
        },
    }


def close_result(prepared, directory, result):
    if not result["boot_verified"]:
        return
    fresh = observe_attempt(prepared, directory)
    require(
        fresh["boot_verified"] is True
        and state.canonical(identity(fresh)) == state.canonical(identity(result))
        and state.canonical(fresh["task"]) == state.canonical(result["task"])
        and state.canonical(fresh["log"]) == state.canonical(result["log"]),
        "closing-runtime-changed",
    )


def boot(raw, trusted, *, timeout_seconds=240):
    prepared = load_prepared(raw, trusted)
    require(os.geteuid() == ROOT_UID, "root-required")
    require(not os.path.lexists(claim_path(prepared)), "target-consumed")
    fresh = prepare(
        state.canonical(prepared["stage_prepared"]),
        prepared["stage_sha256"],
        prepared["stage_completion_sha256"],
    )
    require(state.canonical(fresh) == raw, "preflight-changed")
    directory = None
    try:
        with observe.source_state(
            request_of(prepared)["source_request"], require_stopped=True
        ) as facts:
            stage.check_source(prepared["stage_prepared"], facts)
            require(
                state.canonical(
                    stage.recipient.verify_target(
                        request_of(prepared),
                        prepared["stage_prepared"]["recipient_prepared"],
                    )
                )
                == state.canonical(prepared["stage_prepared"]["target"]),
                "target-changed",
            )
            require(
                state.canonical(denial_facts(request_of(prepared)))
                == state.canonical(prepared["denials"]),
                "denials-changed",
            )
            directory = claim(prepared, trusted)
            publish(prepared, directory)
            backup.write_private(
                directory / "dispatch.json", {"clock": int(time.time())}
            )
            ack = recipient.post_guest_action(request_of(prepared), "start")
            backup.write_private(directory / "acknowledgement.json", ack)
            deadline = time.monotonic() + timeout_seconds
            while True:
                try:
                    result = observe_attempt(prepared, directory)
                except state.PersistenceError as error:
                    if error.code not in {
                        "persistence-blank-runtime-guest-not-ready",
                        "persistence-blank-runtime-state-changed",
                    }:
                        raise
                    result = {**FLAGS, "phase": "boot-starting"}
                if result["phase"] != "boot-starting":
                    break
                require(time.monotonic() < deadline, "readiness-timeout")
                time.sleep(1)
            require(result["boot_verified"] is True, "native-start-unqualified")
        close_result(prepared, directory, result)
        complete = {"prepared_sha256": trusted, **result}
        checksum = backup.write_private(directory / "complete.json", complete)
        close_result(prepared, directory, result)
        return {**complete, "completion_sha256": checksum}
    except BaseException as error:
        if directory is not None:
            try:
                backup.write_private(
                    directory / "failed.json",
                    {
                        "error_code": getattr(
                            error, "code", "persistence-blank-boot-interrupted"
                        )
                    },
                )
            except OSError:
                pass
        raise


def status(raw, trusted):
    prepared = load_prepared(raw, trusted)
    directory = claim_path(prepared)
    backup.private_directory(directory)
    intent, _ = backup.read_private(directory / "intent.json")
    require(
        state.canonical(intent)
        == state.canonical({"prepared": prepared, "prepared_sha256": trusted}),
        "retained-intent",
    )
    with observe.source_state(
        request_of(prepared)["source_request"], require_stopped=True
    ) as facts:
        stage.check_source(prepared["stage_prepared"], facts)
        result = observe_attempt(prepared, directory)
    close_result(prepared, directory, result)
    if result["boot_verified"] and os.path.lexists(directory / "complete.json"):
        complete, _ = backup.read_private(directory / "complete.json")
        require(
            complete["prepared_sha256"] == trusted
            and state.canonical(identity(complete))
            == state.canonical(identity(result)),
            "completed-runtime-changed",
        )
    close_result(prepared, directory, result)
    return result
