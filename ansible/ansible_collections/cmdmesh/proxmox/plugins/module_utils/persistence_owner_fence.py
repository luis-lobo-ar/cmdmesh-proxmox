"""Pure finite owner-actor capture validation, never a fresh worker fence.

Authority bytes/hash are selected externally after successful controller and
reviewed source/scope qualification. A node cannot choose its own authority.
The real collector must authenticate providers, take actual leases and close
controls before asserting a request fence. This module performs no observation.
"""

import copy
from pathlib import PurePosixPath
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_attach as attach,
    persistence_blank_boot as blank,
    persistence_recipient as recipient,
    persistence_owner_checkpoint as checkpoint_codec,
    persistence_owner_transition as transition,
    persistence_owner_retirement as retirement,
    persistence_owner_reaper as reaper,
)

state, observe, current = transition.state, transition.observe, transition.current
legacy, api, writer = retirement.legacy, transition.api, transition.writer
PROFILE = "owner-v3-ack-clock-local-dir-v1"
SCOPE = "cooperating-owner-actors-only-throughout-interval"
SOURCES = frozenset(
    {
        "owner_transition",
        "owner_journal",
        "guest_api",
        "retained_boot",
        "blank_boot",
        "recipient",
        "writer_execution",
        "attach",
        "owner_publish",
        "owner_reconcile",
        "controller_boundary",
        "RESTEnvironment",
        "UPID",
        "Cmd",
        "LXC",
        "Storage",
        "StoragePlugin",
        "DirPlugin",
        "Tools",
        "LXCConfig",
    }
)
FILE_LIMIT = 4194304
AUTHORITY_LIMIT = 4194304
CAPTURE_LIMIT = 33554432
PROCESS_LIMIT = 8192


def require(value, code):
    state.require(value, "persistence-owner-fence-" + code)


def digest(value):
    return state.sha256(state.canonical(value))


def _keys(value, fields):
    require(type(value) is dict and set(value) == set(fields), "schema")


def _decode(raw, trusted, limit):
    state.digest(trusted)
    require(type(raw) is bytes and 0 < len(raw) <= limit, "raw-input")
    require(state.sha256(raw) == trusted, "external-hash")
    value = observe.decode(raw)
    require(type(value) is dict and state.canonical(value) == raw, "canonical")
    return value


def _raw(text, limit=FILE_LIMIT):
    require(type(text) is str and 0 < len(text) <= limit, "raw-text")
    try:
        raw = text.encode("utf-8")
    except UnicodeError:
        require(False, "raw-text")
    require(len(raw) <= limit, "raw-text")
    return raw


def _json(text, limit=FILE_LIMIT):
    raw = _raw(text, limit)
    return _decode(raw, state.sha256(raw), limit)


def _document(value, kind, fields):
    _keys(value, {"document_type", "schema_version", *fields})
    require(
        value["document_type"] == "cmdmesh.proxmox." + kind
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1,
        "document",
    )


def _authority(value):
    hashes = {
        "checkpoint_sha256",
        "writer_prepared_sha256",
        "writer_completion_sha256",
        "shutdown_prepared_sha256",
        "shutdown_result_sha256",
        "shutdown_head_sha256",
        "resume_prepared_sha256",
        "failure_provenance_sha256",
        "legacy_basis_sha256",
    }
    _document(value, "owner-causal-authority", {*hashes, "source_profile"})
    for key in hashes:
        state.digest(value[key])
    profile = value["source_profile"]
    _keys(profile, {"id", "scope", "sources", "extra_claims"})
    require(profile["id"] == PROFILE and profile["scope"] == SCOPE, "source-profile")
    _keys(profile["sources"], SOURCES)
    for checksum in profile["sources"].values():
        state.digest(checksum)
    _keys(profile["extra_claims"], {"blank_boot", "recipient", "attach"})
    for claim in profile["extra_claims"].values():
        _keys(claim, {"prepared_sha256", "files"})
        state.digest(claim["prepared_sha256"])
        require(
            type(claim["files"]) is dict and 2 <= len(claim["files"]) <= 32,
            "claim-files",
        )
        for name, item in claim["files"].items():
            require(state.matches(r"[a-z0-9][a-z0-9_.-]{0,127}", name), "claim-name")
            _keys(item, {"sha256", "bytes"})
            state.digest(item["sha256"])
            state.integer(item["bytes"], 1, FILE_LIMIT)
    return profile


def _checkpoint(authority, captured):
    _keys(captured, {"prepared", "completion", "records"})
    _keys(captured["records"], writer.NAMES | {"complete.json"})
    checkpoint = checkpoint_codec.load_writer_checkpoint(
        prepared_raw=_raw(captured["prepared"], 8388608),
        prepared_sha256=authority["writer_prepared_sha256"],
        completion_raw=_raw(captured["completion"]),
        completion_sha256=authority["writer_completion_sha256"],
        records={name: _raw(raw) for name, raw in captured["records"].items()},
    )
    require(digest(checkpoint) == authority["checkpoint_sha256"], "checkpoint")
    return checkpoint


def _shutdown(authority, checkpoint, captured):
    _keys(captured, {"prepared", "result"})
    raw = _raw(captured["prepared"], 8388608)
    prepared = transition._decode(
        checkpoint, raw, authority["shutdown_prepared_sha256"]
    )
    result_raw = _raw(captured["result"], CAPTURE_LIMIT)
    result = _decode(result_raw, authority["shutdown_result_sha256"], CAPTURE_LIMIT)
    transition.validate_result(
        checkpoint, raw, authority["shutdown_prepared_sha256"], result
    )
    require(
        prepared["kind"] == "shutdown"
        and result["phase"] == "stopped"
        and result["head_sha256"] == authority["shutdown_head_sha256"],
        "accepted-shutdown",
    )
    terminal = _json(result["operation_records"]["terminal.json"])
    task = terminal["payload"]["task"]
    api.validate_task_status(
        transition.binding(checkpoint).guest, task["upid"], task, kind="vzshutdown"
    )
    return prepared, result, task


def _failure(authority, checkpoint, captured, head):
    _keys(captured, {"prepared", "provenance"})
    raw = _raw(captured["prepared"], 8388608)
    prepared = transition._decode(checkpoint, raw, authority["resume_prepared_sha256"])
    require(
        prepared["kind"] == "resume" and prepared["predecessor_sha256"] == head,
        "failed-resume",
    )
    provenance = _decode(
        _raw(captured["provenance"]), authority["failure_provenance_sha256"], FILE_LIMIT
    )
    _document(
        provenance,
        "owner-post-return-failure",
        {
            "error_code",
            "checkpoint_sha256",
            "prepared_sha256",
            "dispatch_sha256",
            "source_profile_sha256",
            "receipt_sha256",
            "mutation_attempted",
            "effects_may_exist",
            "command_outcome",
            "os_transition_verified",
        },
    )
    require(
        provenance["error_code"] == "persistence-owner-journal-ack-clock"
        and provenance["checkpoint_sha256"] == authority["checkpoint_sha256"]
        and provenance["prepared_sha256"] == authority["resume_prepared_sha256"]
        and provenance["source_profile_sha256"] == digest(authority["source_profile"])
        and provenance["mutation_attempted"] is True
        and provenance["effects_may_exist"] is True
        and provenance["command_outcome"] == "unknown"
        and provenance["os_transition_verified"] is False,
        "failure-provenance",
    )
    for key in ("receipt_sha256", "dispatch_sha256"):
        state.digest(provenance[key])
    return prepared, provenance


def _file(value, *, path=None, expected=None, legacy_file=False):
    _keys(value, {"raw", "identity", *({"path"} if path is not None else set())})
    raw = _raw(value["raw"])
    if path is not None:
        require(value["path"] == str(path), "manager-file-path")
    identity = value["identity"]
    # The checkpoint codec shares the exact native full9/private-file contract.
    checkpoint_codec._file(
        {"path": "captured", "sha256": state.sha256(raw), "identity": identity},
        "captured",
        state.sha256(raw),
        len(raw),
        legacy=legacy_file,
    )
    if expected is not None:
        require(
            state.sha256(raw) == expected["sha256"]
            and len(raw)
            == (
                expected["identity"][6] if "identity" in expected else expected["bytes"]
            ),
            "manager-file-content",
        )
        if "identity" in expected:
            require(identity == expected["identity"], "manager-file-identity")
    return raw


def _directory(value, path, expected_files, identity=None):
    require(
        type(expected_files) is dict
        and 0 < len(expected_files) <= 32
        and all(
            state.matches(r"[a-z0-9][a-z0-9_.-]{0,127}", name)
            for name in expected_files
        ),
        "manager-file-names",
    )
    _keys(value, {"path", "identity", "files"})
    require(value["path"] == str(path), "manager-claim-path")
    checkpoint_codec._directory(value["identity"])
    if identity is not None:
        require(value["identity"] == identity[:5], "manager-claim-identity")
    _keys(value["files"], expected_files)
    return {
        name: _file(
            item, expected=expected_files[name], legacy_file=name == "legacy-guard.py"
        )
        for name, item in value["files"].items()
    }


def _legacy(authority, owner, captured, shutdown, prepared, provenance):
    _keys(captured, {"basis", "records", "runtime", "directories"})
    basis = captured["basis"]
    require(digest(basis) == authority["legacy_basis_sha256"], "blocked-basis")
    retirement._basis_shape(owner, basis)
    _keys(captured["records"], basis["files"])
    records = {name: _raw(text) for name, text in captured["records"].items()}
    require(sum(map(len, records.values())) <= retirement.BASIS_LIMIT, "legacy-limit")
    for name, raw in records.items():
        descriptor = basis["files"][name]
        require(
            state.sha256(raw) == descriptor["sha256"]
            and len(raw) == descriptor["identity"][6],
            "legacy-raw",
        )
    runtime_raw = _file(captured["runtime"], path=legacy.RUNTIME_ROOT / "runtime.json")
    require(runtime_raw == state.canonical(legacy.RUNTIME), "legacy-runtime")
    _keys(
        captured["directories"],
        {str(legacy.RUNTIME_ROOT.parent), str(legacy.RUNTIME_ROOT)},
    )
    for identity in captured["directories"].values():
        checkpoint_codec._directory(identity)
    sequence = shutdown["sequence"]
    slot = legacy._slot(sequence)
    require(basis["maximum_sequence"] == sequence + 1, "pending-sequence")
    for name, text in shutdown["operation_records"].items():
        relative = slot + "/" + name
        if name != "HEAD.json":
            require(records[relative] == text.encode(), "accepted-prefix")
    anchor = {
        "head": _json(shutdown["operation_records"]["HEAD.json"]),
        "sha256": authority["shutdown_head_sha256"],
    }
    dispatch = _json(records[legacy._slot(sequence + 1) + "/dispatch.json"].decode())
    require(digest(dispatch) == provenance["dispatch_sha256"], "failure-dispatch")
    # Preparations omit API uptime; this legacy resume entered a stopped OS,
    # whose full dispatch entry necessarily has uptime zero, not a guessed clock.
    entry = copy.deepcopy(prepared["entry"])
    require(
        entry["phase"] == "stopped"
        and entry["guest"]["status"] == "stopped"
        and entry["guest"]["runtime"] == {"vmid": owner.guest.vmid, "pid": 0},
        "resume-entry",
    )
    entry["guest"]["runtime"]["uptime"] = 0
    require(
        dispatch["payload"]["entry_sha256"] == digest(entry),
        "resume-dispatch-entry",
    )
    evidence = {
        "accepted_prepared_sha256": authority["resume_prepared_sha256"],
        "host_epoch": dispatch["payload"]["host_epoch"],
    }
    retirement._validate_legacy(owner, basis, records, anchor, evidence)
    require(
        prepared["entry"]["host"]["boot_id"] == evidence["host_epoch"]["boot_id"]
        and prepared["entry"]["host"]["mount_namespace"]
        == evidence["host_epoch"]["mount_namespace"],
        "prepared-epoch",
    )
    epoch = evidence["host_epoch"]
    for frame in (
        shutdown["before"]["observation"],
        shutdown["current"]["observation"],
    ):
        require(
            all(frame["host"][key] == value for key, value in epoch.items()),
            "shutdown-dispatch-epoch",
        )
    return epoch


def _claim_ack(binding, raws, kind):
    ack = _json(raws["acknowledgement.json"].decode())
    _keys(ack, {"upid", "tls_verified"})
    require(ack["tls_verified"] is True, "claim-ack")
    return api.parse_upid(binding, ack["upid"], kind=kind)


def _extra_claim(name, captured, expected, owner):
    root = {
        "blank_boot": blank.RUNTIME_ROOT,
        "recipient": recipient.RUNTIME_ROOT,
        "attach": attach.RUNTIME_ROOT,
    }[name]
    key = (
        owner.pair_key
        if name == "attach"
        else digest([owner.guest.machine_id_sha256, owner.guest.vmid])
    )
    raws = _directory(captured, root / key, expected["files"])
    require({"intent.json", "write-possible.json"} <= set(raws), "claim-progress")
    intent = _json(raws["intent.json"].decode())
    _keys(intent, {"prepared", "prepared_sha256"})
    require(
        intent["prepared_sha256"] == expected["prepared_sha256"]
        and digest(intent["prepared"]) == expected["prepared_sha256"],
        "claim-preparation",
    )
    return intent["prepared"], raws


def _actors(checkpoint, owner, captured, profile):
    _keys(
        captured,
        {
            "history_directories",
            "history_files",
            "writer",
            "blank_boot",
            "recipient",
            "attach",
            "runtime_files",
            "runtime_directories",
        },
    )
    prepared, completed = checkpoint["prepared"], checkpoint["completion"]
    history = prepared["history"]
    roots = (
        writer.boot.RUNTIME_ROOT,
        writer.boot.reconcile.RUNTIME_ROOT,
        writer.boot.reconcile.original.RUNTIME_ROOT,
    )
    require(
        set(history["directories"]) == {str(root / owner.pair_key) for root in roots},
        "history-claim-roots",
    )
    _keys(captured["history_directories"], history["directories"])
    groups = {
        path: _directory(
            captured["history_directories"][path],
            path,
            expected["files"],
            expected["identity"],
        )
        for path, expected in history["directories"].items()
    }
    _keys(captured["history_files"], history["files"])
    for path, item in captured["history_files"].items():
        _file(
            item,
            path=path,
            expected=history["files"][path],
            legacy_file=PurePosixPath(path).name == "legacy-guard.py",
        )
    writer_files = {
        **completed["journal_files"],
        "complete.json": {
            "sha256": checkpoint["completion_sha256"],
            "bytes": len(state.canonical(completed)),
        },
    }
    _directory(
        captured["writer"],
        writer.trial.claim_path(prepared["source_request"]),
        writer_files,
        completed["claim_directory_identity"],
    )
    boot_path = str(writer.boot.claim_path(prepared["source_request"]))
    require(boot_path in groups, "retained-claim")
    boot_raw = groups[boot_path]
    require(
        state.sha256(boot_raw["complete.json"]) == prepared["boot_completion_sha256"]
        and boot_raw["complete.json"] == state.canonical(prepared["boot_completion"]),
        "retained-completion",
    )
    retained = _claim_ack(owner.guest, boot_raw, "vzstart")
    task = _json(boot_raw["task.json"].decode())
    _keys(task, {"task", "log", "native_outcome"})
    api.validate_task_status(owner.guest, retained["upid"], task["task"])
    require(
        task["task"]["status"] == "stopped"
        and api.native_outcome(task["task"], task["log"]) == task["native_outcome"]
        and task["native_outcome"]["accepted"] is True,
        "retained-task",
    )
    require(
        all(
            task[key] == prepared["boot_completion"][key]
            for key in ("task", "log", "native_outcome")
        ),
        "retained-task-completion",
    )

    extras = {
        name: _extra_claim(name, captured[name], profile["extra_claims"][name], owner)
        for name in ("blank_boot", "recipient", "attach")
    }
    bprep, braw = extras["blank_boot"]
    rprep, rraw = extras["recipient"]
    aprep, araw = extras["attach"]
    require(
        set(braw)
        == {
            "intent.json",
            "write-possible.json",
            "dispatch.json",
            "acknowledgement.json",
            "failed.json",
            "guard.py",
            "policy.json",
        },
        "blank-membership",
    )
    require(
        set(rraw)
        == {
            "intent.json",
            "write-possible.json",
            "dispatch.json",
            "acknowledgement.json",
            "failed.json",
        },
        "recipient-membership",
    )
    try:
        breq = bprep["stage_prepared"]["recipient_prepared"]["request"]
        rreq = rprep["request"]
        attachment = prepared["boot_prepared"]["reconciliation_prepared"][
            "parent_prepared"
        ]["attachment_prepared"]
        for request in (breq, rreq):
            require(
                request["source_request"]["source"]["host_profile"]["machine_id_sha256"]
                == owner.guest.machine_id_sha256
                and request["source_request"]["source"]["selector"]["node"]
                == owner.guest.node
                and type(request["target"]["vmid"]) is int
                and request["target"]["vmid"] == owner.guest.vmid,
                "claim-target",
            )
        require(aprep == attachment, "attachment-lineage")
        require(
            _json(araw["write-possible.json"].decode()) == {"pair_key": owner.pair_key},
            "attachment-pair",
        )
        require(
            _json(braw["write-possible.json"].decode()) == {"vmid": owner.guest.vmid}
            and braw["policy.json"] == state.canonical(bprep["policy"])
            and state.sha256(braw["guard.py"]) == blank.GUARD_SHA256,
            "blank-controls",
        )
        require(
            _json(rraw["write-possible.json"].decode())
            == {"operation_id": rreq["operation_id"]},
            "recipient-claim",
        )
        dispatch = _json(rraw["dispatch.json"].decode())
        _keys(dispatch, {"clock", "parameters"})
        state.integer(dispatch["clock"], 1, 2**63 - 1)
        require(
            dispatch["parameters"] == recipient.create_request(rreq)
            and dispatch["parameters"]["start"] == "0",
            "recipient-stopped-create",
        )
    except (KeyError, TypeError, IndexError):
        require(False, "claim-lineage")
    blank_ack = _claim_ack(owner.guest, braw, "vzstart")
    _claim_ack(owner.guest, rraw, "vzcreate")
    runtime = {
        blank.RUNTIME_ROOT: blank.PROFILE,
        recipient.RUNTIME_ROOT: recipient.PROFILE,
        attach.RUNTIME_ROOT: attach.PROFILE,
    }
    own = completed["runtime_profile"]
    runtime_files = {
        str(root / "profile.json"): state.canonical(value)
        for root, value in runtime.items()
    }
    runtime_files[own["file"]["path"]] = state.canonical(writer.trial.PROFILE)
    _keys(captured["runtime_files"], runtime_files)
    for path, raw in runtime_files.items():
        observed = _file(
            captured["runtime_files"][path],
            path=path,
            expected=own["file"] if path == own["file"]["path"] else None,
        )
        require(observed == raw, "runtime-profile")
    roots = {
        blank.RUNTIME_ROOT,
        recipient.RUNTIME_ROOT,
        attach.RUNTIME_ROOT,
        writer.trial.RUNTIME_ROOT,
        writer.boot.RUNTIME_ROOT,
        writer.boot.reconcile.RUNTIME_ROOT,
        writer.boot.reconcile.original.RUNTIME_ROOT,
    }
    directories = {str(path) for root in roots for path in (root.parent, root)}
    _keys(captured["runtime_directories"], directories)
    for identity in captured["runtime_directories"].values():
        checkpoint_codec._directory(identity)
    for path, identity in (
        (writer.trial.RUNTIME_ROOT, own["directory"]),
        (writer.boot.RUNTIME_ROOT, prepared["boot_runtime"]["directory"]),
    ):
        require(
            captured["runtime_directories"][str(path)] == identity,
            "runtime-directory-identity",
        )
    return (blank_ack["upid"], retained["upid"])


def _process(row):
    _keys(
        row,
        {
            "pid",
            "pstart",
            "ppid",
            "exe",
            "argv",
            "comm",
            "flags",
            "mount_namespace",
            "pid_namespace",
        },
    )
    for key, minimum, maximum in (
        ("pid", 1, 2**32 - 1),
        ("pstart", 0, 2**64 - 1),
        ("ppid", 0, 2**32 - 1),
        ("flags", 0, 2**64 - 1),
    ):
        state.integer(row[key], minimum, maximum)
    require(
        type(row["argv"]) is list
        and len(row["argv"]) <= 128
        and all(
            type(arg) is str and len(arg.encode()) <= 4096 and "\x00" not in arg
            for arg in row["argv"]
        ),
        "process-argv",
    )
    require(
        type(row["comm"]) is str
        and 0 < len(row["comm"]) <= 15
        and "\x00" not in row["comm"],
        "process-comm",
    )
    require(
        state.matches(r"mnt:\[[1-9][0-9]*\]", row["mount_namespace"])
        and state.matches(r"pid:\[[1-9][0-9]*\]", row["pid_namespace"]),
        "process-namespaces",
    )
    if row["exe"] is None:
        require(bool(row["flags"] & 0x200000) and not row["argv"], "kernel-thread")
    else:
        require(
            type(row["exe"]) is str
            and row["exe"].startswith("/")
            and len(row["exe"]) <= 4096
            and "\x00" not in row["exe"],
            "process-exe",
        )


def _projection(checkpoint, captured, epoch, candidate, host_pid_namespace):
    _keys(captured, {"current", "projection"})
    evidence, projection = captured["current"], captured["projection"]
    current.validate_current(checkpoint, "os_quiesced", evidence)
    frame = evidence["observation"]
    init = frame["kernel"]["init"]
    expected_epoch = {
        **epoch,
        "pid_namespace": f"pid:[{init['host_pid_namespace_inode']}]",
    }
    require(
        expected_epoch["pid_namespace"] == host_pid_namespace, "shutdown-pid-namespace"
    )
    _keys(projection, {"epoch", "units", "processes"})
    require(
        projection["epoch"] == expected_epoch
        and all(frame["host"][key] == epoch[key] for key in epoch),
        "projection-epoch",
    )
    policy = checkpoint["prepared"]["source_request"]["policy"]
    vmids = (policy["vmid"], policy["retired_guest"]["vmid"])
    normal = f"pve-container@{policy['vmid']}.service"
    monitor = frame["reference"]["units"][normal]["MainPID"]
    units = {
        f"{kind}@{vmid}.service"
        for vmid in vmids
        for kind in ("pve-container", "pve-container-debug")
    }
    _keys(projection["units"], units)
    for name, unit in projection["units"].items():
        _keys(unit, {"ActiveState", "SubState", "MainPID", "Job"})
        require(
            type(unit["ActiveState"]) is str and type(unit["SubState"]) is str,
            "unit-state",
        )
        require(
            type(unit["Job"]) is int
            and unit["Job"] == 0
            and type(unit["MainPID"]) is int
            and unit["MainPID"] == (monitor if name == normal else 0),
            "unit-job",
        )
        require(
            (unit["ActiveState"], unit["SubState"])
            in (
                {("active", "running")}
                if name == normal
                else {("inactive", "dead"), ("failed", "failed")}
            ),
            "unit-state",
        )
    rows = projection["processes"]
    require(type(rows) is list and 0 < len(rows) <= PROCESS_LIMIT, "process-count")
    by_pid = {}
    for row in rows:
        _process(row)
        require(row["pid"] not in by_pid, "duplicate-process")
        by_pid[row["pid"]] = row
    require(
        init["pid"] in by_pid and monitor in by_pid and monitor != init["pid"],
        "current-processes",
    )
    init_row = by_pid[init["pid"]]
    require(
        init_row["pstart"] == init["pstart"]
        and init_row["pid_namespace"] == f"pid:[{init['pid_namespace_inode']}]",
        "init-process",
    )
    require(
        by_pid[monitor]["pid_namespace"] == expected_epoch["pid_namespace"],
        "monitor-process",
    )
    require(
        init_row["exe"] == "/usr/lib/systemd/systemd"
        and init_row["argv"] == ["/sbin/init"],
        "init-process-role",
    )
    monitor_row = by_pid[monitor]
    require(
        monitor_row["exe"] == "/usr/bin/lxc-start"
        and monitor_row["argv"]
        == ["/usr/bin/lxc-start", "-F", "-n", str(policy["vmid"])],
        "monitor-process-role",
    )
    require(monitor_row["pstart"] >= candidate["pstart"], "monitor-before-request")
    target = by_pid.get(candidate["pid"])
    require(
        target is None or target["pstart"] > candidate["pstart"],
        "candidate-still-running",
    )
    for row in rows:
        if row["pid"] in {init["pid"], monitor}:
            continue
        args = row["argv"]
        joined = " ".join(args)
        # Unknown target-related work refuses. Unrelated process churn is allowed.
        require(not any(unit in joined for unit in units), "live-unit-helper")
        require(
            not any(f":{vmid}:" in joined and "UPID:" in joined for vmid in vmids),
            "live-target-task",
        )
        commands = {PurePosixPath(row["exe"] or "/kernel-thread").name}
        commands.update(PurePosixPath(arg).name for arg in args[:2])
        if commands & {"systemctl", "pct", "pvesh"} or any(
            command.startswith(("lxc-", "pve-container-")) for command in commands
        ):
            require(
                not any(
                    arg.rsplit("=", 1)[-1]
                    in {unit.removesuffix(".service") for unit in units}
                    for arg in args
                ),
                "live-unit-helper",
            )
            require(
                not any(
                    str(vmid) in args
                    or any(
                        arg
                        in {
                            "--name=" + str(vmid),
                            "--vmid=" + str(vmid),
                            "-n" + str(vmid),
                        }
                        or f"/lxc/{vmid}/" in arg
                        or arg.endswith(f"/lxc/{vmid}")
                        for arg in args
                    )
                    for vmid in vmids
                ),
                "live-target-helper",
            )
    return {"init": copy.deepcopy(init_row), "monitor": copy.deepcopy(by_pid[monitor])}


def validate_causal_capture(
    authority_raw, authority_sha256, capture_raw, capture_sha256
):
    """Verify one complete bounded semantic capture under external actor authority.

    This is deliberately not a collector, export authenticator or permission
    object. A prior successful return never replaces fresh real lease closure.
    """
    authority = _decode(authority_raw, authority_sha256, AUTHORITY_LIMIT)
    profile = _authority(authority)
    captured = _decode(capture_raw, capture_sha256, CAPTURE_LIMIT)
    _document(
        captured,
        "owner-causal-capture",
        {
            "checkpoint",
            "shutdown",
            "failed_resume",
            "legacy",
            "actors",
            "normal_return",
            "before",
            "closing",
        },
    )
    checkpoint = _checkpoint(authority, captured["checkpoint"])
    owner = transition.binding(checkpoint)
    _, shutdown, shutdown_task = _shutdown(authority, checkpoint, captured["shutdown"])
    prepared, provenance = _failure(
        authority, checkpoint, captured["failed_resume"], shutdown["head_sha256"]
    )
    epoch = _legacy(
        authority, owner, captured["legacy"], shutdown, prepared, provenance
    )
    excluded = _actors(checkpoint, owner, captured["actors"], profile)
    normal_raw = _raw(captured["normal_return"])
    normal = reaper.validate_normal_return(
        owner.guest,
        epoch["boot_id"],
        digest(profile),
        normal_raw,
        state.sha256(normal_raw),
        birth_floor=shutdown_task["pstart"],
        excluded_upids=excluded,
    )
    candidate = api.parse_upid(owner.guest, normal["upid"])
    old_init = shutdown["before"]["observation"]["kernel"]["init"]
    host_pid_namespace = f"pid:[{old_init['host_pid_namespace_inode']}]"
    before = _projection(
        checkpoint, captured["before"], epoch, candidate, host_pid_namespace
    )
    closing = _projection(
        checkpoint, captured["closing"], epoch, candidate, host_pid_namespace
    )
    require(before == closing, "current-process-changed")
    first, final = (
        copy.deepcopy(captured[key]["current"]) for key in ("before", "closing")
    )
    new_init = first["observation"]["kernel"]["init"]
    require(
        (new_init["pid"], new_init["pstart"]) != (old_init["pid"], old_init["pstart"])
        and new_init["pstart"] >= shutdown_task["pstart"],
        "new-init-required",
    )
    require(
        final["observation"]["guest"]["runtime"]["uptime"]
        >= first["observation"]["guest"]["runtime"]["uptime"],
        "uptime-decreased",
    )
    for value in (first, final):
        value["observation"]["guest"] = current.runtime.stable_guest(
            value["observation"]["guest"]
        )
    require(state.canonical(first) == state.canonical(final), "current-changed")
    require(
        state.canonical(authority) == authority_raw
        and state.canonical(captured) == capture_raw
        and digest(checkpoint) == authority["checkpoint_sha256"],
        "capture-memory-changed",
    )
    return {
        "semantic_certificate_verified": True,
        "authority_sha256": authority_sha256,
        "capture_sha256": capture_sha256,
        "checkpoint_sha256": authority["checkpoint_sha256"],
        "predecessor_sha256": authority["shutdown_head_sha256"],
        "pending_head_sha256": captured["legacy"]["basis"]["head_sha256"],
        "candidate_upid": normal["upid"],
        "source_profile_sha256": digest(profile),
        "scope": SCOPE,
        "host_epoch": copy.deepcopy(epoch),
        "original_request_fenced": False,
        "original_native_operation_qualified": False,
        "ack_recovered": False,
        "native_action_dispatched": False,
        "metadata_resolution_recorded": False,
        "mutation_attempted": False,
        "application_write_verified": False,
        "rebuild_verified": False,
        "restore_verified": False,
        "backup_verified": False,
    }
