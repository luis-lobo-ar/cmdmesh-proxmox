"""Prepare a retained OS start from an accepted, stopped owner handoff.

Preparation creates no runtime, claim or lifecycle task. Historical file seals
are independent of stopped observers so a later running controller can close
the same history without replaying reconciliation's current-state checks.
"""

from contextlib import ExitStack
import copy
import os
from pathlib import Path
import stat
import time

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_backup as backup,
    persistence_config_lock as config_lock,
    persistence_guest_api as api,
    persistence_observe as observe,
    persistence_owner_reconcile as reconcile,
    persistence_pair_lock as pair_lock,
    persistence_retained_runtime as runtime,
    persistence_state as state,
    systemd_exec as execution,
)

RUNTIME_ROOT = Path("/var/lib/cmdmesh/reference-retained-boot")
PREPARED = "cmdmesh.proxmox.persistence.prepared-retained-boot"
PROFILE = {
    "document_type": "cmdmesh.proxmox.persistence.retained-boot-runtime",
    "schema_version": 1,
}


def require(value, code):
    state.require(value, "persistence-retained-boot-" + code)


def claim_path(request):
    return RUNTIME_ROOT / state.pair_key(request["policy"]["datasets"])


def unused(request):
    require(observe.absolute(str(RUNTIME_ROOT)), "runtime-path")
    for item in request["policy"]["datasets"].values():
        mount = Path(item["mountpoint"])
        require(
            RUNTIME_ROOT != mount and mount not in RUNTIME_ROOT.parents,
            "runtime-inside-retained-state",
        )
    if os.path.lexists(RUNTIME_ROOT):
        backup.private_directory(RUNTIME_ROOT)
        require(
            backup.read_private(RUNTIME_ROOT / "profile.json")[1]
            == state.canonical(PROFILE),
            "runtime-profile",
        )
    require(not os.path.lexists(claim_path(request)), "pair-consumed")


def root_identity(profile):
    path = Path(profile["rootfs"]["path"])
    require(path.resolve(strict=True) == path, "root-path")
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "root-file")
    return list(observe.stable(info))[:7]


def _history_file(path, *, private=True):
    reconcile.original.safe_parents(path)
    raw, info = observe.read_regular(path, 4194304)
    require(
        info.st_uid == info.st_gid == os.geteuid()
        and (
            stat.S_IMODE(info.st_mode) == 0o600
            if private
            else not info.st_mode & 0o7022
        ),
        "history-permissions",
    )
    return {
        "path": str(path),
        "sha256": state.sha256(raw),
        "identity": list(observe.stable(info)),
    }


def _history_directory(path):
    backup.private_directory(path)
    before = list(observe.stable(path.lstat()))
    names = sorted(item.name for item in path.iterdir())
    require(
        0 < len(names) <= 32
        and all(state.matches(r"[a-z0-9][a-z0-9_.-]{0,127}", name) for name in names),
        "history-membership",
    )
    files = {
        name: _history_file(path / name, private=name != "legacy-guard.py")
        for name in names
    }
    require(
        sum(item["identity"][6] for item in files.values()) <= 16777216,
        "history-size",
    )
    require(
        sorted(item.name for item in path.iterdir()) == names
        and list(observe.stable(path.lstat())) == before,
        "history-directory-changed",
    )
    return {"identity": before, "files": files}


def history_seal(reconciliation, publication):
    """Read raw immutable history and controls, without stopped-state collection."""
    parent = reconciliation["parent_prepared"]
    directories = (
        reconcile.claim_path(parent),
        reconcile.original.claim_path(reconcile.request_of(parent)),
    )
    result = {
        "directories": {str(path): _history_directory(path) for path in directories},
        "files": {},
    }
    paths = {
        str(reconcile.RUNTIME_ROOT / "profile.json"),
        str(reconcile.original.RUNTIME_ROOT / "profile.json"),
    }
    paths.update(publication["files"])
    for control in publication["controls"].values():
        paths.update(item["path"] for item in control["files"].values())
    for path in sorted(paths):
        # The retirement stub is private; its archived original is the only
        # readable legacy program, handled inside the recovery directory above.
        result["files"][path] = _history_file(
            Path(path), private=Path(path).name != "legacy-guard.py"
        )
    for path, expected in publication["files"].items():
        require(result["files"][path] == expected, "publication-file-changed")
    for control in publication["controls"].values():
        for expected in control["files"].values():
            require(
                result["files"][expected["path"]] == expected,
                "publication-control-changed",
            )
    close_history(result)
    return result


def close_history(history):
    """Fast-close recorded identities after all content reads and native probes."""
    files = dict(history["files"])
    for directory, recorded in history["directories"].items():
        path = Path(directory)
        require(
            path.resolve(strict=True) == path
            and list(observe.stable(path.lstat())) == recorded["identity"]
            and sorted(item.name for item in path.iterdir())
            == sorted(recorded["files"]),
            "history-directory-changed",
        )
        files.update(
            {str(path / name): item for name, item in recorded["files"].items()}
        )
    for name, recorded in files.items():
        path = Path(name)
        require(
            path.resolve(strict=True) == path
            and list(observe.stable(path.lstat())) == recorded["identity"],
            "history-file-changed",
        )


def _source_check(request, profile, observed, trusted):
    require(
        state.sha256(state.canonical(observed)) == trusted
        and observed["source"] == request["source"]
        and observed["quiesced"] is True
        and observed["guest"]["status"] == "stopped"
        and state.canonical(observed["guest"]["config"])
        == state.canonical(profile["config"]),
        "stopped-source-changed",
    )


def prepare(
    reconciliation_raw,
    reconciliation_sha256,
    completion_sha256,
    source_sha256,
    image_profile,
):
    frozen = reconcile.decode_prepared(reconciliation_raw, reconciliation_sha256)
    state.digest(completion_sha256)
    state.digest(source_sha256)
    request, profile = copy.deepcopy(frozen["source_request"]), copy.deepcopy(
        image_profile
    )
    runtime.load_profile(request, profile)
    unused(request)
    accepted = reconcile.status(reconciliation_raw, reconciliation_sha256)
    require(
        accepted["prepared_sha256"] == reconciliation_sha256
        and accepted["completion_sha256"] == completion_sha256
        and accepted["source_request"] == request
        and accepted["phase"] == "owner-reconciled-starts-denied"
        and all(
            accepted[key] is True
            for key in (
                "owner_reconciliation_verified",
                "owner_publication_verified",
                "legacy_source_refused",
            )
        )
        and all(accepted[key] is False for key in reconcile.original.FLAGS),
        "reconciliation-unqualified",
    )
    _source_check(request, profile, accepted["source_observed"], source_sha256)
    guard = observe.load_guard(request["reference_guard"])
    policy = request["policy"]
    with pair_lock.locked_pair(policy["datasets"]), ExitStack() as held:
        for vmid in sorted((policy["vmid"], policy["retired_guest"]["vmid"])):
            held.enter_context(config_lock.read_guest(vmid))
        unused(request)
        with observe.source_state(request, require_stopped=True) as source:
            _source_check(request, profile, source, source_sha256)
            current = reconcile.current_files(frozen, guard)
            require(current == accepted["publication"], "publication-changed")
            before = history_seal(frozen, current)
            require(
                root_identity(profile) == profile["rootfs"]["identity"], "root-changed"
            )
            stopped = copy.deepcopy(source)
        # The stopped application context must finish before the controller can
        # take its direct EX across a future native start.
        require(
            reconcile.phase_journal(
                frozen,
                reconciliation_sha256,
                guard,
                current,
                reconcile.claim_path(frozen["parent_prepared"]),
            )
            == accepted["phase_journal_sha256"],
            "reconciliation-history-changed",
        )
        require(
            history_seal(frozen, current) == before
            and root_identity(profile) == profile["rootfs"]["identity"],
            "closing-history-changed",
        )
        unused(request)
        close_history(before)
    return {
        "document_type": PREPARED,
        "schema_version": 1,
        "reconciliation_prepared": frozen,
        "reconciliation_sha256": reconciliation_sha256,
        "completion_sha256": completion_sha256,
        "source_sha256": source_sha256,
        "source_request": request,
        "image_profile": profile,
        "source_before": stopped,
        "publication": current,
        "history": before,
    }


def decode_prepared(raw, trusted):
    state.digest(trusted)
    require(
        type(raw) is bytes and 0 < len(raw) <= 8388608 and state.sha256(raw) == trusted,
        "prepared-changed",
    )
    value = observe.decode(raw)
    state.keys(
        value,
        {
            "document_type",
            "schema_version",
            "reconciliation_prepared",
            "reconciliation_sha256",
            "completion_sha256",
            "source_sha256",
            "source_request",
            "image_profile",
            "source_before",
            "publication",
            "history",
        },
    )
    require(
        raw == state.canonical(value)
        and value["document_type"] == PREPARED
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1,
        "prepared-version",
    )
    parent = reconcile.decode_prepared(
        state.canonical(value["reconciliation_prepared"]),
        value["reconciliation_sha256"],
    )
    require(value["source_request"] == parent["source_request"], "prepared-parent")
    state.digest(value["completion_sha256"])
    state.digest(value["source_sha256"])
    runtime.load_profile(value["source_request"], value["image_profile"])
    _source_check(
        value["source_request"],
        value["image_profile"],
        value["source_before"],
        value["source_sha256"],
    )
    return value


def create_claim(prepared, trusted):
    request = prepared["source_request"]
    unused(request)
    backup.private_directory(RUNTIME_ROOT.parent)
    try:
        RUNTIME_ROOT.mkdir(mode=0o700)
    except FileExistsError:
        backup.private_directory(RUNTIME_ROOT)
    else:
        backup.write_private(RUNTIME_ROOT / "profile.json", PROFILE)
        backup.sync_directory(RUNTIME_ROOT.parent)
    unused(request)
    directory = claim_path(request)
    directory.mkdir(mode=0o700)
    backup.sync_directory(RUNTIME_ROOT)
    backup.write_private(
        directory / "intent.json", {"prepared": prepared, "prepared_sha256": trusted}
    )
    backup.write_private(
        directory / "write-possible.json", {"pair_key": directory.name}
    )
    return directory


def own_runtime():
    backup.private_directory(RUNTIME_ROOT)
    profile = _history_file(RUNTIME_ROOT / "profile.json")
    require(
        profile["sha256"] == state.sha256(state.canonical(PROFILE)), "runtime-profile"
    )
    return {
        "directory": list(observe.stable(RUNTIME_ROOT.lstat()))[:5],
        "file": profile,
    }


def close_own_runtime(expected):
    require(
        RUNTIME_ROOT.resolve(strict=True) == RUNTIME_ROOT
        and list(observe.stable(RUNTIME_ROOT.lstat()))[:5] == expected["directory"]
        and list(observe.stable((RUNTIME_ROOT / "profile.json").lstat()))
        == expected["file"]["identity"],
        "runtime-profile-changed",
    )


def after_denials(prepared):
    """Project only the two claimed target-denial removals, retaining all else."""
    request = prepared["source_request"]
    publication, expected = copy.deepcopy(prepared["publication"]), copy.deepcopy(
        prepared["history"]
    )
    attach = reconcile.original.attach
    for unit in runtime.reference_units(request):
        item = publication["controls"][unit]["files"].pop(attach.DENIAL_NAME)
        path = attach.UNIT_ROOT / (unit + ".d") / attach.DENIAL_NAME
        require(item["path"] == str(path), "denial-path")
        require(expected["files"].pop(str(path)) == item, "denial-history")
    return publication, expected


def close_retained_history(prepared):
    publication, expected = after_denials(prepared)
    actual = history_seal(prepared["reconciliation_prepared"], publication)
    require(actual == expected, "retained-history-changed")
    close_history(expected)


def remove_denials(prepared, directory):
    request = prepared["source_request"]
    attach = reconcile.original.attach
    for index, unit in enumerate(runtime.reference_units(request)):
        expected = prepared["publication"]["controls"][unit]["files"][
            attach.DENIAL_NAME
        ]
        path = attach.UNIT_ROOT / (unit + ".d") / attach.DENIAL_NAME
        require(
            expected["path"] == str(path) and _history_file(path) == expected,
            "denial-changed",
        )
        raw, _ = observe.read_regular(path, 4096)
        require(raw == attach.DENIAL, "denial-bytes")
        archive = directory / f"target-denial-{index}.conf"
        # Copy/fsync before unlink also works when /etc and /var differ in backing.
        reconcile.original.write_raw(archive, raw)
        archived = _history_file(archive)
        require(archived["sha256"] == expected["sha256"], "denial-archive")
        backup.write_private(
            directory / f"target-{index}-dispatch.json",
            {"previous": expected, "archive": archived},
        )
        require(_history_file(path) == expected, "denial-changed")
        path.unlink()
        backup.sync_directory(path.parent)
        backup.write_private(
            directory / f"target-{index}-result.json",
            {"removed": str(path), "archive": archived},
        )
    reconcile.original.reload_units()


def declaration(prepared):
    request = prepared["source_request"]
    attach = reconcile.original.attach
    for unit in runtime.reference_units(request):
        path = attach.UNIT_ROOT / (unit + ".d") / "50-cmdmesh-reference.conf"
        require(
            sorted(item.name for item in path.parent.iterdir()) == [path.name],
            "unit-membership",
        )
        require(
            _history_file(path)
            == prepared["publication"]["controls"][unit]["files"][path.name],
            "reference-changed",
        )
        fields = reconcile.original.unit_state(unit)
        require(
            fields["LoadState"] == "loaded"
            and fields["ActiveState"] in {"inactive", "failed"}
            and fields["MainPID"] == "0"
            and fields["DropInPaths"] == [str(path)],
            "unit-declaration",
        )
        values = fields["commands"]
        require(type(values) is list and len(values) == 1, "unit-declaration")
        command = values[0]
        require(
            command["path"] == runtime.reference_argv(request)[0]
            and command["argv"] == runtime.reference_argv(request)
            and command["ignore_errors"] is False,
            "unit-declaration",
        )


def _start(binding, directory, timeout_seconds):
    clock = int(time.time())
    backup.write_private(
        directory / "dispatch.json",
        {"clock": clock, "vmid": binding.vmid, "action": "start"},
    )
    acknowledgement = api.post_guest_action(binding, "start")
    state.keys(acknowledgement, {"upid", "tls_verified"})
    require(acknowledgement["tls_verified"] is True, "unverified-acknowledgement")
    identity = api.parse_upid(binding, acknowledgement["upid"])
    require(clock - 2 <= identity["starttime"] <= clock + 60, "task-clock")
    backup.write_private(directory / "acknowledgement.json", acknowledgement)
    deadline = time.monotonic() + timeout_seconds
    while True:
        task, log = api.task_state(binding, acknowledgement["upid"])
        outcome = api.native_outcome(task, log)
        if task["status"] == "stopped":
            backup.write_private(
                directory / "task.json",
                {"task": task, "log": log, "native_outcome": outcome},
            )
            require(outcome["accepted"] is True, "native-task-unqualified")
            return clock, task, log, outcome
        require(time.monotonic() < deadline, "native-task-timeout")
        time.sleep(min(1, max(0, deadline - time.monotonic())))


def journal_snapshot(directory, *, complete=False):
    names = {
        "intent.json",
        "write-possible.json",
        "guard-dispatch.json",
        "guard-result.json",
        "target-0-dispatch.json",
        "target-0-result.json",
        "target-1-dispatch.json",
        "target-1-result.json",
        "target-denial-0.conf",
        "target-denial-1.conf",
        "dispatch.json",
        "acknowledgement.json",
        "task.json",
    }
    expected = names | ({"complete.json"} if complete else set())
    require(
        {path.name for path in directory.iterdir()} == expected, "journal-membership"
    )
    values = {name: _history_file(directory / name) for name in sorted(names)}
    close_journal(directory, values, complete=complete)
    return values


def close_journal(directory, values, *, complete=False):
    require(
        {path.name for path in directory.iterdir()}
        == set(values) | ({"complete.json"} if complete else set()),
        "journal-membership",
    )
    for name, value in values.items():
        require(
            list(observe.stable((directory / name).lstat())) == value["identity"],
            "journal-changed",
        )


def boot(raw, trusted, *, timeout_seconds=240):
    prepared = decode_prepared(raw, trusted)
    state.integer(timeout_seconds, 1, 600)
    request, profile = prepared["source_request"], prepared["image_profile"]
    unused(request)
    require(
        state.canonical(
            prepare(
                state.canonical(prepared["reconciliation_prepared"]),
                prepared["reconciliation_sha256"],
                prepared["completion_sha256"],
                prepared["source_sha256"],
                profile,
            )
        )
        == raw,
        "preflight-changed",
    )
    guard, _, binding = runtime.load_profile(request, profile)
    guard = observe.load_guard(request["reference_guard"])
    native_binding = api.GuestBinding.from_source(request["source"])
    policy = request["policy"]
    directory = None
    try:
        with pair_lock.locked_pair(policy["datasets"]), config_lock.read_guest(
            policy["retired_guest"]["vmid"]
        ), ExitStack() as target:
            target.enter_context(config_lock.read_guest(policy["vmid"]))
            unused(request)
            with observe.source_state(request, require_stopped=True) as source:
                _source_check(request, profile, source, prepared["source_sha256"])
                require(
                    history_seal(
                        prepared["reconciliation_prepared"], prepared["publication"]
                    )
                    == prepared["history"],
                    "history-changed",
                )
            config = (
                Path(policy["datasets"]["config"]["mountpoint"]) / "application.json"
            )
            uid, gid = (
                policy["mapping"]["offset"] + policy["mapping"][name]
                for name in ("uid", "gid")
            )
            with observe.locked_config(config, uid, gid) as app_raw:
                require(
                    state.sha256(app_raw) == policy["application"]["config_sha256"],
                    "configuration-changed",
                )
                require(
                    root_identity(profile) == profile["rootfs"]["identity"],
                    "root-changed",
                )
                close_history(prepared["history"])
                directory = create_claim(prepared, trusted)
                own = own_runtime()
                argv = runtime.reference_argv(request)
                backup.write_private(directory / "guard-dispatch.json", {"argv": argv})
                command = reconcile.execute_guard(argv)
                backup.write_private(directory / "guard-result.json", command)
                reconcile.require_qualified(command)
                remove_denials(prepared, directory)
                declaration(prepared)
                close_retained_history(prepared)
                # All nested target leases, including stopped Source3, are now
                # closed. Keep retired SH, pair EX and application EX throughout.
                target.close()
                config_lock.require_write_available(policy["vmid"])
                clock, task, log, outcome = _start(
                    native_binding, directory, timeout_seconds
                )
                target.enter_context(config_lock.read_guest(policy["vmid"]))
                close_retained_history(prepared)
                journal_files = journal_snapshot(directory)
                journal = state.sha256(state.canonical(journal_files))
                observed = runtime._collect_leased(
                    request,
                    profile,
                    guard,
                    binding,
                    prepared["source_before"]["host"],
                    app_raw,
                )
                require(
                    observed["application"] == prepared["source_before"]["application"],
                    "application-changed",
                )
                execution.require_success(
                    observed["reference"]["units"][runtime.reference_units(request)[0]][
                        "commands"
                    ],
                    argv,
                    clock,
                    int(time.time()),
                )
                close_history(after_denials(prepared)[1])
                close_journal(directory, journal_files)
                result = {
                    "prepared_sha256": trusted,
                    "phase": "retained-os-quiesced",
                    "runtime": observed,
                    "task": task,
                    "log": log,
                    "native_outcome": outcome,
                    "journal_files": journal_files,
                    "phase_journal_sha256": journal,
                    "mutation_attempted": True,
                    "boot_verified": True,
                    "application_quiesced": True,
                    "rebuild_verified": False,
                    "restore_verified": False,
                    "backup_verified": False,
                }
                checksum = backup.write_private(directory / "complete.json", result)
                completion_file = _history_file(directory / "complete.json")
                require(completion_file["sha256"] == checksum, "completion-changed")
                closing = runtime._collect_leased(
                    request,
                    profile,
                    guard,
                    binding,
                    prepared["source_before"]["host"],
                    app_raw,
                )
                require(
                    closing["guest"]["runtime"]["uptime"]
                    >= observed["guest"]["runtime"]["uptime"],
                    "runtime-changed",
                )
                _same(
                    _runtime_identity(closing),
                    _runtime_identity(observed),
                    "runtime-changed",
                )
                close_journal(directory, journal_files, complete=True)
                close_history(after_denials(prepared)[1])
                close_history(
                    {
                        "directories": {},
                        "files": {completion_file["path"]: completion_file},
                    }
                )
                close_own_runtime(own)
        return {**result, "completion_sha256": checksum}
    except BaseException as error:
        if directory is not None:
            try:
                backup.write_private(
                    directory / "failed.json",
                    {
                        "error_code": getattr(
                            error, "code", "persistence-retained-boot-interrupted"
                        )
                    },
                )
            except OSError:
                pass
        raise


def _same(actual, expected, code):
    require(state.canonical(actual) == state.canonical(expected), code)


def _journal_contract(prepared, trusted, directory, binding):
    def record(name):
        value, raw = backup.read_private(directory / name)
        require(raw == state.canonical(value), "journal-canonical")
        return value

    _same(
        record("intent.json"),
        {"prepared": prepared, "prepared_sha256": trusted},
        "journal-intent",
    )
    _same(record("write-possible.json"), {"pair_key": directory.name}, "journal-intent")
    request = prepared["source_request"]
    _same(
        record("guard-dispatch.json"),
        {"argv": runtime.reference_argv(request)},
        "journal-guard",
    )
    reconcile.require_qualified(record("guard-result.json"))
    for index, unit in enumerate(runtime.reference_units(request)):
        expected = prepared["publication"]["controls"][unit]["files"][
            reconcile.original.attach.DENIAL_NAME
        ]
        archive = _history_file(directory / f"target-denial-{index}.conf")
        require(archive["sha256"] == expected["sha256"], "journal-archive")
        _same(
            record(f"target-{index}-dispatch.json"),
            {"previous": expected, "archive": archive},
            "journal-denial",
        )
        _same(
            record(f"target-{index}-result.json"),
            {"removed": expected["path"], "archive": archive},
            "journal-denial",
        )
    dispatch = record("dispatch.json")
    state.keys(dispatch, {"clock", "vmid", "action"})
    state.integer(dispatch["clock"], 1, 2**63 - 1)
    _same(
        dispatch,
        {"clock": dispatch["clock"], "vmid": binding.vmid, "action": "start"},
        "journal-dispatch",
    )
    ack = record("acknowledgement.json")
    state.keys(ack, {"upid", "tls_verified"})
    require(ack["tls_verified"] is True, "unverified-acknowledgement")
    task = api.parse_upid(binding, ack["upid"])
    require(
        dispatch["clock"] - 2 <= task["starttime"] <= dispatch["clock"] + 60,
        "task-clock",
    )
    return dispatch["clock"], ack, record("task.json")


def _runtime_identity(value):
    result = copy.deepcopy(value)
    result["guest"]["runtime"].pop("uptime")
    return result


def status(raw, trusted):
    """Requalify a completed OS start without any stopped observer or mutation."""
    prepared = decode_prepared(raw, trusted)
    request, profile = prepared["source_request"], prepared["image_profile"]
    own = own_runtime()
    directory = claim_path(request)
    backup.private_directory(directory)
    require(not os.path.lexists(directory / "failed.json"), "failed-or-uncertain")
    completed, completed_raw = backup.read_private(directory / "complete.json")
    state.keys(
        completed,
        {
            "prepared_sha256",
            "phase",
            "runtime",
            "task",
            "log",
            "native_outcome",
            "journal_files",
            "phase_journal_sha256",
            "mutation_attempted",
            "boot_verified",
            "application_quiesced",
            "rebuild_verified",
            "restore_verified",
            "backup_verified",
        },
    )
    require(
        completed_raw == state.canonical(completed)
        and completed["prepared_sha256"] == trusted
        and completed["phase"] == "retained-os-quiesced"
        and completed["mutation_attempted"] is True
        and completed["boot_verified"] is True
        and completed["application_quiesced"] is True
        and all(
            completed[key] is False
            for key in ("rebuild_verified", "restore_verified", "backup_verified")
        ),
        "completion-unqualified",
    )
    state.digest(completed["phase_journal_sha256"])
    runtime.validate(request, profile, "os_quiesced", completed["runtime"])
    guard, _, binding = runtime.load_profile(request, profile)
    guard = observe.load_guard(request["reference_guard"])
    native_binding = api.GuestBinding.from_source(request["source"])
    policy = request["policy"]
    with pair_lock.locked_pair(policy["datasets"]), ExitStack() as held:
        for vmid in sorted((policy["vmid"], policy["retired_guest"]["vmid"])):
            held.enter_context(config_lock.read_guest(vmid))
        runtime.validate_running_guest(request, profile, observe.guest_facts(policy))
        clock, ack, recorded_task = _journal_contract(
            prepared, trusted, directory, native_binding
        )
        task, log = api.task_state(native_binding, ack["upid"])
        outcome = api.native_outcome(task, log)
        require(
            task["status"] == "stopped" and outcome["accepted"] is True,
            "native-task-unqualified",
        )
        _same(
            recorded_task,
            {"task": task, "log": log, "native_outcome": outcome},
            "task-changed",
        )
        _same(
            {key: completed[key] for key in ("task", "log", "native_outcome")},
            recorded_task,
            "completion-task",
        )
        close_retained_history(prepared)
        journal_files = journal_snapshot(directory, complete=True)
        _same(journal_files, completed["journal_files"], "journal-descriptor-changed")
        require(
            state.sha256(state.canonical(journal_files))
            == completed["phase_journal_sha256"],
            "journal-changed",
        )
        completion_file = _history_file(directory / "complete.json")
        require(
            completion_file["sha256"] == state.sha256(completed_raw),
            "completion-changed",
        )
        config = Path(policy["datasets"]["config"]["mountpoint"]) / "application.json"
        uid, gid = (
            policy["mapping"]["offset"] + policy["mapping"][name]
            for name in ("uid", "gid")
        )
        with observe.locked_config(config, uid, gid) as app_raw:
            observed = runtime._collect_leased(
                request,
                profile,
                guard,
                binding,
                prepared["source_before"]["host"],
                app_raw,
            )
            require(
                observed["application"] == prepared["source_before"]["application"],
                "application-changed",
            )
            require(
                observed["guest"]["runtime"]["uptime"]
                >= completed["runtime"]["guest"]["runtime"]["uptime"],
                "runtime-changed",
            )
            _same(
                _runtime_identity(observed),
                _runtime_identity(completed["runtime"]),
                "runtime-changed",
            )
            execution.require_success(
                observed["reference"]["units"][runtime.reference_units(request)[0]][
                    "commands"
                ],
                runtime.reference_argv(request),
                clock,
                int(time.time()),
            )
            close_journal(directory, journal_files, complete=True)
            close_history(after_denials(prepared)[1])
            close_history(
                {"directories": {}, "files": {completion_file["path"]: completion_file}}
            )
            close_own_runtime(own)
    return {
        **completed,
        "runtime": observed,
        "mutation_attempted": False,
        "completion_sha256": state.sha256(completed_raw),
    }
