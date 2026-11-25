"""One claimed start/write/read-back/stop test of the retained application.

The lifecycle caller must authorize this mutation. A consumed GUID-pair claim is
never retried. Containment preserves an unknown write rather than erasing it.
"""

from contextlib import contextmanager, ExitStack
import copy
import errno
from dataclasses import asdict
import os
import re
import stat
import time

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_ledger_api as ledger,
    persistence_state as state,
    persistence_writer_runtime as active,
    persistence_writer_trial as trial,
)

runtime, backup, boot = trial.runtime, trial.backup, trial.boot
NAMES = frozenset(
    {
        "intent.json",
        "write-possible.json",
        "start-dispatch.json",
        "start-result.json",
        "before-read.json",
        "append-dispatch.json",
        "append-result.json",
        "after-read.json",
        "stop-admission.json",
        "stop-dispatch.json",
        "stop-result.json",
        "quiesced.json",
    }
)


def require(value, code):
    state.require(value, "persistence-writer-execution-" + code)


def same(left, right, code):
    require(state.canonical(left) == state.canonical(right), code)


def _own():
    backup.private_directory(trial.RUNTIME_ROOT)
    file = boot._history_file(trial.RUNTIME_ROOT / "profile.json")
    require(
        file["sha256"] == state.sha256(state.canonical(trial.PROFILE)),
        "runtime-profile",
    )
    return {
        "directory": list(runtime.observe.stable(trial.RUNTIME_ROOT.lstat()))[:5],
        "file": file,
    }


def _close_own(expected):
    same(_own(), expected, "runtime-profile-changed")


def _record(directory, name, value):
    require(state.matches(r"[a-z][a-z0-9-]*\.json", name), "journal-name")
    backup.private_directory(directory)
    return backup.write_private(directory / name, value)


def _claim(prepared, trusted):
    request = prepared["source_request"]
    trial.unused(request)
    try:
        trial.RUNTIME_ROOT.mkdir(mode=0o700)
    except FileExistsError:
        backup.private_directory(trial.RUNTIME_ROOT)
    else:
        backup.write_private(trial.RUNTIME_ROOT / "profile.json", trial.PROFILE)
        backup.sync_directory(trial.RUNTIME_ROOT.parent)
    trial.unused(request)
    directory = trial.claim_path(request)
    directory.mkdir(mode=0o700)
    backup.sync_directory(trial.RUNTIME_ROOT)
    _record(
        directory,
        "intent.json",
        {
            "prepared_sha256": trusted,
            "source": request["source"],
            "nonce": prepared["nonce"],
        },
    )
    _record(directory, "write-possible.json", {"mutation_attempted": True})
    return directory


def _close_parent(prepared):
    journal = prepared["boot_completion"]["journal_files"]
    history, own = trial._history(
        prepared["boot_prepared"], prepared["boot_completion_sha256"], journal
    )
    same(
        (history, own),
        (prepared["history"], prepared["boot_runtime"]),
        "parent-history-changed",
    )


@contextmanager
def _quiesced(prepared, guard, binding):
    """Admit current host/API/kernel before reading configuration bytes."""
    request, profile = prepared["source_request"], prepared["image_profile"]
    host = prepared["runtime_identity"]["host"]
    same(runtime.observe.host_facts(request), host, "quiesced-host")
    runtime.validate_running_guest(
        request, profile, runtime.observe.guest_facts(request["policy"])
    )
    same(
        runtime.kernel.collect(binding),
        prepared["runtime_identity"]["kernel"],
        "quiesced-kernel",
    )
    with trial._quiesced(request, profile, guard, binding, host) as observed:
        yield observed


def _fast_close(prepared, directory, journal, completion, own, claim_identity):
    """Only stat/membership checks after the final actual SQL/runtime worker."""
    boot.close_history(prepared["history"])
    boot.close_own_runtime(prepared["boot_runtime"])
    backup.private_directory(directory)
    same(
        list(runtime.observe.stable(directory.lstat()))[:5],
        claim_identity,
        "claim-directory-changed",
    )
    require(
        trial.RUNTIME_ROOT.resolve(strict=True) == trial.RUNTIME_ROOT
        and list(runtime.observe.stable(trial.RUNTIME_ROOT.lstat()))[:5]
        == own["directory"],
        "runtime-directory-changed",
    )
    files = {item["path"]: item for item in journal.values()}
    files[completion["path"]] = completion
    files[own["file"]["path"]] = own["file"]
    boot.close_history({"directories": {}, "files": files})
    require(
        {path.name for path in directory.iterdir()} == NAMES | {"complete.json"},
        "journal-membership",
    )


def _base_compatible(prepared, frame):
    before = prepared["runtime_identity"]
    same(frame["host"], before["host"], "host-changed")
    same(frame["kernel"], before["kernel"], "kernel-changed")
    guest = copy.deepcopy(frame["guest"])
    uptime = guest["runtime"].pop("uptime")
    state.integer(uptime, prepared["uptime_floor"], 2**63 - 1)
    same(guest, before["guest"], "guest-changed")
    same(frame["reference"], before["reference"], "references-changed")
    same(frame["ownership"], before["retained"]["ownership"], "owner-changed")
    same(frame["bindings"], before["bindings"], "binds-changed")
    helper = runtime.load_profile(
        prepared["source_request"], prepared["image_profile"]
    )[1]
    runtime.validate_image(
        prepared["image_profile"],
        helper,
        frame["image"],
        frame["kernel"],
        writer_pid=active.process.main_pid(frame["image"]),
    )


def _service_snapshot(prepared):
    """Admit a known active service without socket readiness or authentication."""
    request, profile = prepared["source_request"], prepared["image_profile"]
    guard, image, binding = runtime.load_profile(request, profile)
    host = prepared["runtime_identity"]["host"]
    frame = active._base_frame(request, profile, guard, binding, host)
    _base_compatible(prepared, frame)
    init = active.unix_peer.process_identity(frame["kernel"]["init"]["pid"])
    peer = active._find_peer(
        init.pid_namespace, active.process.main_pid(frame["image"])
    )
    offset = request["policy"]["mapping"]["offset"]
    with ExitStack() as opened:
        root = os.open(
            active.PROC_ROOT / str(init.pid) / "root",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        opened.callback(os.close, root)
        info = os.fstat(root)
        require(
            (info.st_dev, info.st_ino) == init.root
            and (info.st_uid, info.st_gid) == (offset, offset)
            and stat.S_IMODE(info.st_mode) == 0o755,
            "service-root",
        )
        python = active._python(opened, root, (offset, offset))
        active.process.validate(
            request, profile, frame["kernel"], frame["image"], init, peer, python
        )
        active._program(opened, root, (offset, offset), image.PROGRAM_SHA256)
        require(
            active.unix_peer.process_identity(init.pid) == init
            and active.unix_peer.process_identity(peer.pid) == peer,
            "service-process-changed",
        )
    frame["peer"] = asdict(peer)
    return frame


def _service(prepared, action, expected_peer=None):
    require(action in {"start", "stop"}, "service-action")
    request, profile = prepared["source_request"], prepared["image_profile"]
    guard, image, binding = runtime.load_profile(request, profile)
    host = prepared["runtime_identity"]["host"]
    same(runtime.observe.host_facts(request), host, "service-host")
    guest = runtime.observe.guest_facts(request["policy"])
    runtime.validate_running_guest(request, profile, guest)
    kernel = runtime.kernel.collect(binding)
    same(kernel, prepared["runtime_identity"]["kernel"], "service-kernel")
    if action == "stop":
        current = _service_snapshot(prepared)
        if expected_peer is not None:
            same(current["peer"], expected_peer, "service-replaced")
    else:
        facts = runtime.guest_image(request, profile)
        runtime.validate_image(profile, image, facts, kernel)
    raw = runtime.observe.native(
        [
            "/usr/sbin/pct",
            "exec",
            str(request["policy"]["vmid"]),
            "--",
            "/usr/bin/systemctl",
            action,
            "reference-ledger.service",
        ]
    )
    require(raw == b"", "service-output")
    return {"exit_code": 0, "stdout_sha256": state.sha256(raw), "stderr_bytes": 0}


def _read(client, instance):
    value = client.read()
    state.keys(value, {"instance_id", "entries", "records_sha256", "record_count"})
    checked = ledger.validate_read(
        {
            "outcome": "read",
            "instance_id": value["instance_id"],
            "entries": value["entries"],
        },
        instance,
    )
    same(value, checked, "api-read-unqualified")
    return value


def _summary(value):
    return {
        key: value[key] for key in ("instance_id", "records_sha256", "record_count")
    }


@contextmanager
def _ready_session(request, profile, guard, binding, host, timeout_seconds=240):
    """Retry only missing-socket admission, never a start or an API request."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        opened = ExitStack()
        try:
            client = opened.enter_context(
                active._session_leased(request, profile, guard, binding, host)
            )
        except FileNotFoundError as error:
            opened.close()
            if error.errno != errno.ENOENT or error.filename != "api.sock":
                raise
            remaining = deadline - time.monotonic()
            require(remaining > 0, "socket-readiness-timeout")
            time.sleep(min(0.1, remaining))
            continue
        except BaseException:
            opened.close()
            raise
        with opened:
            require(time.monotonic() <= deadline, "socket-readiness-timeout")
            yield client
        return


def _stop_once(prepared, directory, peer=None):
    require(
        not os.path.lexists(directory / "stop-dispatch.json"), "stop-already-dispatched"
    )
    frame = _service_snapshot(prepared)
    _base_compatible(prepared, frame)
    if peer is not None:
        same(frame["peer"], peer, "stop-peer-changed")
    _record(directory, "stop-admission.json", frame)
    _record(directory, "stop-dispatch.json", {"action": "stop", "peer": frame["peer"]})
    result = _service(prepared, "stop", expected_peer=frame["peer"])
    _record(directory, "stop-result.json", result)
    return result


def _code(error):
    value = getattr(error, "code", None)
    return (
        value
        if type(value) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,120}", value)
        else "persistence-writer-trial-refused"
    )


def _contain(prepared, directory, guard, binding, peer):
    if not os.path.lexists(directory / "start-dispatch.json"):
        return {"outcome": "start-not-dispatched"}
    if os.path.lexists(directory / "stop-dispatch.json"):
        return {"outcome": "stop-already-dispatched"}
    try:
        _stop_once(prepared, directory, peer)
        outcome = "contained-stop"
    except Exception as error:
        outcome = "stop-refused-or-unknown"
        if os.path.lexists(directory / "stop-dispatch.json"):
            return {"outcome": outcome, "error_code": _code(error)}
    try:
        with _quiesced(prepared, guard, binding) as observed:
            application = copy.deepcopy(observed["application"])
        return {
            "outcome": (
                "already-quiesced" if outcome == "stop-refused-or-unknown" else outcome
            ),
            "application_quiesced": True,
            "application": application,
        }
    except Exception as error:
        return {
            "outcome": outcome,
            "application_quiesced": False,
            "error_code": _code(error),
        }


def _journal(directory, complete=False):
    backup.private_directory(directory)
    require(
        {path.name for path in directory.iterdir()}
        == NAMES | ({"complete.json"} if complete else set()),
        "journal-membership",
    )
    values = {name: boot._history_file(directory / name) for name in sorted(NAMES)}
    boot.close_history(
        {"directories": {}, "files": {item["path"]: item for item in values.values()}}
    )
    require(
        {path.name for path in directory.iterdir()}
        == NAMES | ({"complete.json"} if complete else set()),
        "journal-membership",
    )
    return values


def _ack(value):
    state.keys(value, {"exit_code", "stdout_sha256", "stderr_bytes"})
    require(
        type(value["exit_code"]) is int
        and value["exit_code"] == 0
        and type(value["stderr_bytes"]) is int
        and value["stderr_bytes"] == 0
        and value["stdout_sha256"] == state.sha256(b""),
        "service-result",
    )


def _journal_contract(
    prepared, trusted, directory, before, after, appended, observed, peer
):
    records = {}
    for name in NAMES:
        value, raw = backup.read_private(directory / name)
        require(raw == state.canonical(value), "journal-canonical")
        records[name] = value
    same(
        records["intent.json"],
        {
            "prepared_sha256": trusted,
            "source": prepared["source_request"]["source"],
            "nonce": prepared["nonce"],
        },
        "journal-intent",
    )
    same(
        records["write-possible.json"], {"mutation_attempted": True}, "journal-possible"
    )
    same(
        records["start-dispatch.json"],
        {"action": "start", "source": prepared["source_request"]["source"]},
        "journal-start",
    )
    _ack(records["start-result.json"])
    _ack(records["stop-result.json"])
    state.keys(
        before, {"instance_id", "records_sha256", "record_count", "last_sequence"}
    )
    state.integer(before["last_sequence"], 1, 2**63 - 2)
    previous = prepared["runtime_identity"]["application"]
    same(
        {key: before[key] for key in ("instance_id", "records_sha256", "record_count")},
        {
            key: previous[key]
            for key in ("instance_id", "records_sha256", "record_count")
        },
        "journal-before",
    )
    same(records["before-read.json"], before, "journal-before")
    same(
        records["append-dispatch.json"],
        {
            "operation_id": prepared["nonce"],
            "value_sha256": state.sha256(trial.payload(prepared["nonce"]).encode()),
            "sequence": before["last_sequence"] + 1,
        },
        "journal-append",
    )
    same(
        appended,
        {"outcome": "committed", "sequence": before["last_sequence"] + 1},
        "journal-commit",
    )
    same(records["append-result.json"], appended, "journal-commit")
    same(records["after-read.json"], after, "journal-after")
    _postcondition(prepared, observed, after)
    _base_compatible(prepared, records["stop-admission.json"])
    same(records["stop-admission.json"]["peer"], peer, "journal-stop-peer")
    same(
        records["stop-dispatch.json"], {"action": "stop", "peer": peer}, "journal-stop"
    )
    same(records["quiesced.json"], observed, "journal-quiesced")


def _postcondition(prepared, observed, after):
    before = copy.deepcopy(prepared["runtime_identity"])
    current = boot._runtime_identity(observed)
    actual, previous = current["application"], before["application"]
    require(
        actual["record_count"] == previous["record_count"] + 1
        and actual["records_sha256"] == after["records_sha256"]
        and actual["instance_id"] == after["instance_id"],
        "sql-readback",
    )
    for value in (before, current):
        for key in ("database_sha256", "records_sha256", "record_count"):
            value["application"].pop(key)
        value["retained"]["application"]["database"].pop("bytes")
    same(current, before, "post-runtime-changed")


def preflight(raw, trusted):
    """Repeat preparation and require unused ownership without creating a claim."""
    prepared = trial.decode_prepared(raw, trusted)
    request = prepared["source_request"]
    trial.unused(request)
    require(
        prepared["runtime_identity"]["application"]["record_count"] < 4096,
        "record-capacity",
    )
    fresh = trial.prepare(
        state.canonical(prepared["boot_prepared"]),
        prepared["boot_prepared_sha256"],
        prepared["boot_completion_sha256"],
        prepared["nonce"],
    )
    require(state.canonical(fresh) == raw, "prepared-state-changed")
    return prepared


def run(raw, trusted):
    prepared = preflight(raw, trusted)
    request, profile = prepared["source_request"], prepared["image_profile"]
    guard, unused, binding = runtime.load_profile(request, profile)
    guard = runtime.observe.load_guard(request["reference_guard"])
    host = prepared["runtime_identity"]["host"]
    policy = request["policy"]
    directory, peer = None, None
    with runtime.pair_lock.locked_pair(policy["datasets"]), ExitStack() as leased:
        for vmid in sorted((policy["vmid"], policy["retired_guest"]["vmid"])):
            leased.enter_context(runtime.config_lock.read_guest(vmid))
        try:
            trial.unused(request)
            with _quiesced(prepared, guard, binding) as before:
                same(
                    boot._runtime_identity(before),
                    prepared["runtime_identity"],
                    "before-state-changed",
                )
                _close_parent(prepared)
                directory = _claim(prepared, trusted)
                claim_identity = list(runtime.observe.stable(directory.lstat()))[:5]
                own = _own()
            _record(
                directory,
                "start-dispatch.json",
                {"action": "start", "source": request["source"]},
            )
            _record(directory, "start-result.json", _service(prepared, "start"))
            with _ready_session(request, profile, guard, binding, host) as client:
                original = _read(client, policy["application"]["instance_id"])
                _base_compatible(prepared, client.frame)
                peer = copy.deepcopy(client.frame["peer"])
                previous = prepared["runtime_identity"]["application"]
                require(
                    original["records_sha256"] == previous["records_sha256"]
                    and original["record_count"] == previous["record_count"]
                    and all(
                        row["operation_id"] != prepared["nonce"]
                        for row in original["entries"]
                    ),
                    "old-api-state-changed",
                )
                before_proof = {
                    **_summary(original),
                    "last_sequence": original["entries"][-1]["sequence"],
                }
                _record(directory, "before-read.json", before_proof)
                sequence = original["entries"][-1]["sequence"] + 1
                value = trial.payload(prepared["nonce"])
                _record(
                    directory,
                    "append-dispatch.json",
                    {
                        "operation_id": prepared["nonce"],
                        "value_sha256": state.sha256(value.encode()),
                        "sequence": sequence,
                    },
                )
                appended = client.append(prepared["nonce"], value)
                state.keys(appended, {"outcome", "sequence"})
                require(
                    appended["outcome"] == "committed"
                    and type(appended["sequence"]) is int
                    and appended["sequence"] == sequence,
                    "append-not-committed",
                )
                _record(directory, "append-result.json", appended)
                after = _read(client, policy["application"]["instance_id"])
                same(
                    after["entries"],
                    [
                        *original["entries"],
                        {
                            "sequence": sequence,
                            "operation_id": prepared["nonce"],
                            "value": value,
                        },
                    ],
                    "api-readback",
                )
                _base_compatible(prepared, client.frame)
                same(client.frame["peer"], peer, "api-peer-changed")
                _record(directory, "after-read.json", _summary(after))
            _stop_once(prepared, directory, peer)
            with _quiesced(prepared, guard, binding) as observed:
                _postcondition(prepared, observed, after)
                _close_parent(prepared)
                _record(directory, "quiesced.json", observed)
                journal = _journal(directory)
                result = {
                    "prepared_sha256": trusted,
                    "phase": "retained-application-rebuilt",
                    "runtime": observed,
                    "before": before_proof,
                    "after": _summary(after),
                    "peer": peer,
                    "append_result": appended,
                    "journal_files": journal,
                    "phase_journal_sha256": state.sha256(state.canonical(journal)),
                    "runtime_profile": own,
                    "claim_directory_identity": claim_identity,
                    "mutation_attempted": True,
                    "application_quiesced": True,
                    "application_write_verified": True,
                    "rebuild_verified": True,
                    "boot_verified": False,
                    "restore_verified": False,
                    "backup_verified": False,
                }
                _journal_contract(
                    prepared,
                    trusted,
                    directory,
                    result["before"],
                    result["after"],
                    appended,
                    observed,
                    peer,
                )
                same(_journal(directory), journal, "journal-changed")
                checksum = _record(directory, "complete.json", result)
                completion = boot._history_file(directory / "complete.json")
                require(completion["sha256"] == checksum, "completion-changed")
                same(_journal(directory, complete=True), journal, "journal-changed")
                _close_parent(prepared)
                _close_own(own)
            _fast_close(prepared, directory, journal, completion, own, claim_identity)
            return {**result, "completion_sha256": checksum}
        except BaseException as error:
            if directory is not None:
                try:
                    containment = _contain(prepared, directory, guard, binding, peer)
                    _record(directory, "containment.json", containment)
                    _record(
                        directory,
                        "failed.json",
                        {
                            "error_code": _code(error),
                            "containment": containment,
                            "rebuild_verified": False,
                            "application_write_verified": False,
                        },
                    )
                except BaseException:
                    pass
            raise


def status(raw, trusted, completion_sha256):
    """Verify the new app tuple and historical boot bytes, never old boot status."""
    state.digest(completion_sha256)
    prepared = trial.decode_prepared(raw, trusted)
    request, profile = prepared["source_request"], prepared["image_profile"]
    directory = trial.claim_path(request)
    require(
        not os.path.lexists(directory / "failed.json")
        and not os.path.lexists(directory / "containment.json"),
        "failed-or-uncertain",
    )
    completed, completed_raw = backup.read_private(directory / "complete.json")
    completion_file = boot._history_file(directory / "complete.json")
    require(
        state.sha256(completed_raw) == completion_sha256
        and completed_raw == state.canonical(completed)
        and completed["prepared_sha256"] == trusted
        and completed["phase"] == "retained-application-rebuilt"
        and all(
            completed[name] is True
            for name in (
                "application_quiesced",
                "application_write_verified",
                "rebuild_verified",
                "mutation_attempted",
            )
        )
        and all(
            completed[name] is False
            for name in ("boot_verified", "restore_verified", "backup_verified")
        ),
        "completion-unqualified",
    )
    require(completion_file["sha256"] == completion_sha256, "completion-changed")
    journal = _journal(directory, complete=True)
    state.require(
        type(completed["claim_directory_identity"]) is list
        and len(completed["claim_directory_identity"]) == 5
        and all(
            type(value) is int and value >= 0
            for value in completed["claim_directory_identity"]
        ),
        "persistence-writer-execution-claim-identity",
    )
    same(
        list(runtime.observe.stable(directory.lstat()))[:5],
        completed["claim_directory_identity"],
        "claim-directory-changed",
    )
    same(journal, completed["journal_files"], "journal-changed")
    require(
        state.sha256(state.canonical(journal)) == completed["phase_journal_sha256"],
        "journal-hash",
    )
    own = _own()
    same(own, completed["runtime_profile"], "runtime-profile-changed")
    guard, unused, binding = runtime.load_profile(request, profile)
    guard = runtime.observe.load_guard(request["reference_guard"])
    with runtime.pair_lock.locked_pair(
        request["policy"]["datasets"]
    ), ExitStack() as leased:
        for vmid in sorted(
            (request["policy"]["vmid"], request["policy"]["retired_guest"]["vmid"])
        ):
            leased.enter_context(runtime.config_lock.read_guest(vmid))
        with _quiesced(prepared, guard, binding) as observed:
            runtime.validate(request, profile, "os_quiesced", completed["runtime"])
            _postcondition(prepared, observed, completed["after"])
            same(
                boot._runtime_identity(observed),
                boot._runtime_identity(completed["runtime"]),
                "new-runtime-changed",
            )
            require(
                observed["guest"]["runtime"]["uptime"]
                >= completed["runtime"]["guest"]["runtime"]["uptime"],
                "uptime-decreased",
            )
            _close_parent(prepared)
            _journal_contract(
                prepared,
                trusted,
                directory,
                completed["before"],
                completed["after"],
                completed["append_result"],
                completed["runtime"],
                completed["peer"],
            )
            same(_journal(directory, complete=True), journal, "journal-changed")
            _close_own(own)
            _close_parent(prepared)
            _close_own(own)
            same(_journal(directory, complete=True), journal, "journal-changed")
        _fast_close(
            prepared,
            directory,
            journal,
            completion_file,
            own,
            completed["claim_directory_identity"],
        )
    return {
        **completed,
        "runtime": observed,
        "mutation_attempted": False,
        "completion_sha256": completion_sha256,
    }
