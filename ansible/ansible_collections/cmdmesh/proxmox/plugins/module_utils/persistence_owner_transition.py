"""Fixed same-owner OS transitions from accepted, quiesced application authority.

Internal SDK only. The checkpoint must already come from the external-hash-backed
codec. Target candidates never supply accepted predecessor authority. Ordinary
operations cannot continue a pending attempt or retry its native request.
"""

from contextlib import contextmanager, ExitStack
import copy
from dataclasses import asdict, dataclass
from pathlib import Path
import time

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_current as current,
    persistence_owner_journal as journal,
)

runtime, state, observe = current.runtime, current.state, current.observe
api, writer = journal.api, current.checkpoint_codec.writer
PREPARED = "cmdmesh.proxmox.owner-os-transition.prepared"


def require(value, code):
    state.require(value, "persistence-owner-transition-" + code)


def digest(value):
    return state.sha256(state.canonical(value))


def binding(checkpoint):
    request, _, _ = current._authority(checkpoint)
    return journal.Binding(
        state.pair_key(request["policy"]["datasets"]),
        digest(checkpoint),
        api.GuestBinding.from_source(request["source"]),
    )


def genesis_sha256(checkpoint):
    """Derive the proposed initial head without reading or initializing metadata."""
    return digest(journal._genesis(binding(checkpoint)))


def _history(checkpoint):
    """Read historical raw evidence without running an old current-state check."""
    prepared, completion = checkpoint["prepared"], checkpoint["completion"]
    writer._close_parent(prepared)
    directory = writer.trial.claim_path(prepared["source_request"])
    files = writer._journal(directory, complete=True)
    current.same(files, completion["journal_files"], "writer-history-changed")
    complete = writer.boot._history_file(directory / "complete.json")
    require(complete["sha256"] == checkpoint["completion_sha256"], "writer-completion")
    own = writer._own()
    current.same(own, completion["runtime_profile"], "writer-runtime-changed")
    result = {
        "directory": directory,
        "files": files,
        "complete": complete,
        "own": own,
        "identity": completion["claim_directory_identity"],
    }
    _close_history((checkpoint, result))
    return result


def _close_history(value):
    checkpoint, history = value
    writer._fast_close(
        checkpoint["prepared"],
        history["directory"],
        history["files"],
        history["complete"],
        history["own"],
        history["identity"],
    )


@dataclass
class _Scope:
    request: dict
    entry: dict
    raw: bytes
    target: ExitStack
    pending: journal.Pending | None = None
    outcome: str = "not-dispatched"


@contextmanager
def _leased(checkpoint, phase, prior_runtime):
    request, _, _ = current._authority(checkpoint)
    policy = request["policy"]
    scope = None
    with runtime.pair_lock.locked_pair(policy["datasets"]):
        try:
            with runtime.config_lock.read_guest(
                policy["retired_guest"]["vmid"]
            ), ExitStack() as target:
                target.enter_context(runtime.config_lock.read_guest(policy["vmid"]))
                entry = current._entry_leased(checkpoint, phase, prior_runtime)
                path = (
                    Path(policy["datasets"]["config"]["mountpoint"])
                    / "application.json"
                )
                uid, gid = (
                    policy["mapping"]["offset"] + policy["mapping"][key]
                    for key in ("uid", "gid")
                )
                with observe.locked_config(path, uid, gid) as raw:
                    scope = _Scope(request, entry, raw, target)
                    yield scope
        except BaseException:
            # Native leases have closed, but the same real pair EX is retained.
            # Failure reporting must not replace the original exception.
            if scope is not None and scope.pending is not None:
                try:
                    journal._fail(
                        scope.pending, "transition-unqualified", scope.outcome
                    )
                except Exception:
                    pass
            raise


def _entry_identity(entry):
    value = copy.deepcopy(entry)
    value["guest"] = runtime.stable_guest(value["guest"])
    return value


def _phase(kind):
    require(type(kind) is str and kind in {"shutdown", "resume"}, "kind")
    return "os_quiesced" if kind == "shutdown" else "stopped"


def _init_identity(evidence):
    if evidence["phase"] == "stopped":
        return None
    frame = evidence["observation"]
    return copy.deepcopy({"host": frame["host"], "init": frame["kernel"]["init"]})


def initialize(checkpoint, expected_head_sha256):
    """Explicit metadata-only initialization under current admission and leases."""
    require(expected_head_sha256 == genesis_sha256(checkpoint), "genesis")
    owner = binding(checkpoint)
    with _leased(checkpoint, "os_quiesced", None) as scope:
        history = _history(checkpoint)
        with current._current_leased(checkpoint, scope.entry, scope.raw):
            result = journal._initialize(owner)
            view = journal._inspect(owner, expected_head_sha256)
        _close_history((checkpoint, history))
        journal._close(view.seal)
    return result


def prepare(checkpoint, predecessor_sha256, kind, prior_runtime=None):
    """Observe one ready transition without creating metadata or dispatching work."""
    phase = _phase(kind)
    owner = binding(checkpoint)
    with _leased(checkpoint, phase, prior_runtime) as scope:
        history = _history(checkpoint)
        view = journal._inspect(owner, predecessor_sha256)
        require(view.head["state"] == "ready", "pending")
        store = observe.mount_facts(scope.request["backup_store"])
        with current._current_leased(
            checkpoint, scope.entry, scope.raw, prior_runtime
        ) as observed:
            result = {
                "document_type": PREPARED,
                "schema_version": 1,
                "checkpoint_sha256": digest(checkpoint),
                "predecessor_sha256": predecessor_sha256,
                "kind": kind,
                "entry": _entry_identity(scope.entry),
                "init_identity": _init_identity(observed),
                "uptime_floor": observed["observation"]["guest"]["runtime"]["uptime"],
                "backup_store": store,
                "prior_runtime": copy.deepcopy(prior_runtime),
            }
        _close_history((checkpoint, history))
        journal._close(view.seal)
    return result


def _decode(checkpoint, raw, trusted):
    state.digest(trusted)
    require(type(raw) is bytes and 0 < len(raw) <= 8388608, "payload")
    require(state.sha256(raw) == trusted, "hash")
    value = observe.decode(raw)
    state.keys(
        value,
        {
            "document_type",
            "schema_version",
            "checkpoint_sha256",
            "predecessor_sha256",
            "kind",
            "entry",
            "init_identity",
            "uptime_floor",
            "backup_store",
            "prior_runtime",
        },
    )
    require(
        state.canonical(value) == raw
        and value["document_type"] == PREPARED
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["checkpoint_sha256"] == digest(checkpoint),
        "preparation",
    )
    state.digest(value["predecessor_sha256"])
    state.integer(value["uptime_floor"], 0, 2**63 - 1)
    _phase(value["kind"])
    return value


def _poll(operation, timeout_seconds):
    kind = "vzshutdown" if operation.kind == "shutdown" else "vzstart"
    ack = operation.phases.records["ack.json"]["payload"]
    deadline = time.monotonic() + timeout_seconds
    while True:
        journal._close(operation.seal)
        task, log = api.task_state(operation.binding.guest, ack["upid"], kind=kind)
        require(time.monotonic() <= deadline, "native-task-timeout")
        outcome = api.native_outcome(task, log)
        if task["status"] == "stopped":
            return (
                journal._append_phase(
                    operation,
                    "terminal",
                    {
                        "task": task,
                        "log": log,
                        "native_outcome": outcome,
                    },
                ),
                outcome,
            )
        remaining = deadline - time.monotonic()
        require(remaining > 0, "native-task-timeout")
        time.sleep(min(1, remaining))


def _documents(owner, prepared, result):
    intent = journal._document(
        "intent",
        profile_sha256=digest(journal._profile(owner)),
        sequence=result["sequence"],
        predecessor_sha256=prepared["predecessor_sha256"],
        kind=prepared["kind"],
        prepared_sha256=result["prepared_sha256"],
    )
    completed = journal._document(
        "result",
        profile_sha256=digest(journal._profile(owner)),
        sequence=result["sequence"],
        intent_sha256=digest(intent),
        evidence={
            "before": result["before"],
            "entry": result["entry"],
            "after": result["current"],
        },
        phase_files=result["phase_files"],
        phase_chain_sha256=result["phase_chain_sha256"],
    )
    head = journal._head(
        owner,
        result["sequence"],
        "ready",
        prepared["predecessor_sha256"],
        digest(intent),
        digest(completed),
    )
    return {"intent.json": intent, "result.json": completed, "HEAD.json": head}


def _validate_evidence(checkpoint, prepared, evidence, dispatch):
    state.keys(evidence, {"before", "entry", "after"})
    before, entry, after = evidence["before"], evidence["entry"], evidence["after"]
    state.keys(
        entry, {"phase", "host", "guest", "reference", "root", "ownership", "stopped"}
    )
    phase = _phase(prepared["kind"])
    current.validate_current(checkpoint, phase, before)
    current.validate_current(
        checkpoint, "stopped" if phase == "os_quiesced" else "os_quiesced", after
    )
    current.same(_entry_identity(entry), prepared["entry"], "receipt-entry")
    current.same(_init_identity(before), prepared["init_identity"], "receipt-init")
    require(
        before["observation"]["guest"]["runtime"]["uptime"] >= prepared["uptime_floor"],
        "receipt-uptime",
    )
    current.same(before["observation"]["host"], entry["host"], "receipt-host")
    current.same(
        runtime.stable_guest(before["observation"]["guest"]),
        runtime.stable_guest(entry["guest"]),
        "receipt-guest",
    )
    current.same(
        dispatch["host_epoch"],
        {key: entry["host"][key] for key in ("boot_id", "mount_namespace")},
        "receipt-epoch",
    )
    require(dispatch["entry_sha256"] == digest(entry), "receipt-entry-hash")


def validate_result(checkpoint, prepared_raw, prepared_sha256, result):
    """Check a captured SDK return without IO or a claim of fresh native truth."""
    prepared = _decode(checkpoint, prepared_raw, prepared_sha256)
    state.keys(
        result,
        {
            "prepared_sha256",
            "predecessor_sha256",
            "head_sha256",
            "result_sha256",
            "sequence",
            "phase",
            "current",
            "before",
            "entry",
            "native_outcome",
            "phase_files",
            "phase_chain_sha256",
            "os_transition_verified",
            "application_quiesced",
            "application_write_verified",
            "restore_verified",
            "rebuild_verified",
            "backup_verified",
            "mutation_attempted",
            "operation_records",
        },
    )
    state.integer(result["sequence"], 1, journal.MAX_OPERATIONS)
    require(
        result["prepared_sha256"] == prepared_sha256
        and result["predecessor_sha256"] == prepared["predecessor_sha256"]
        and all(
            result[key] is True
            for key in (
                "os_transition_verified",
                "application_quiesced",
                "mutation_attempted",
            )
        )
        and all(
            result[key] is False
            for key in (
                "application_write_verified",
                "restore_verified",
                "rebuild_verified",
                "backup_verified",
            )
        ),
        "return-flags",
    )
    phase = "stopped" if prepared["kind"] == "shutdown" else "os_quiesced"
    require(result["phase"] == phase, "return-phase")
    current.validate_current(checkpoint, phase, result["current"])
    owner = binding(checkpoint)
    documents = _documents(owner, prepared, result)
    names = {
        "intent.json",
        "result.json",
        "HEAD.json",
        *(stage + ".json" for stage in journal.STAGES),
    }
    state.keys(result["operation_records"], names)
    require(
        all(
            type(raw) is str and 0 < len(raw.encode()) <= journal.LIMIT
            for raw in result["operation_records"].values()
        ),
        "return-records",
    )
    records = {name: raw.encode() for name, raw in result["operation_records"].items()}
    require(sum(map(len, records.values())) <= 16777216, "return-size")
    for name, value in documents.items():
        require(records[name] == state.canonical(value), "return-document")
    phases = journal.validate_phase_capture(
        owner,
        documents["intent.json"],
        {stage + ".json": records[stage + ".json"] for stage in journal.STAGES},
        result["phase_files"],
    )
    _validate_evidence(
        checkpoint,
        prepared,
        {
            "before": result["before"],
            "entry": result["entry"],
            "after": result["current"],
        },
        phases.records["dispatch.json"]["payload"],
    )
    outcome = phases.records["terminal.json"]["payload"]["native_outcome"]
    current.same(outcome, result["native_outcome"], "return-native-outcome")
    require(
        outcome["accepted"] is True
        and phases.sha256 == result["phase_chain_sha256"]
        and digest(documents["result.json"]) == result["result_sha256"]
        and digest(documents["HEAD.json"]) == result["head_sha256"],
        "return-hashes",
    )


def operate(checkpoint, prepared_raw, prepared_sha256, *, timeout_seconds=240):
    """Issue one fixed native action from a ready predecessor, never a pending slot."""
    state.integer(timeout_seconds, 1, 600)
    prepared = _decode(checkpoint, prepared_raw, prepared_sha256)
    phase = _phase(prepared["kind"])
    final_phase = "stopped" if phase == "os_quiesced" else "os_quiesced"
    owner = binding(checkpoint)
    prior = prepared["prior_runtime"]
    with _leased(checkpoint, phase, prior) as scope:
        history = _history(checkpoint)
        view = journal._inspect(owner, prepared["predecessor_sha256"])
        require(view.head["state"] == "ready", "pending")
        current.same(_entry_identity(scope.entry), prepared["entry"], "preflight-entry")
        current.same(
            observe.mount_facts(scope.request["backup_store"]),
            prepared["backup_store"],
            "backup-mount",
        )
        with current._current_leased(
            checkpoint, scope.entry, scope.raw, prior
        ) as before:
            current.same(
                _init_identity(before), prepared["init_identity"], "preflight-init"
            )
            require(
                before["observation"]["guest"]["runtime"]["uptime"]
                >= prepared["uptime_floor"],
                "preflight-uptime",
            )
            pending = journal._begin(
                owner, prepared["predecessor_sha256"], prepared["kind"], prepared_sha256
            )
            scope.pending = pending
            action = "shutdown" if pending.kind == "shutdown" else "start"
            pending = journal._append_phase(
                pending,
                "dispatch",
                {
                    "action": action,
                    "binding": asdict(owner.guest),
                    "prepared_sha256": prepared_sha256,
                    "entry_sha256": digest(scope.entry),
                    "host_epoch": {
                        key: scope.entry["host"][key]
                        for key in ("boot_id", "mount_namespace")
                    },
                    "clock": int(time.time()),
                    "parameters": api._parameters(owner.guest, action, None),
                },
            )
        _close_history((checkpoint, history))
        journal._close(pending.seal)
        scope.target.close()
        runtime.config_lock.require_write_available(owner.guest.vmid)
        scope.outcome = "unknown"
        ack = api.post_guest_action(owner.guest, action)
        pending = journal._append_phase(pending, "ack", ack)
        pending, native_outcome = _poll(pending, timeout_seconds)
        scope.outcome = "failed"
        require(native_outcome["accepted"] is True, "native-task-unqualified")
        scope.outcome = "postcondition-refused"
        scope.target.enter_context(runtime.config_lock.read_guest(owner.guest.vmid))
        final_prior = before["observation"] if phase == "os_quiesced" else prior
        entry = current._entry_leased(checkpoint, final_phase, final_prior)
        history = _history(checkpoint)
        journal._current_operation(pending)
        current.same(
            observe.mount_facts(scope.request["backup_store"]),
            prepared["backup_store"],
            "backup-mount",
        )
        with current._current_leased(
            checkpoint, entry, scope.raw, final_prior
        ) as observed:
            evidence = {"before": before, "entry": scope.entry, "after": observed}
            candidate = journal._complete(pending, evidence)
            result = {
                "prepared_sha256": prepared_sha256,
                "predecessor_sha256": prepared["predecessor_sha256"],
                "head_sha256": candidate.head_sha256,
                "result_sha256": candidate.result_sha256,
                "sequence": candidate.sequence,
                "phase": final_phase,
                "current": observed,
                "before": before,
                "entry": scope.entry,
                "native_outcome": native_outcome,
                "phase_files": candidate.phases.files,
                "phase_chain_sha256": candidate.phases.sha256,
                "os_transition_verified": True,
                "application_quiesced": True,
                "application_write_verified": False,
                "restore_verified": False,
                "rebuild_verified": False,
                "backup_verified": False,
                "mutation_attempted": True,
            }
            documents = _documents(owner, prepared, result) | candidate.phases.records
            result["operation_records"] = {
                name: state.canonical(value).decode()
                for name, value in documents.items()
            }
            validate_result(checkpoint, prepared_raw, prepared_sha256, result)
        _close_history((checkpoint, history))
        journal._close(candidate.seal)
    return result


def status(
    checkpoint,
    prepared_raw,
    prepared_sha256,
    accepted_head_sha256,
    *,
    prior_runtime=None
):
    """Recheck a separately accepted transition without writes or native retry."""
    prepared = _decode(checkpoint, prepared_raw, prepared_sha256)
    owner = binding(checkpoint)
    phase = "stopped" if prepared["kind"] == "shutdown" else "os_quiesced"
    prior = prior_runtime if prior_runtime is not None else prepared["prior_runtime"]
    with _leased(checkpoint, phase, prior) as scope:
        history = _history(checkpoint)
        view = journal._inspect(owner, accepted_head_sha256)
        require(
            view.head["state"] == "ready"
            and view.head["sequence"] > 0
            and view.intent["prepared_sha256"] == prepared_sha256
            and view.intent["predecessor_sha256"] == prepared["predecessor_sha256"]
            and view.intent["kind"] == prepared["kind"],
            "accepted-transition",
        )
        path = (
            journal.RUNTIME_ROOT
            / owner.pair_key
            / journal._slot(view.head["sequence"])
            / "result.json"
        )
        recorded = journal._read(path, view.seal)
        require(digest(recorded) == view.head["result_sha256"], "accepted-result")
        _validate_evidence(
            checkpoint,
            prepared,
            recorded["evidence"],
            view.phases.records["dispatch.json"]["payload"],
        )
        terminal = view.phases.records["terminal.json"]["payload"]
        ack = view.phases.records["ack.json"]["payload"]
        scope.target.close()
        task, log = api.task_state(
            owner.guest,
            ack["upid"],
            kind="vzshutdown" if prepared["kind"] == "shutdown" else "vzstart",
        )
        current.same(
            {"task": task, "log": log, "native_outcome": api.native_outcome(task, log)},
            terminal,
            "native-task-changed",
        )
        scope.target.enter_context(runtime.config_lock.read_guest(owner.guest.vmid))
        entry = current._entry_leased(checkpoint, phase, prior)
        current._same_entry(scope.entry, entry)
        history = _history(checkpoint)
        view = journal._inspect(owner, accepted_head_sha256)
        with current._current_leased(checkpoint, entry, scope.raw, prior) as observed:
            result = {
                "prepared_sha256": prepared_sha256,
                "head_sha256": accepted_head_sha256,
                "phase": phase,
                "current": observed,
                "os_transition_verified": True,
                "application_quiesced": True,
                "mutation_attempted": False,
                "application_write_verified": False,
                "restore_verified": False,
                "rebuild_verified": False,
                "backup_verified": False,
            }
        _close_history((checkpoint, history))
        journal._close(view.seal)
    return result
