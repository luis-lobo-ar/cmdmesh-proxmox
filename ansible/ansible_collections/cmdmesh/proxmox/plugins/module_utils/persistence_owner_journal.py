"""Internal manager-side metadata ordering for one reference-owner cohort.

Mutation helpers require the caller's real GUID-pair EX. They neither acquire
that lease nor admit a host, owner, guest or native action. A candidate head is
successor authority only after the controller accepts its verified return.
"""

from dataclasses import asdict, dataclass, field, fields, replace
import os
from pathlib import Path
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_backup as backup,
    persistence_observe as observe,
    persistence_state as state,
    persistence_guest_api as api,
)

RUNTIME_ROOT = Path("/var/lib/cmdmesh/owner-lifecycle")
LIMIT = 4194304
MAX_OPERATIONS = 4096
ROOT_UID = 0
VERSION = 2
ACTION_PROFILE = "owner-os-action-v1"
STAGES = ("dispatch", "ack", "terminal")
RUNTIME = {
    "document_type": "cmdmesh.proxmox.owner-journal.runtime",
    "schema_version": VERSION,
    "action_profile": ACTION_PROFILE,
}
HEAD_FIELDS = {
    "profile_sha256",
    "sequence",
    "state",
    "predecessor_sha256",
    "intent_sha256",
    "result_sha256",
}


def require(value, code):
    state.require(value, "persistence-owner-journal-" + code)


def _digest(value):
    return state.sha256(state.canonical(value))


def _document(document_kind, **values):
    return {
        "document_type": "cmdmesh.proxmox.owner-journal." + document_kind,
        "schema_version": VERSION,
        **values,
    }


def _schema(value, kind, fields):
    state.keys(value, {"document_type", "schema_version", *fields})
    require(
        value["document_type"] == "cmdmesh.proxmox.owner-journal." + kind
        and type(value["schema_version"]) is int
        and value["schema_version"] == VERSION,
        "schema",
    )


@dataclass(frozen=True)
class Binding:
    pair_key: str
    authority_sha256: str
    guest: api.GuestBinding

    def __post_init__(self):
        state.digest(self.pair_key)
        state.digest(self.authority_sha256)
        require(type(self.guest) is api.GuestBinding, "guest-binding")


@dataclass
class Seal:
    files: dict = field(default_factory=dict)
    directories: dict = field(default_factory=dict)
    members: dict = field(default_factory=dict)


@dataclass(frozen=True)
class PhaseChain:
    records: dict
    files: dict
    sha256: str


@dataclass(frozen=True)
class View:
    head: dict
    head_sha256: str
    seal: Seal
    intent: dict | None
    phases: PhaseChain


@dataclass(frozen=True)
class Pending:
    binding: Binding
    sequence: int
    kind: str
    prepared_sha256: str
    predecessor_sha256: str
    intent_sha256: str
    pending_head_sha256: str
    seal: Seal
    phases: PhaseChain


@dataclass(frozen=True)
class Candidate:
    sequence: int
    head_sha256: str
    result_sha256: str
    seal: Seal
    phases: PhaseChain


def _directory(path, seal):
    backup.private_directory(path)
    seal.directories[str(path)] = tuple(observe.stable(path.lstat()))[:5]


def _members(path, expected, seal):
    names = tuple(sorted(item.name for item in path.iterdir()))
    require(set(names) == set(expected), "membership")
    seal.members[str(path)] = names


def _read(path, seal):
    raw, info = observe.read_regular(path, LIMIT)
    require(
        info.st_uid == os.geteuid()
        and info.st_gid == os.getegid()
        and info.st_mode & 0o7777 == 0o600
        and info.st_nlink == 1,
        "file",
    )
    value = observe.decode(raw)
    require(type(value) is dict and state.canonical(value) == raw, "canonical")
    seal.files[str(path)] = tuple(observe.stable(info))
    return value


def _close(seal):
    """Fast metadata/membership closure; no content or application reads."""
    for path, identity in seal.files.items():
        require(tuple(observe.stable(Path(path).lstat())) == identity, "file-changed")
    for path, identity in seal.directories.items():
        backup.private_directory(Path(path))
        require(
            tuple(observe.stable(Path(path).lstat()))[:5] == identity,
            "directory-changed",
        )
    for path, names in seal.members.items():
        require(
            tuple(sorted(item.name for item in Path(path).iterdir())) == names,
            "membership-changed",
        )


def _write(path, value):
    require(type(value) is dict and len(state.canonical(value)) <= LIMIT, "payload")
    return backup.write_private(path, value)


def _profile(binding):
    require(type(binding) is Binding, "binding")
    return _document(
        "profile",
        pair_key=binding.pair_key,
        authority_sha256=binding.authority_sha256,
        action_profile=ACTION_PROFILE,
        guest_binding=asdict(binding.guest),
    )


def _head(binding, sequence, phase, predecessor, intent=None, result=None):
    return _document(
        "head",
        profile_sha256=_digest(_profile(binding)),
        sequence=sequence,
        state=phase,
        predecessor_sha256=predecessor,
        intent_sha256=intent,
        result_sha256=result,
    )


def _genesis(binding):
    return _head(binding, 0, "ready", binding.authority_sha256)


def _slot(sequence):
    state.integer(sequence, 1, MAX_OPERATIONS)
    return f"{sequence:020d}"


def _global(seal):
    _directory(RUNTIME_ROOT.parent, seal)
    _directory(RUNTIME_ROOT, seal)
    require(
        _digest(_read(RUNTIME_ROOT / "runtime.json", seal)) == _digest(RUNTIME),
        "runtime-profile",
    )
    require(
        all(
            item.name == "runtime.json" or state.matches(r"[a-f0-9]{64}", item.name)
            for item in RUNTIME_ROOT.iterdir()
        ),
        "runtime-membership",
    )


def _validate_intent(binding, intent):
    _schema(
        intent,
        "intent",
        {"profile_sha256", "sequence", "predecessor_sha256", "kind", "prepared_sha256"},
    )
    state.integer(intent["sequence"], 1, MAX_OPERATIONS)
    state.digest(intent["prepared_sha256"])
    state.digest(intent["predecessor_sha256"])
    require(
        intent["profile_sha256"] == _digest(_profile(binding))
        and type(intent["kind"]) is str
        and intent["kind"] in {"shutdown", "resume"},
        "intent",
    )


def _prefix(names):
    require(len(names) <= len(STAGES), "phase-membership")
    expected = tuple(stage + ".json" for stage in STAGES[: len(names)])
    require(set(names) == set(expected), "phase-membership")
    return expected


def _phase_payload(owner, intent, stage, payload, previous):
    require(type(payload) is dict, "phase-payload")
    action = "shutdown" if intent["kind"] == "shutdown" else "start"
    kind = "vzshutdown" if action == "shutdown" else "vzstart"
    if stage == "dispatch":
        state.keys(
            payload,
            {
                "action",
                "binding",
                "prepared_sha256",
                "entry_sha256",
                "host_epoch",
                "clock",
                "parameters",
            },
        )
        state.keys(payload["binding"], {item.name for item in fields(api.GuestBinding)})
        require(
            _digest(payload["binding"]) == _digest(asdict(owner.guest)),
            "dispatch-target",
        )
        binding = owner.guest
        state.digest(payload["entry_sha256"])
        state.integer(payload["clock"], 1, 2**63 - 1)
        state.keys(payload["host_epoch"], {"boot_id", "mount_namespace"})
        require(
            payload["action"] == action
            and payload["prepared_sha256"] == intent["prepared_sha256"]
            and state.matches(
                r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}",
                payload["host_epoch"]["boot_id"],
            )
            and state.matches(
                r"mnt:\[[1-9][0-9]*\]", payload["host_epoch"]["mount_namespace"]
            )
            and _digest(payload["parameters"])
            == _digest(api._parameters(binding, action, None)),
            "dispatch",
        )
        return
    dispatch = previous["dispatch.json"]["payload"]
    binding = owner.guest
    if stage == "ack":
        state.keys(payload, {"upid", "tls_verified"})
        require(payload["tls_verified"] is True, "ack-tls")
        parsed = api.parse_upid(binding, payload["upid"], kind=kind)
        require(
            dispatch["clock"] - 2 <= parsed["starttime"] <= dispatch["clock"] + 60,
            "ack-clock",
        )
        return
    state.keys(payload, {"task", "log", "native_outcome"})
    ack = previous["ack.json"]["payload"]
    api.validate_task_status(binding, ack["upid"], payload["task"], kind=kind)
    require(payload["task"]["status"] == "stopped", "terminal")
    outcome = api.native_outcome(payload["task"], payload["log"])
    require(_digest(payload["native_outcome"]) == _digest(outcome), "terminal-outcome")


def validate_phase_capture(binding, intent, records, descriptors):
    """Validate a canonical raw phase prefix without IO or native truth claims.

    This validates recorded metadata and links only. An incomplete prefix cannot
    complete an operation; no captured document acquires a lease or authorizes
    a retry. Manager-side descriptor ownership is fixed at root.
    """
    _validate_intent(binding, intent)
    require(type(records) is dict and type(descriptors) is dict, "phase-capture")
    names = _prefix(records)
    state.keys(descriptors, set(names))
    require(
        all(type(raw) is bytes and 0 < len(raw) <= LIMIT for raw in records.values()),
        "phase-capture-size",
    )
    documents = {}
    predecessor = _digest(intent)
    for name in names:
        raw = records[name]
        document = observe.decode(raw)
        _schema(
            document,
            "phase",
            {
                "profile_sha256",
                "sequence",
                "intent_sha256",
                "predecessor_sha256",
                "stage",
                "payload",
            },
        )
        stage = name[:-5]
        require(
            state.canonical(document) == raw
            and document["profile_sha256"] == intent["profile_sha256"]
            and type(document["sequence"]) is int
            and document["sequence"] == intent["sequence"]
            and document["intent_sha256"] == _digest(intent)
            and document["predecessor_sha256"] == predecessor
            and document["stage"] == stage,
            "phase-chain",
        )
        _phase_payload(binding, intent, stage, document["payload"], documents)
        info = descriptors[name]
        state.keys(info, {"path", "sha256", "identity"})
        identity = info["identity"]
        expected = str(
            RUNTIME_ROOT / binding.pair_key / _slot(intent["sequence"]) / name
        )
        require(
            info["path"] == expected
            and info["sha256"] == state.sha256(raw)
            and type(identity) is list
            and len(identity) == 9
            and all(type(part) is int and part >= 0 for part in identity)
            and identity[0] > 0
            and identity[1] > 0
            and identity[2:7]
            == [stat.S_IFREG | 0o600, ROOT_UID, ROOT_UID, 1, len(raw)],
            "phase-file",
        )
        documents[name] = document
        predecessor = state.sha256(raw)
    return PhaseChain(documents, descriptors, _digest(descriptors))


def _read_phases(binding, intent, slot, pending, seal):
    names = {path.name for path in slot.iterdir()}
    phases = names - {"intent.json", "result.json"}
    ordered = _prefix(phases)
    require(pending or len(ordered) == len(STAGES), "phases-incomplete")
    _members(
        slot, {"intent.json", *ordered, *(() if pending else ("result.json",))}, seal
    )
    records, descriptors = {}, {}
    for name in ordered:
        path = slot / name
        records[name] = state.canonical(_read(path, seal))
        descriptors[name] = {
            "path": str(path),
            "sha256": state.sha256(records[name]),
            "identity": list(seal.files[str(path)]),
        }
    return validate_phase_capture(binding, intent, records, descriptors)


def _inspect(binding, expected_head_sha256):
    """Read a fully coherent chain at an externally accepted head; create nothing."""
    profile = _profile(binding)
    state.digest(expected_head_sha256)
    seal = Seal()
    _global(seal)
    directory = RUNTIME_ROOT / binding.pair_key
    _directory(directory, seal)
    require(
        _digest(_read(directory / "profile.json", seal)) == _digest(profile),
        "authority",
    )
    genesis = _read(directory / "genesis.json", seal)
    require(_digest(genesis) == _digest(_genesis(binding)), "genesis")
    head = _read(directory / "HEAD.json", seal)
    _schema(head, "head", HEAD_FIELDS)
    state.integer(head["sequence"], 0, MAX_OPERATIONS)
    require(
        type(head["state"]) is str
        and head["state"] in {"ready", "pending"}
        and _digest(head) == expected_head_sha256,
        "head",
    )
    previous, cursor = _digest(genesis), genesis
    intent, phases = None, PhaseChain({}, {}, _digest({}))
    for sequence in range(1, head["sequence"] + 1):
        slot = directory / _slot(sequence)
        _directory(slot, seal)
        pending = sequence == head["sequence"] and head["state"] == "pending"
        intent = _read(slot / "intent.json", seal)
        _validate_intent(binding, intent)
        require(
            intent["sequence"] == sequence
            and type(intent["kind"]) is str
            and intent["kind"] in {"shutdown", "resume"}
            and intent["profile_sha256"] == _digest(profile)
            and intent["predecessor_sha256"] == previous,
            "intent",
        )
        intent_sha = _digest(intent)
        phases = _read_phases(binding, intent, slot, pending, seal)
        result_sha = None
        if not pending:
            result = _read(slot / "result.json", seal)
            _schema(
                result,
                "result",
                {
                    "profile_sha256",
                    "sequence",
                    "intent_sha256",
                    "evidence",
                    "phase_files",
                    "phase_chain_sha256",
                },
            )
            state.integer(result["sequence"], 1, MAX_OPERATIONS)
            require(
                result["profile_sha256"] == _digest(profile)
                and result["sequence"] == sequence
                and result["intent_sha256"] == intent_sha
                and type(result["evidence"]) is dict,
                "result",
            )
            require(
                result["phase_chain_sha256"] == phases.sha256
                and _digest(result["phase_files"]) == phases.sha256
                and phases.records["terminal.json"]["payload"]["native_outcome"][
                    "accepted"
                ]
                is True,
                "result-phases",
            )
            result_sha = _digest(result)
        cursor = _head(
            binding,
            sequence,
            "pending" if pending else "ready",
            previous,
            intent_sha,
            result_sha,
        )
        previous = _digest(cursor)
    require(_digest(cursor) == _digest(head), "head-chain")
    _members(
        directory,
        {
            "profile.json",
            "genesis.json",
            "HEAD.json",
            *(_slot(index) for index in range(1, head["sequence"] + 1)),
        },
        seal,
    )
    _close(seal)
    return View(head, expected_head_sha256, seal, intent, phases)


def _initialize(binding):
    """Explicit metadata initialization, idempotent only before the first operation."""
    _profile(binding)
    backup.private_directory(RUNTIME_ROOT.parent)
    if not os.path.lexists(RUNTIME_ROOT):
        RUNTIME_ROOT.mkdir(mode=0o700)
        _write(RUNTIME_ROOT / "runtime.json", RUNTIME)
        backup.sync_directory(RUNTIME_ROOT.parent)
    seal = Seal()
    _global(seal)
    directory = RUNTIME_ROOT / binding.pair_key
    changed = not os.path.lexists(directory)
    if changed:
        directory.mkdir(mode=0o700)
        backup.sync_directory(RUNTIME_ROOT)
        _write(directory / "profile.json", _profile(binding))
        _write(directory / "genesis.json", _genesis(binding))
        _write(directory / "HEAD.json", _genesis(binding))
    digest = _digest(_genesis(binding))
    _inspect(binding, digest)
    return {"changed": changed, "head_sha256": digest}


def _publish(binding, previous_sha256, value):
    _profile(binding)
    directory = RUNTIME_ROOT / binding.pair_key
    seal = Seal()
    _directory(directory, seal)
    require(
        _digest(_read(directory / "HEAD.json", seal)) == previous_sha256, "predecessor"
    )
    checksum = _write(directory / "HEAD.next", value)
    _close(seal)
    os.replace(directory / "HEAD.next", directory / "HEAD.json")
    backup.sync_directory(directory)
    return checksum


def _begin(binding, predecessor_sha256, kind, prepared_sha256):
    """Durably claim the next slot before the caller may dispatch anything."""
    state.digest(prepared_sha256)
    require(type(kind) is str and kind in {"shutdown", "resume"}, "kind")
    before = _inspect(binding, predecessor_sha256)
    require(before.head["state"] == "ready", "pending")
    sequence = before.head["sequence"] + 1
    slot = RUNTIME_ROOT / binding.pair_key / _slot(sequence)
    _close(before.seal)
    slot.mkdir(mode=0o700)
    backup.sync_directory(slot.parent)
    intent = _document(
        "intent",
        profile_sha256=_digest(_profile(binding)),
        sequence=sequence,
        predecessor_sha256=predecessor_sha256,
        kind=kind,
        prepared_sha256=prepared_sha256,
    )
    intent_sha = _write(slot / "intent.json", intent)
    pending_sha = _publish(
        binding,
        predecessor_sha256,
        _head(binding, sequence, "pending", predecessor_sha256, intent_sha),
    )
    view = _inspect(binding, pending_sha)
    return Pending(
        binding,
        sequence,
        kind,
        prepared_sha256,
        predecessor_sha256,
        intent_sha,
        pending_sha,
        view.seal,
        view.phases,
    )


def _current_operation(operation):
    require(type(operation) is Pending, "operation")
    _close(operation.seal)
    current = _inspect(operation.binding, operation.pending_head_sha256)
    require(
        current.head["state"] == "pending"
        and current.head["sequence"] == operation.sequence
        and current.head["intent_sha256"] == operation.intent_sha256,
        "operation",
    )
    require(
        current.intent["kind"] == operation.kind
        and current.intent["prepared_sha256"] == operation.prepared_sha256
        and current.intent["predecessor_sha256"] == operation.predecessor_sha256
        and current.phases.sha256 == operation.phases.sha256,
        "operation-scope",
    )
    return current


def _append_phase(operation, stage, payload):
    """Durably append the next fixed phase and return a freshly sealed token."""
    require(type(stage) is str and stage in STAGES, "phase")
    require(
        type(payload) is dict and len(state.canonical(payload)) <= LIMIT,
        "phase-payload",
    )
    payload = observe.decode(state.canonical(payload))
    current = _current_operation(operation)
    count = len(current.phases.records)
    require(count < len(STAGES) and stage == STAGES[count], "phase-order")
    _phase_payload(
        operation.binding, current.intent, stage, payload, current.phases.records
    )
    predecessor = (
        operation.intent_sha256
        if count == 0
        else _digest(current.phases.records[STAGES[count - 1] + ".json"])
    )
    document = _document(
        "phase",
        profile_sha256=_digest(_profile(operation.binding)),
        sequence=operation.sequence,
        intent_sha256=operation.intent_sha256,
        predecessor_sha256=predecessor,
        stage=stage,
        payload=payload,
    )
    slot = RUNTIME_ROOT / operation.binding.pair_key / _slot(operation.sequence)
    intended_sha256 = _digest(document)
    _close(current.seal)
    _write(slot / (stage + ".json"), document)
    view = _inspect(operation.binding, operation.pending_head_sha256)
    require(
        view.phases.files[stage + ".json"]["sha256"] == intended_sha256,
        "phase-write-changed",
    )
    return replace(operation, seal=view.seal, phases=view.phases)


def _complete(operation, evidence):
    """Publish a metadata candidate after caller validation; do not certify native work."""
    require(type(evidence) is dict, "operation")
    current = _current_operation(operation)
    require(
        len(current.phases.records) == len(STAGES)
        and current.phases.records["terminal.json"]["payload"]["native_outcome"][
            "accepted"
        ]
        is True,
        "phases-incomplete",
    )
    binding = operation.binding
    slot = RUNTIME_ROOT / binding.pair_key / _slot(operation.sequence)
    result = _document(
        "result",
        profile_sha256=_digest(_profile(binding)),
        sequence=operation.sequence,
        intent_sha256=operation.intent_sha256,
        evidence=evidence,
        phase_files=current.phases.files,
        phase_chain_sha256=current.phases.sha256,
    )
    result_sha = _write(slot / "result.json", result)
    head_sha = _publish(
        binding,
        operation.pending_head_sha256,
        _head(
            binding,
            operation.sequence,
            "ready",
            operation.predecessor_sha256,
            operation.intent_sha256,
            result_sha,
        ),
    )
    view = _inspect(binding, head_sha)
    return Candidate(operation.sequence, head_sha, result_sha, view.seal, view.phases)


def _fail(operation, reason, outcome):
    """Append a durable barrier, including after candidate publication; never reset."""
    require(type(operation) is Pending, "operation")
    require(
        state.matches(r"[a-z][a-z0-9-]{0,120}", reason)
        and type(outcome) is str
        and outcome in {"unknown", "failed", "postcondition-refused", "not-dispatched"},
        "failure",
    )
    binding = operation.binding
    _profile(binding)
    seal = Seal()
    _global(seal)
    directory = RUNTIME_ROOT / binding.pair_key
    slot = directory / _slot(operation.sequence)
    for path in (directory, slot):
        _directory(path, seal)
        require(
            seal.directories[str(path)] == operation.seal.directories[str(path)],
            "directory-changed",
        )
    require(
        _digest(_read(directory / "profile.json", seal)) == _digest(_profile(binding)),
        "authority",
    )
    require(
        _digest(_read(slot / "intent.json", seal)) == operation.intent_sha256, "intent"
    )
    _close(seal)
    return _write(
        slot / "failure.json",
        _document(
            "failure",
            intent_sha256=operation.intent_sha256,
            reason=reason,
            outcome=outcome,
        ),
    )
