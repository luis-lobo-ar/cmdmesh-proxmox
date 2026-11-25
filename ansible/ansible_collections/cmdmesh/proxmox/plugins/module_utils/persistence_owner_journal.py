"""Internal manager-side metadata ordering for one reference-owner cohort.

Mutation helpers require the caller's real GUID-pair EX. They neither acquire
that lease nor admit a host, owner, guest or native action. A candidate head is
successor authority only after the controller accepts its verified return.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_backup as backup,
    persistence_observe as observe,
    persistence_state as state,
)

RUNTIME_ROOT = Path("/var/lib/cmdmesh/owner-lifecycle")
LIMIT = 4194304
MAX_OPERATIONS = 4096
RUNTIME = {
    "document_type": "cmdmesh.proxmox.owner-journal.runtime",
    "schema_version": 1,
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
        "schema_version": 1,
        **values,
    }


def _schema(value, kind, fields):
    state.keys(value, {"document_type", "schema_version", *fields})
    require(
        value["document_type"] == "cmdmesh.proxmox.owner-journal." + kind
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1,
        "schema",
    )


@dataclass(frozen=True)
class Binding:
    pair_key: str
    authority_sha256: str

    def __post_init__(self):
        state.digest(self.pair_key)
        state.digest(self.authority_sha256)


@dataclass
class Seal:
    files: dict = field(default_factory=dict)
    directories: dict = field(default_factory=dict)
    members: dict = field(default_factory=dict)


@dataclass(frozen=True)
class View:
    head: dict
    head_sha256: str
    seal: Seal


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


@dataclass(frozen=True)
class Candidate:
    sequence: int
    head_sha256: str
    result_sha256: str
    seal: Seal


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
        "profile", pair_key=binding.pair_key, authority_sha256=binding.authority_sha256
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
    for sequence in range(1, head["sequence"] + 1):
        slot = directory / _slot(sequence)
        _directory(slot, seal)
        pending = sequence == head["sequence"] and head["state"] == "pending"
        _members(
            slot, {"intent.json"} if pending else {"intent.json", "result.json"}, seal
        )
        intent = _read(slot / "intent.json", seal)
        _schema(
            intent,
            "intent",
            {
                "profile_sha256",
                "sequence",
                "predecessor_sha256",
                "kind",
                "prepared_sha256",
            },
        )
        state.integer(intent["sequence"], 1, MAX_OPERATIONS)
        state.digest(intent["prepared_sha256"])
        require(
            intent["sequence"] == sequence
            and type(intent["kind"]) is str
            and intent["kind"] in {"shutdown", "resume"}
            and intent["profile_sha256"] == _digest(profile)
            and intent["predecessor_sha256"] == previous,
            "intent",
        )
        intent_sha = _digest(intent)
        result_sha = None
        if not pending:
            result = _read(slot / "result.json", seal)
            _schema(
                result,
                "result",
                {"profile_sha256", "sequence", "intent_sha256", "evidence"},
            )
            state.integer(result["sequence"], 1, MAX_OPERATIONS)
            require(
                result["profile_sha256"] == _digest(profile)
                and result["sequence"] == sequence
                and result["intent_sha256"] == intent_sha
                and type(result["evidence"]) is dict,
                "result",
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
    return View(head, expected_head_sha256, seal)


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
    )


def _complete(operation, evidence):
    """Publish a metadata candidate after caller validation; do not certify native work."""
    require(type(operation) is Pending and type(evidence) is dict, "operation")
    _close(operation.seal)
    current = _inspect(operation.binding, operation.pending_head_sha256)
    require(
        current.head["state"] == "pending"
        and current.head["sequence"] == operation.sequence
        and current.head["intent_sha256"] == operation.intent_sha256,
        "operation",
    )
    binding = operation.binding
    slot = RUNTIME_ROOT / binding.pair_key / _slot(operation.sequence)
    result = _document(
        "result",
        profile_sha256=_digest(_profile(binding)),
        sequence=operation.sequence,
        intent_sha256=operation.intent_sha256,
        evidence=evidence,
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
    return Candidate(operation.sequence, head_sha, result_sha, view.seal)


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
