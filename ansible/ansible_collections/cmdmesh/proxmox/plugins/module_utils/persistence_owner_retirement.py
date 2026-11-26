"""Internal metadata retirement of one uncertain legacy resume.

Callers hold the actual pair EX, application EX and guest config SH leases and
qualify fresh current/worker evidence themselves. Evidence references here are
opaque: neither a metadata candidate nor a supplied hash grants native authority.
No helper calls a native API, changes old records or initializes a new journal.
"""

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_journal as legacy,
    persistence_owner_request_journal as successor,
)

state, observe, backup = legacy.state, legacy.observe, legacy.backup
RUNTIME_ROOT = Path("/var/lib/cmdmesh/owner-profile-handoff-v1")
MARKER = "RETIRED-v4.json"
LIMIT = 4194304
MARKER_LIMIT = 16384
BASIS_LIMIT = 16777216
MODE = "uncertain-resume-v3"
RUNTIME = {
    "document_type": "cmdmesh.proxmox.owner-retirement.runtime",
    "schema_version": 1,
    "legacy_schema": 3,
    "target_schema": 4,
}


def require(value, code):
    state.require(value, "persistence-owner-retirement-" + code)


def digest(value):
    return state.sha256(state.canonical(value))


def _document(kind, **values):
    return {
        "document_type": "cmdmesh.proxmox.owner-retirement." + kind,
        "schema_version": 1,
        **values,
    }


def _schema(value, kind, fields):
    state.keys(value, {"document_type", "schema_version", *fields})
    require(
        value["document_type"] == "cmdmesh.proxmox.owner-retirement." + kind
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1,
        "schema",
    )


def _decode(raw, trusted, limit=LIMIT):
    state.digest(trusted)
    require(type(raw) is bytes and 0 < len(raw) <= limit, "raw-input")
    require(state.sha256(raw) == trusted, "external-hash")
    value = observe.decode(raw)
    require(type(value) is dict and state.canonical(value) == raw, "canonical")
    return value


def _binding(value):
    require(type(value) is legacy.Binding, "binding")
    require(type(value.guest) is legacy.api.GuestBinding, "guest-binding")
    body = asdict(value)
    bound = legacy.Binding(
        body["pair_key"],
        body["authority_sha256"],
        legacy.api.GuestBinding(**body["guest"]),
    )
    return bound, state.canonical(body)


def _close_binding(original, bound, raw):
    for value in (original, bound):
        _, current = _binding(value)
        require(current == raw, "binding-changed")


def _evidence(value):
    state.keys(
        value,
        {
            "phase",
            "host_epoch",
            "current_sha256",
            "worker_fence_sha256",
            "failure_provenance_sha256",
            "source_manifest_sha256",
            "accepted_prepared_sha256",
        },
    )
    require(value["phase"] == "os_quiesced", "evidence-phase")
    state.keys(value["host_epoch"], {"boot_id", "mount_namespace"})
    require(
        state.matches(
            r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}",
            value["host_epoch"]["boot_id"],
        )
        and state.matches(
            r"mnt:\[[1-9][0-9]*\]", value["host_epoch"]["mount_namespace"]
        ),
        "evidence-epoch",
    )
    for key in value.keys() - {"phase", "host_epoch"}:
        state.digest(value[key])


def _read(path, remaining, seal):
    """Charge the next file against the remaining budget before its data read."""
    before = path.lstat()
    limit = min(LIMIT, remaining)
    require(0 < before.st_size <= limit, "read-budget")
    raw, info = observe.read_regular(path, limit)
    require(observe.stable(before) == observe.stable(info), "file-changed")
    require(
        info.st_uid == os.geteuid()
        and info.st_gid == os.getegid()
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_nlink == 1,
        "file",
    )
    seal.files[str(path)] = tuple(observe.stable(info))
    return raw, {
        "path": str(path),
        "sha256": state.sha256(raw),
        "identity": list(observe.stable(info)),
    }


def _close(*seals):
    """Close all old/new controls together: memberships before fast metadata."""
    seal = legacy.Seal()
    for source in seals:
        require(type(source) is legacy.Seal, "seal")
        for section in ("members", "directories", "files"):
            target = getattr(seal, section)
            for path, identity in getattr(source, section).items():
                require(path not in target or target[path] == identity, "seal-conflict")
                target[path] = identity
    for path, names in seal.members.items():
        require(
            tuple(sorted(item.name for item in Path(path).iterdir())) == names,
            "membership-changed",
        )
    for path, identity in seal.directories.items():
        backup.private_directory(Path(path))
        require(
            tuple(observe.stable(Path(path).lstat()))[:5] == identity,
            "directory-changed",
        )
    for path, identity in seal.files.items():
        require(tuple(observe.stable(Path(path).lstat())) == identity, "file-changed")
    return seal


def _layout(sequence):
    root = {
        "profile.json",
        "genesis.json",
        "HEAD.json",
        *(legacy._slot(n) for n in range(1, sequence + 1)),
    }
    members = {"": sorted(root)}
    for n in range(1, sequence + 1):
        names = (
            {"intent.json", "dispatch.json", "failure.json"}
            if n == sequence
            else {
                "intent.json",
                "dispatch.json",
                "ack.json",
                "terminal.json",
                "result.json",
            }
        )
        members[legacy._slot(n)] = sorted(names)
    return members


def _identity(value, directory=False):
    require(type(value) is list and len(value) == (5 if directory else 9), "identity")
    require(all(type(part) is int and part >= 0 for part in value), "identity")
    require(value[0] > 0 and value[1] > 0, "identity")
    require(
        value[2:5]
        == [
            stat.S_IFDIR | 0o700 if directory else stat.S_IFREG | 0o600,
            legacy.ROOT_UID,
            legacy.ROOT_UID,
        ],
        "identity",
    )
    if not directory:
        require(value[5] == 1 and 0 < value[6] <= LIMIT, "identity")


def _descriptor(value, path, limit=LIMIT):
    state.keys(value, {"path", "sha256", "identity"})
    require(value["path"] == str(path), "descriptor-path")
    state.digest(value["sha256"])
    _identity(value["identity"])
    require(value["identity"][6] <= limit, "descriptor-size")


def _basis_shape(owner, value):
    state.keys(
        value,
        {"maximum_sequence", "head", "head_sha256", "files", "directories", "members"},
    )
    sequence = value["maximum_sequence"]
    state.integer(sequence, 1, legacy.MAX_OPERATIONS)
    head = value["head"]
    legacy._schema(head, "head", legacy.HEAD_FIELDS)
    state.integer(head["sequence"], 1, legacy.MAX_OPERATIONS)
    require(
        head["sequence"] == sequence
        and head["state"] == "pending"
        and head["result_sha256"] is None,
        "pending-head",
    )
    require(head["profile_sha256"] == digest(legacy._profile(owner)), "legacy-profile")
    for key in ("profile_sha256", "predecessor_sha256", "intent_sha256"):
        state.digest(head[key])
    require(value["head_sha256"] == digest(head), "head-hash")
    expected = _layout(sequence)
    require(
        type(value["members"]) is dict and value["members"] == expected,
        "legacy-membership",
    )
    state.keys(value["directories"], set(expected))
    for identity in value["directories"].values():
        _identity(identity, directory=True)
    names = {"profile.json", "genesis.json", "HEAD.json"}
    names.update(
        slot + "/" + name for slot in expected.keys() - {""} for name in expected[slot]
    )
    state.keys(value["files"], names)
    total = 0
    for entry in value["files"].values():
        state.keys(entry, {"sha256", "identity"})
        state.digest(entry["sha256"])
        _identity(entry["identity"])
        total += entry["identity"][6]
    require(total <= BASIS_LIMIT, "basis-limit")
    for name, document in (
        ("profile.json", legacy._profile(owner)),
        ("genesis.json", legacy._genesis(owner)),
        ("HEAD.json", head),
    ):
        descriptor = value["files"][name]
        require(
            descriptor["sha256"] == digest(document)
            and descriptor["identity"][6] == len(state.canonical(document)),
            "known-control",
        )


def _capture(owner, retired=False):
    """Strict dedicated reader: exact layout, with only the declared marker added."""
    legacy._profile(owner)
    seal = legacy.Seal()
    for path in (legacy.RUNTIME_ROOT.parent, legacy.RUNTIME_ROOT):
        legacy._directory(path, seal)
    raw_runtime, shared = _read(legacy.RUNTIME_ROOT / "runtime.json", BASIS_LIMIT, seal)
    require(raw_runtime == state.canonical(legacy.RUNTIME), "shared-runtime")
    for count, path in enumerate(legacy.RUNTIME_ROOT.iterdir(), 1):
        require(
            count <= legacy.MAX_OPERATIONS + 1
            and (
                path.name == "runtime.json" or state.matches(r"[a-f0-9]{64}", path.name)
            ),
            "shared-membership",
        )
    remaining = BASIS_LIMIT - len(raw_runtime)
    directory = legacy.RUNTIME_ROOT / owner.pair_key
    legacy._directory(directory, seal)
    raws, files = {}, {}
    # Read the fixed controls first to bound the derived slot layout.
    for name in ("profile.json", "genesis.json", "HEAD.json"):
        raw, descriptor = _read(directory / name, remaining, seal)
        remaining -= len(raw)
        raws[name] = raw
        files[name] = {key: descriptor[key] for key in ("sha256", "identity")}
    require(
        raws["profile.json"] == state.canonical(legacy._profile(owner))
        and raws["genesis.json"] == state.canonical(legacy._genesis(owner)),
        "legacy-authority",
    )
    head = _decode(raws["HEAD.json"], files["HEAD.json"]["sha256"])
    state.integer(head.get("sequence"), 1, legacy.MAX_OPERATIONS)
    sequence = head["sequence"]
    members = _layout(sequence)
    legacy._members(directory, {*members[""], *({MARKER} if retired else set())}, seal)
    directories = {"": list(seal.directories[str(directory)])}
    for slot in sorted(members.keys() - {""}):
        path = directory / slot
        legacy._directory(path, seal)
        directories[slot] = list(seal.directories[str(path)])
        legacy._members(path, members[slot], seal)
        for name in members[slot]:
            raw, descriptor = _read(path / name, remaining, seal)
            remaining -= len(raw)
            relative = slot + "/" + name
            raws[relative] = raw
            files[relative] = {key: descriptor[key] for key in ("sha256", "identity")}
    marker = None
    if retired:
        raw, descriptor = _read(directory / MARKER, MARKER_LIMIT, seal)
        marker = (raw, descriptor)
    basis = {
        "maximum_sequence": sequence,
        "head": head,
        "head_sha256": digest(head),
        "files": files,
        "directories": directories,
        "members": members,
    }
    _basis_shape(owner, basis)
    _close(seal)
    return basis, raws, shared, marker, seal


def _validate_legacy(owner, basis, raws, anchor, evidence):
    require(
        anchor["head"]["sequence"] == basis["maximum_sequence"] - 1, "latest-anchor"
    )
    raw_anchor = state.canonical(anchor["head"])
    validated = legacy._anchor(owner, raw_anchor, anchor["sha256"], basis, raws)
    legacy._anchor_ratchet(owner, validated, basis, raws)
    _pending(owner, basis, _pending_records(basis, raws), anchor, evidence)


def _pending_records(basis, raws):
    slot = legacy._slot(basis["maximum_sequence"])
    return {
        name: _decode(
            raws[slot + "/" + name], basis["files"][slot + "/" + name]["sha256"]
        )
        for name in ("intent.json", "dispatch.json", "failure.json")
    }


def _pending(owner, basis, records, anchor, evidence):
    slot = legacy._slot(basis["maximum_sequence"])
    state.keys(records, {"intent.json", "dispatch.json", "failure.json"})
    for name, value in records.items():
        require(
            digest(value) == basis["files"][slot + "/" + name]["sha256"]
            and len(state.canonical(value))
            == basis["files"][slot + "/" + name]["identity"][6],
            "pending-file",
        )
    intent = records["intent.json"]
    legacy._validate_intent(owner, intent)
    require(
        intent["kind"] == "resume"
        and intent["sequence"] == basis["maximum_sequence"]
        and intent["predecessor_sha256"] == anchor["sha256"],
        "pending-intent",
    )
    expected_head = legacy._head(
        owner, intent["sequence"], "pending", anchor["sha256"], digest(intent)
    )
    require(digest(expected_head) == basis["head_sha256"], "pending-head")
    dispatch = records["dispatch.json"]
    dispatch_raw = state.canonical(dispatch)
    legacy.validate_phase_capture(
        owner,
        intent,
        {"dispatch.json": dispatch_raw},
        {
            "dispatch.json": {
                "path": str(
                    legacy.RUNTIME_ROOT / owner.pair_key / slot / "dispatch.json"
                ),
                **basis["files"][slot + "/dispatch.json"],
            }
        },
    )
    failure = records["failure.json"]
    legacy._schema(failure, "failure", {"intent_sha256", "reason", "outcome"})
    require(
        failure["intent_sha256"] == digest(intent)
        and failure["reason"] == "transition-unqualified"
        and failure["outcome"] == "unknown",
        "failure-provenance",
    )
    require(
        evidence["accepted_prepared_sha256"] == intent["prepared_sha256"]
        and digest(evidence["host_epoch"]) == digest(dispatch["payload"]["host_epoch"]),
        "evidence-binding",
    )


def _target(owner):
    return {
        "schema_version": successor.VERSION,
        "action_profile": successor.ACTION_PROFILE,
        "runtime_root": str(successor.RUNTIME_ROOT),
        "guest_binding": asdict(owner.guest),
    }


def _shared_directories(seal):
    return {
        str(path): list(seal.directories[str(path)])
        for path in (legacy.RUNTIME_ROOT.parent, legacy.RUNTIME_ROOT)
    }


def _intent(owner, raw, sha):
    value = _decode(raw, sha)
    _schema(
        value,
        "intent",
        {
            "mode",
            "binding",
            "target",
            "anchor",
            "basis",
            "shared_runtime",
            "shared_directories",
            "caller_evidence",
            "pending_records",
        },
    )
    require(
        value["mode"] == MODE
        and digest(value["binding"]) == digest(asdict(owner))
        and digest(value["target"]) == digest(_target(owner)),
        "intent-authority",
    )
    _basis_shape(owner, value["basis"])
    _descriptor(value["shared_runtime"], legacy.RUNTIME_ROOT / "runtime.json")
    state.keys(
        value["shared_directories"],
        {str(legacy.RUNTIME_ROOT.parent), str(legacy.RUNTIME_ROOT)},
    )
    for identity in value["shared_directories"].values():
        _identity(identity, directory=True)
    require(
        value["shared_runtime"]["sha256"] == digest(legacy.RUNTIME)
        and value["shared_runtime"]["identity"][6]
        == len(state.canonical(legacy.RUNTIME)),
        "shared-runtime",
    )
    require(
        sum(entry["identity"][6] for entry in value["basis"]["files"].values())
        + value["shared_runtime"]["identity"][6]
        <= BASIS_LIMIT,
        "basis-limit",
    )
    state.keys(value["anchor"], {"head", "sha256"})
    legacy._schema(value["anchor"]["head"], "head", legacy.HEAD_FIELDS)
    require(
        value["anchor"]["head"]["state"] == "ready"
        and value["anchor"]["sha256"] == digest(value["anchor"]["head"]),
        "anchor",
    )
    state.integer(value["anchor"]["head"]["sequence"], 0, legacy.MAX_OPERATIONS)
    require(
        value["anchor"]["head"]["sequence"] == value["basis"]["maximum_sequence"] - 1,
        "latest-anchor",
    )
    _evidence(value["caller_evidence"])
    _pending(
        owner,
        value["basis"],
        value["pending_records"],
        value["anchor"],
        value["caller_evidence"],
    )
    return value


def _prepare(binding, anchor_raw, anchor_sha, basis_sha, evidence_raw, evidence_sha):
    """Read-only metadata preparation; caller-provided evidence remains unqualified."""
    owner, binding_raw = _binding(binding)
    evidence = _decode(evidence_raw, evidence_sha)
    _evidence(evidence)
    state.digest(basis_sha)
    basis, raws, shared, _, seal = _capture(owner)
    require(digest(basis) == basis_sha, "basis-changed")
    anchor = legacy._anchor(owner, anchor_raw, anchor_sha, basis, raws)
    _validate_legacy(owner, basis, raws, anchor, evidence)
    value = _document(
        "intent",
        mode=MODE,
        binding=asdict(owner),
        target=_target(owner),
        anchor=anchor,
        basis=basis,
        shared_runtime=shared,
        shared_directories=_shared_directories(seal),
        caller_evidence=evidence,
        pending_records=_pending_records(basis, raws),
    )
    raw = state.canonical(value)
    require(len(raw) <= LIMIT, "intent-size")
    _intent(owner, raw, state.sha256(raw))
    _close(seal)
    _close_binding(binding, owner, binding_raw)
    return value


def _write(path, value, limit):
    require(type(value) is dict and len(state.canonical(value)) <= limit, "write-size")
    return backup.write_private(path, value)


def _runtime(seal, initialize=False):
    expected_raw = state.canonical(RUNTIME)
    legacy._directory(RUNTIME_ROOT.parent, seal)
    if initialize and not os.path.lexists(RUNTIME_ROOT):
        RUNTIME_ROOT.mkdir(mode=0o700)
        backup.sync_directory(RUNTIME_ROOT.parent)
        _write(RUNTIME_ROOT / "runtime.json", observe.decode(expected_raw), LIMIT)
    legacy._directory(RUNTIME_ROOT, seal)
    raw, _ = _read(RUNTIME_ROOT / "runtime.json", LIMIT, seal)
    require(raw == expected_raw == state.canonical(RUNTIME), "runtime-profile")
    for count, path in enumerate(RUNTIME_ROOT.iterdir(), 1):
        require(
            count <= legacy.MAX_OPERATIONS + 1
            and (
                path.name == "runtime.json" or state.matches(r"[a-f0-9]{64}", path.name)
            ),
            "runtime-membership",
        )


def _stored_intent(owner, raw, sha, names):
    value = _intent(owner, raw, sha)
    seal = legacy.Seal()
    _runtime(seal)
    directory = RUNTIME_ROOT / owner.pair_key
    legacy._directory(directory, seal)
    legacy._members(directory, names, seal)
    actual, descriptor = _read(directory / "intent.json", LIMIT, seal)
    require(actual == raw and descriptor["sha256"] == sha, "intent-changed")
    return value, descriptor, seal


def _same_legacy(owner, intent, retired):
    basis, raws, shared, marker, seal = _capture(owner, retired)
    require(
        digest(basis) == digest(intent["basis"])
        and digest(shared) == digest(intent["shared_runtime"])
        and digest(_shared_directories(seal)) == digest(intent["shared_directories"]),
        "legacy-changed",
    )
    _validate_legacy(owner, basis, raws, intent["anchor"], intent["caller_evidence"])
    return marker, seal


@dataclass(frozen=True)
class Claim:
    owner: legacy.Binding
    binding_raw: bytes
    intent_raw: bytes
    intent_sha256: str
    seal: legacy.Seal


@dataclass(frozen=True)
class Retired:
    claim: Claim
    marker_raw: bytes
    marker_file: dict
    seal: legacy.Seal


@dataclass(frozen=True)
class Candidate:
    raw: bytes
    sha256: str
    seal: legacy.Seal


@dataclass(frozen=True)
class View:
    intent: dict
    completion: dict
    seal: legacy.Seal


def _begin(binding, intent_raw, intent_sha):
    """Claim H0 once; no old HEAD write and no native action."""
    owner, binding_raw = _binding(binding)
    intent = _intent(owner, intent_raw, intent_sha)
    _, old_seal = _same_legacy(owner, intent, False)
    directory = RUNTIME_ROOT / owner.pair_key
    require(not os.path.lexists(directory), "already-claimed")
    seal = legacy.Seal()
    _runtime(seal, initialize=True)
    _close(old_seal, seal)
    directory.mkdir(mode=0o700)
    backup.sync_directory(RUNTIME_ROOT)
    require(
        _write(directory / "intent.json", intent, LIMIT) == intent_sha, "intent-write"
    )
    _, _, result_seal = _stored_intent(owner, intent_raw, intent_sha, {"intent.json"})
    _, final_old = _same_legacy(owner, intent, False)
    _close(result_seal, final_old)
    _close_binding(binding, owner, binding_raw)
    return Claim(owner, binding_raw, intent_raw, intent_sha, result_seal)


def _marker(owner, intent_sha):
    return _document(
        "marker",
        intent_sha256=intent_sha,
        pair_key=owner.pair_key,
        checkpoint_sha256=owner.authority_sha256,
        legacy_profile_sha256=digest(legacy._profile(owner)),
        target=_target(owner),
        legacy_retired=True,
        native_action_dispatched=False,
        original_native_operation_qualified=False,
    )


def _claim(claim, names):
    require(type(claim) is Claim, "claim")
    _close_binding(claim.owner, claim.owner, claim.binding_raw)
    _close(claim.seal)
    return _stored_intent(claim.owner, claim.intent_raw, claim.intent_sha256, names)


def _mark(claim):
    """O_EXCL publication may leave a partial marker; ordinary replay then refuses."""
    intent, _, seal = _claim(claim, {"intent.json"})
    _, old_seal = _same_legacy(claim.owner, intent, False)
    document = _marker(claim.owner, claim.intent_sha256)
    expected_raw = state.canonical(document)
    expected_sha = state.sha256(expected_raw)
    _close(seal, old_seal)
    require(
        _write(
            legacy.RUNTIME_ROOT / claim.owner.pair_key / MARKER, document, MARKER_LIMIT
        )
        == expected_sha,
        "marker-write",
    )
    marker, final_old = _same_legacy(claim.owner, intent, True)
    require(marker[0] == expected_raw, "marker-changed")
    _close(seal, final_old)
    _close_binding(claim.owner, claim.owner, claim.binding_raw)
    return Retired(claim, marker[0], marker[1], final_old)


def _closing(initial, closing):
    _evidence(closing)
    for key in initial.keys() - {"current_sha256", "worker_fence_sha256"}:
        require(
            state.canonical(initial[key]) == state.canonical(closing[key]),
            "closing-evidence",
        )


def _completion(
    owner, intent_sha, intent_file, marker_raw, marker_file, basis, evidence
):
    return _document(
        "complete",
        intent_sha256=intent_sha,
        intent_file=intent_file,
        marker=_decode(marker_raw, marker_file["sha256"], MARKER_LIMIT),
        marker_file=marker_file,
        basis_sha256=digest(basis),
        caller_closing_evidence=evidence,
        legacy_retired=True,
        metadata_resolution_recorded=True,
        original_native_operation_qualified=False,
        native_action_dispatched=False,
    )


def validate_handoff(binding, intent_raw, intent_sha, complete_raw, complete_sha):
    """Pure metadata validation, never intrinsic current/worker-fence qualification."""
    owner, binding_raw = _binding(binding)
    intent = _intent(owner, intent_raw, intent_sha)
    value = _decode(complete_raw, complete_sha)
    _schema(
        value,
        "complete",
        {
            "intent_sha256",
            "intent_file",
            "marker",
            "marker_file",
            "basis_sha256",
            "caller_closing_evidence",
            "legacy_retired",
            "metadata_resolution_recorded",
            "original_native_operation_qualified",
            "native_action_dispatched",
        },
    )
    require(
        value["intent_sha256"] == intent_sha
        and value["basis_sha256"] == digest(intent["basis"]),
        "completion-link",
    )
    _descriptor(value["intent_file"], RUNTIME_ROOT / owner.pair_key / "intent.json")
    require(
        value["intent_file"]["sha256"] == intent_sha
        and value["intent_file"]["identity"][6] == len(intent_raw),
        "intent-file",
    )
    _descriptor(
        value["marker_file"],
        legacy.RUNTIME_ROOT / owner.pair_key / MARKER,
        MARKER_LIMIT,
    )
    marker = _marker(owner, intent_sha)
    require(
        digest(value["marker"]) == digest(marker)
        and value["marker_file"]["sha256"] == digest(marker)
        and value["marker_file"]["identity"][6] == len(state.canonical(marker)),
        "marker-link",
    )
    require(
        value["legacy_retired"] is True
        and value["metadata_resolution_recorded"] is True
        and value["native_action_dispatched"] is False
        and value["original_native_operation_qualified"] is False,
        "completion-flags",
    )
    _closing(intent["caller_evidence"], value["caller_closing_evidence"])
    _close_binding(binding, owner, binding_raw)
    return value


def _complete(retired, closing_raw, closing_sha):
    """Record caller-supplied closing evidence; leases/fence remain caller obligations."""
    require(type(retired) is Retired, "retired")
    claim = retired.claim
    intent, intent_file, seal = _claim(claim, {"intent.json"})
    _close(retired.seal)
    marker, old_seal = _same_legacy(claim.owner, intent, True)
    require(
        marker[0] == retired.marker_raw
        and digest(marker[1]) == digest(retired.marker_file)
        and marker[0] == state.canonical(_marker(claim.owner, claim.intent_sha256)),
        "marker-changed",
    )
    evidence = _decode(closing_raw, closing_sha)
    _closing(intent["caller_evidence"], evidence)
    document = _completion(
        claim.owner,
        claim.intent_sha256,
        intent_file,
        marker[0],
        marker[1],
        intent["basis"],
        evidence,
    )
    raw = state.canonical(document)
    require(len(raw) <= LIMIT, "completion-size")
    sha = state.sha256(raw)
    validate_handoff(claim.owner, claim.intent_raw, claim.intent_sha256, raw, sha)
    _close(seal, old_seal)
    require(
        _write(RUNTIME_ROOT / claim.owner.pair_key / "complete.json", document, LIMIT)
        == sha,
        "completion-write",
    )
    view = _inspect(claim.owner, claim.intent_raw, claim.intent_sha256, raw, sha)
    _close_binding(claim.owner, claim.owner, claim.binding_raw)
    return Candidate(raw, sha, view.seal)


def _inspect(binding, intent_raw, intent_sha, complete_raw, complete_sha):
    """Read-only closure against externally supplied hashes, not node discovery."""
    owner, binding_raw = _binding(binding)
    completion = validate_handoff(
        owner, intent_raw, intent_sha, complete_raw, complete_sha
    )
    intent, intent_file, seal = _stored_intent(
        owner, intent_raw, intent_sha, {"intent.json", "complete.json"}
    )
    require(
        digest(intent_file) == digest(completion["intent_file"]), "intent-file-changed"
    )
    raw, _ = _read(RUNTIME_ROOT / owner.pair_key / "complete.json", LIMIT, seal)
    require(raw == complete_raw, "completion-changed")
    marker, old_seal = _same_legacy(owner, intent, True)
    require(
        marker[0] == state.canonical(completion["marker"])
        and digest(marker[1]) == digest(completion["marker_file"]),
        "marker-changed",
    )
    seal = _close(seal, old_seal)
    _close_binding(binding, owner, binding_raw)
    return View(intent, completion, seal)
