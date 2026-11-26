"""Pure externally selected execution assertions, never producer/FS authority.

This codec authenticates no exporter, interpreter, lease or live filesystem. A
qualified controller selects exact records; the executor still obtains its own
actual current/leases/FD facts and validates every real publication. Historical
decision references retain their original meaning; no native ACK is recovered.
"""

import base64
import binascii
from dataclasses import dataclass, field
from pathlib import PurePosixPath
import re
import stat
import struct

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_atomic as atomic,
    persistence_owner_bootstrap as bootstrap,
    persistence_owner_fence as fence,
    persistence_owner_publication_witness as witness,
    persistence_owner_semantics as semantics,
)

# Kept as the existing pure dependency's namespace for compatibility with audit
# guards; no function in this module performs an observation.
os = semantics.r.os
r, storage = semantics.r, semantics.storage
ADMISSION_DOCUMENT = "cmdmesh.proxmox.owner-execution-admission"
MANIFEST_DOCUMENT = "cmdmesh.proxmox.owner-executor-source-manifest"
FILESYSTEM_DOCUMENT = "cmdmesh.proxmox.owner-filesystem-qualification"
SCOPE_PROFILE = "single-cooperating-owner-native-post-normal-return-v1"
CONCLUSION = "no-remaining-original-forward-work-within-selected-cooperating-profile"
EVENT_PROFILE = witness.EVENT_PROFILE
PROBE_DIRECTORY = ".owner-handoff-fs-probe-v1"
PROBE_PAYLOAD = (
    b'{"document_type":"cmdmesh.proxmox.owner-filesystem-probe","schema_version":1}'
)
SDK_ROLES = frozenset(
    {
        "metadata_executor",
        "execution_admission",
        "filesystem",
        "begin",
        "resources",
        "directory",
        "bootstrap",
        "atomic",
        "publication_witness",
        "attempt",
        "attempt_codec",
        "semantics",
        "completion",
        "phase_admission",
        "continuation_v2",
        "current",
        "transition",
        "storage_profile",
    }
)
PRIMITIVES = frozenset(
    {
        "atomic",
        "publication_witness",
        "directory",
        "attempt",
        "resources",
        "bootstrap",
        "storage_profile",
    }
)
ACTIONS = frozenset(
    {
        "begin",
        "finish-runtime",
        "record-intent",
        "publish-marker",
        "record-completion",
        "requalify-complete",
        "inspect",
    }
)
COMPONENTS = frozenset(
    {"sdk", "node", "boundary", "recipe", "controller", "verifier", "transport"}
)
ROLES = frozenset(
    {
        "bootstrap-lock",
        "runtime-directory",
        "runtime-profile",
        "pair-directory",
        "intent",
        "legacy-marker",
        "completion",
    }
)
ADMISSION_LIMIT = 65536
RECORD_LIMIT = 1048576


def require(value, code):
    r.require(value, "execution-admission-" + code)


def _keys(value, keys):
    require(type(value) is dict and set(value) == set(keys), "schema")


def _int(value, low=0, high=2**64 - 1):
    require(type(value) is int and low <= value <= high, "integer")


def _text(value, limit=4096):
    require(
        type(value) is str
        and 0 < len(value) <= limit
        and not any(c in value for c in ("\0", "\r", "\n")),
        "text",
    )


def _path(value, *, root=False):
    _text(value)
    path = PurePosixPath(value)
    require(
        path.is_absolute()
        and str(path) == value
        and ".." not in path.parts
        and (root or value != "/"),
        "path",
    )
    return path


def _same(left, right, code="join"):
    require(r.state.canonical(left) == r.state.canonical(right), code)


def _epoch(value):
    _keys(value, {"boot_id", "mount_namespace"})
    require(
        type(value["boot_id"]) is str
        and re.fullmatch(
            r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value["boot_id"]
        )
        is not None,
        "epoch",
    )
    require(
        type(value["mount_namespace"]) is str
        and re.fullmatch(r"mnt:\[[1-9][0-9]*\]", value["mount_namespace"]) is not None,
        "epoch",
    )


def _stable(value):
    require(type(value) is list and len(value) == 5, "identity")
    for part in value:
        _int(part)
    require(
        value[0] > 0
        and value[1] > 0
        and value[2:] == [stat.S_IFDIR | 0o700, r.legacy.ROOT_UID, r.legacy.ROOT_UID],
        "identity",
    )


def _decode(raw, sha, limit):
    require(type(raw) is bytes and 0 < len(raw) <= limit, "input-size")
    r.state.digest(sha)
    require(r.state.sha256(raw) == sha, "external-hash")
    value = r.observe.decode(raw)
    semantics.codec.admission._json(value)
    require(r.state.canonical(value) == raw, "canonical")
    require(type(value) is dict, "record")
    return value


def _document(value, name, fields):
    _keys(value, {"document_type", "schema_version", *fields})
    require(
        value["document_type"] == name
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1,
        "document",
    )


def _configuration():
    return r.state.canonical(
        dict(
            admission=ADMISSION_DOCUMENT,
            manifest=MANIFEST_DOCUMENT,
            filesystem=FILESYSTEM_DOCUMENT,
            scope=SCOPE_PROFILE,
            conclusion=CONCLUSION,
            event=EVENT_PROFILE,
            probe_directory=PROBE_DIRECTORY,
            payload_sha256=r.state.sha256(PROBE_PAYLOAD),
            sdk_roles=sorted(SDK_ROLES),
            primitives=sorted(PRIMITIVES),
            actions=sorted(ACTIONS),
            components=sorted(COMPONENTS),
            roles=sorted(ROLES),
            admission_limit=ADMISSION_LIMIT,
            record_limit=RECORD_LIMIT,
        )
    )


def destination_roles(selection):
    """Pure fixed destination derivation, never caller-selected target paths."""
    require(type(selection) is semantics.Selection, "selection")
    selection.validate()
    pair = storage.RUNTIME_ROOT / selection._private_binding.pair_key
    return {
        "bootstrap-lock": str(storage.RUNTIME_ROOT.parent / bootstrap.LOCK_NAME),
        "runtime-directory": str(storage.RUNTIME_ROOT),
        "runtime-profile": str(storage.RUNTIME_ROOT / "runtime.json"),
        "pair-directory": str(pair),
        "intent": str(pair / "intent.json"),
        "legacy-marker": str(
            r.legacy.RUNTIME_ROOT / selection._private_binding.pair_key / storage.MARKER
        ),
        "completion": str(pair / "complete.json"),
    }


def _manifest(value):
    _document(value, MANIFEST_DOCUMENT, {"components"})
    _keys(value["components"], COMPONENTS)
    count = 0
    for component, files in value["components"].items():
        require(type(files) is dict, "source-map")
        if component in {"sdk", "boundary", "recipe", "controller"}:
            require(bool(files), "source-map")
        for path, item in files.items():
            count += 1
            require(
                count <= 512 and type(path) is str and 0 < len(path) <= 256,
                "source-budget",
            )
            parts = path.split("/")
            require(
                all(
                    re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", part) is not None
                    for part in parts
                )
                and str(PurePosixPath(path)) == path,
                "source-path",
            )
            _keys(item, {"sha256", "bytes"})
            r.state.digest(item["sha256"])
            _int(item["bytes"], 1, 16777216)
    require(count > 0, "source-map")
    sdk = value["components"]["sdk"]
    require(
        all(
            "plugins/module_utils/persistence_owner_" + role + ".py" in sdk
            for role in SDK_ROLES
        ),
        "source-roles",
    )


def _mount(value):
    _keys(
        value,
        {
            "mount_id",
            "parent_id",
            "device",
            "root",
            "target",
            "filesystem",
            "source",
            "options",
            "super_options",
            "statfs_type",
            "statfs_fsid",
        },
    )
    _int(value["mount_id"], 1)
    _int(value["parent_id"], 1)
    require(type(value["device"]) is list and len(value["device"]) == 2, "device")
    for part in value["device"]:
        _int(part, 0, 2**32 - 1)
    _path(value["root"], root=True)
    _path(value["target"], root=True)
    _text(value["filesystem"], 128)
    _text(value["source"])
    for field in ("options", "super_options"):
        rows = value[field]
        require(
            type(rows) is list
            and len(rows) <= 128
            and all(type(row) is str for row in rows)
            and rows == sorted(set(rows)),
            "mount-options",
        )
        for row in rows:
            _text(row, 4096)
    require(bool(value["options"]), "mount-options")
    _int(value["statfs_type"], 1)
    require(
        type(value["statfs_fsid"]) is list and len(value["statfs_fsid"]) == 2, "fsid"
    )
    for part in value["statfs_fsid"]:
        _int(part, -(2**31), 2**31 - 1)


def _index(value, rows):
    _int(value, 0, len(rows) - 1)
    return rows[value]


def _trace(value):
    _keys(value, {"raw_base64", "bytes", "sha256"})
    _int(value["bytes"], 1, 65536)
    r.state.digest(value["sha256"])
    require(
        type(value["raw_base64"]) is str and len(value["raw_base64"]) <= 87384,
        "trace-size",
    )
    try:
        raw = base64.b64decode(value["raw_base64"], validate=True)
    except (ValueError, binascii.Error):
        raise r.state.PersistenceError(
            "persistence-owner-retirement-execution-admission-trace-base64"
        ) from None
    require(
        base64.b64encode(raw).decode() == value["raw_base64"]
        and len(raw) == value["bytes"]
        and r.state.sha256(raw) == value["sha256"],
        "trace-hash",
    )
    rows = []
    offset = 0
    watch = None
    while offset < len(raw):
        require(len(rows) < 4096 and len(raw) - offset >= 16, "trace-frame")
        wd, mask, cookie, size = struct.unpack_from("iIII", raw, offset)
        require(
            wd >= 0
            and cookie == 0
            and 0 < size <= 4096
            and offset + 16 + size <= len(raw)
            and not mask & (0x400 | 0x800 | 0x2000 | 0x4000 | 0x8000),
            "trace-frame",
        )
        watch = wd if watch is None else watch
        require(wd == watch, "trace-watch")
        name, separator, padding = raw[offset + 16 : offset + 16 + size].partition(
            b"\0"
        )
        require(
            separator
            and not any(padding)
            and 0 < len(name) <= 255
            and not any(c in name for c in (0, 10, 13, 47)),
            "trace-name",
        )
        try:
            name = name.decode("utf-8")
        except UnicodeError:
            raise r.state.PersistenceError(
                "persistence-owner-retirement-execution-admission-trace-name"
            ) from None
        rows.append((name, mask))
        offset += 16 + size
    return rows


def _receipt(value, parent, identity):
    _keys(
        value,
        {
            "path",
            "parent_identity",
            "anonymous_name",
            "before_identity",
            "final_identity",
            "payload_sha256",
            "payload_bytes",
            "protocol",
        },
    )
    require(
        value["path"] == str(parent / "atomic.json")
        and value["protocol"] == storage.PROTOCOL,
        "probe-receipt",
    )
    _same(value["parent_identity"], identity)
    _text(value["anonymous_name"], 255)
    require(
        value["anonymous_name"] not in {".", "..", "atomic.json"}
        and "/" not in value["anonymous_name"],
        "anonymous",
    )
    for field, links in (("before_identity", 0), ("final_identity", 1)):
        info = value[field]
        require(type(info) is list and len(info) == 9, "receipt-identity")
        for part in info:
            _int(part)
        require(
            info[0] == identity[0]
            and info[1] > 0
            and info[2:7]
            == [
                stat.S_IFREG | 0o600,
                r.legacy.ROOT_UID,
                r.legacy.ROOT_UID,
                links,
                len(PROBE_PAYLOAD),
            ],
            "receipt-policy",
        )
    _same(value["before_identity"][:5], value["final_identity"][:5])
    require(
        type(value["payload_bytes"]) is int
        and value["payload_bytes"] == len(PROBE_PAYLOAD)
        and value["payload_sha256"] == r.state.sha256(PROBE_PAYLOAD),
        "probe-payload",
    )


def _probe(value, mounts, common):
    _keys(
        value,
        {
            "parent_path",
            "parent_identity",
            "mount_index",
            "procedure",
            "atomic_receipt",
            "atomic_events",
            "mkdir_events",
            "named_samebyte_events",
            "transient_extra_events",
            "second_link_errno",
            "closed_probe_provenance_sha256",
        },
    )
    parent = _path(value["parent_path"])
    require(
        parent.parent == common / PROBE_DIRECTORY
        and re.fullmatch(r"probe-[a-f0-9]{32}", parent.name) is not None,
        "probe-location",
    )
    _stable(value["parent_identity"])
    require(
        value["procedure"] == "same-mount-disposable-atomic-event-v1"
        and type(value["second_link_errno"]) is int
        and value["second_link_errno"] == 17,
        "procedure",
    )
    r.state.digest(value["closed_probe_provenance_sha256"])
    mount = _index(value["mount_index"], mounts)
    require(
        "rw" in mount["options"]
        and "ro" not in mount["options"]
        and mount["filesystem"] != "proc",
        "probe-mount",
    )
    require(
        os.makedev(*mount["device"]) == value["parent_identity"][0]
        and parent.is_relative_to(PurePosixPath(mount["target"])),
        "probe-device",
    )
    receipt = value["atomic_receipt"]
    _receipt(receipt, parent, value["parent_identity"])
    stage = 0
    modified = False
    for name, mask in _trace(value["atomic_events"]):
        if stage == 0 and (name, mask) == (receipt["anonymous_name"], 2):
            modified = True
        elif stage == 0 and modified and (name, mask) == ("atomic.json", 256):
            stage = 1
        elif stage == 1 and (name, mask) == (receipt["anonymous_name"], 8):
            stage = 2
        else:
            require(False, "atomic-events")
    require(stage == 2, "atomic-events")
    require(
        _trace(value["mkdir_events"]) == [("directory", 0x40000100)], "mkdir-events"
    )
    named = _trace(value["named_samebyte_events"])
    require(named == [("atomic.json", 2), ("atomic.json", 8)], "named-write-events")
    transient = _trace(value["transient_extra_events"])
    require(
        transient
        in (
            [("extra", 256), ("extra", 8), ("extra", 512)],
            [("extra", 256), ("extra", 2), ("extra", 8), ("extra", 512)],
        ),
        "transient-events",
    )


def _filesystem(value, selection, manifest):
    _document(
        value,
        FILESYSTEM_DOCUMENT,
        {
            "subject",
            "publication_protocol",
            "event_profile",
            "runtime_profile_sha256",
            "primitives",
            "qualifier_producer_manifest_sha256",
            "qualifier_provenance_sha256",
            "logic_qualification_sha256",
            "procfs",
            "mounts",
            "probes",
            "roles",
        },
    )
    _keys(value["subject"], {"binding", "host_epoch", "kernel_release", "abi"})
    _same(value["subject"]["binding"], r.asdict(selection._private_binding))
    _epoch(value["subject"]["host_epoch"])
    _text(value["subject"]["kernel_release"], 256)
    require(
        value["subject"]["abi"] == "linux64-procfd-v1"
        and value["publication_protocol"] == storage.PROTOCOL
        and value["event_profile"] == EVENT_PROFILE
        and value["runtime_profile_sha256"] == r.digest(storage.RUNTIME),
        "filesystem-profile",
    )
    for field in (
        "qualifier_producer_manifest_sha256",
        "qualifier_provenance_sha256",
        "logic_qualification_sha256",
    ):
        r.state.digest(value[field])
    _keys(value["primitives"], PRIMITIVES)
    for role, sha in value["primitives"].items():
        require(
            sha
            == manifest["components"]["sdk"][
                "plugins/module_utils/persistence_owner_" + role + ".py"
            ]["sha256"],
            "primitive-source",
        )
    mounts = value["mounts"]
    require(type(mounts) is list and 0 < len(mounts) <= 8, "mount-count")
    for row in mounts:
        _mount(row)
    require(len({row["mount_id"] for row in mounts}) == len(mounts), "mount-duplicate")
    _keys(value["procfs"], {"mount_index", "type_magic"})
    proc = _index(value["procfs"]["mount_index"], mounts)
    require(
        type(value["procfs"]["type_magic"]) is int
        and value["procfs"]["type_magic"] == 0x9FA0
        and proc["statfs_type"] == 0x9FA0
        and proc["filesystem"] == "proc"
        and proc["target"] == "/proc",
        "procfs",
    )
    common = PurePosixPath(str(storage.RUNTIME_ROOT.parent))
    require(common == PurePosixPath(str(r.legacy.RUNTIME_ROOT.parent)), "root-parent")
    probes = value["probes"]
    require(type(probes) is list and 0 < len(probes) <= 7, "probe-count")
    for row in probes:
        _probe(row, mounts, common)
    require(
        len({row["parent_path"] for row in probes}) == len(probes), "probe-duplicate"
    )
    _keys(value["roles"], ROLES)
    destinations = destination_roles(selection)
    intent = r._intent(
        selection._private_binding, selection._intent_raw, selection._intent_sha256
    )
    for role, row in value["roles"].items():
        _keys(
            row,
            {
                "destination",
                "parent",
                "ancestor_path",
                "ancestor_identity",
                "missing_suffix",
                "mount_index",
                "probe_index",
            },
        )
        require(row["destination"] == destinations[role], "role-destination")
        parent = _path(row["parent"])
        ancestor = _path(row["ancestor_path"])
        require(
            parent == PurePosixPath(destinations[role]).parent
            and parent.is_relative_to(ancestor),
            "role-parent",
        )
        suffix = row["missing_suffix"]
        require(
            type(suffix) is list
            and len(suffix) <= 2
            and suffix == list(parent.relative_to(ancestor).parts),
            "role-absence",
        )
        _stable(row["ancestor_identity"])
        if role == "legacy-marker":
            require(ancestor == parent and suffix == [], "legacy-ancestor")
            _same(row["ancestor_identity"], intent["basis"]["directories"][""])
        else:
            require(
                ancestor
                in {
                    common,
                    PurePosixPath(str(storage.RUNTIME_ROOT)),
                    PurePosixPath(
                        str(storage.RUNTIME_ROOT / selection._private_binding.pair_key)
                    ),
                },
                "role-ancestor",
            )
            if ancestor == common:
                _same(
                    row["ancestor_identity"], intent["shared_directories"][str(common)]
                )
        mount = _index(row["mount_index"], mounts)
        probe = _index(row["probe_index"], probes)
        require(
            row["mount_index"] == probe["mount_index"]
            and os.makedev(*mount["device"]) == row["ancestor_identity"][0]
            and ancestor.is_relative_to(PurePosixPath(mount["target"])),
            "role-mount",
        )


def _historical(value, selection, authority, captured, result):
    hashes = {
        "decision_sha256",
        "h0_acceptance_sha256",
        "authority_sha256",
        "causal_capture_sha256",
        "actor_capture_sha256",
        "closed_observation_sha256",
        "review_sha256",
        "source_assessment_sha256",
        "historical_producer_cohort_sha256",
        "source_profile_sha256",
        "prepared_sha256",
        "failure_provenance_sha256",
        "basis_sha256",
        "predecessor_sha256",
        "pending_head_sha256",
    }
    _keys(value, {*hashes, "host_epoch", "candidate_upid", "interval"})
    for name in hashes:
        r.state.digest(value[name])
    _epoch(value["host_epoch"])
    _keys(value["interval"], {"before_current_sha256", "closing_current_sha256"})
    for key in value["interval"]:
        r.state.digest(value["interval"][key])
    intent = r._intent(
        selection._private_binding, selection._intent_raw, selection._intent_sha256
    )
    evidence = intent["caller_evidence"]
    expected = dict(
        decision_sha256=evidence["worker_fence_sha256"],
        authority_sha256=result["authority_sha256"],
        causal_capture_sha256=result["capture_sha256"],
        actor_capture_sha256=r.digest(captured["actors"]),
        source_profile_sha256=r.digest(authority["source_profile"]),
        prepared_sha256=authority["resume_prepared_sha256"],
        failure_provenance_sha256=authority["failure_provenance_sha256"],
        basis_sha256=r.digest(intent["basis"]),
        predecessor_sha256=intent["anchor"]["sha256"],
        pending_head_sha256=intent["basis"]["head_sha256"],
        host_epoch=evidence["host_epoch"],
        candidate_upid=result["candidate_upid"],
    )
    for key, want in expected.items():
        _same(value[key], want, "historical-join")
    require(
        value["source_profile_sha256"] == evidence["source_manifest_sha256"]
        and value["prepared_sha256"] == evidence["accepted_prepared_sha256"]
        and value["failure_provenance_sha256"] == evidence["failure_provenance_sha256"]
        and value["basis_sha256"] == authority["legacy_basis_sha256"]
        and value["predecessor_sha256"] == result["predecessor_sha256"]
        and value["pending_head_sha256"] == result["pending_head_sha256"],
        "historical-join",
    )
    _same(value["host_epoch"], result["host_epoch"])
    for side in ("before", "closing"):
        require(
            value["interval"][side + "_current_sha256"]
            == r.digest(captured[side]["current"]),
            "historical-interval",
        )
    # H0 acceptance/review/producer/exporter refs are external accepted claims,
    # not self-authenticating source facts or fresh-current authority.


def _validate(selection, action, raws):
    require(
        type(selection) is semantics.Selection
        and type(action) is str
        and action in ACTIONS,
        "selection-action",
    )
    selection.validate()
    config = _configuration()
    names = (
        "admission",
        "historical_authority",
        "historical_capture",
        "producer_manifest",
        "filesystem_qualification",
    )
    limits = (
        ADMISSION_LIMIT,
        fence.AUTHORITY_LIMIT,
        fence.CAPTURE_LIMIT,
        RECORD_LIMIT,
        RECORD_LIMIT,
    )
    decoded = {
        name: _decode(raw, sha, limit)
        for name, (raw, sha), limit in zip(names, raws, limits)
    }
    admission, authority, captured, manifest, filesystem = (
        decoded[name] for name in names
    )
    _document(
        admission,
        ADMISSION_DOCUMENT,
        {
            "subject",
            "scope_profile",
            "conclusion",
            "historical_profile_id",
            "historical",
            "execution",
            "arbitrary_root_or_cli_excluded",
            "registry_archive_complete",
            "original_native_operation_qualified",
            "ack_recovered",
        },
    )
    _keys(
        admission["subject"],
        {
            "binding",
            "checkpoint_sha256",
            "intent_sha256",
            "publication_contract_sha256",
        },
    )
    _same(
        admission["subject"],
        dict(
            binding=r.asdict(selection._private_binding),
            checkpoint_sha256=selection.checkpoint_sha256,
            intent_sha256=selection._intent_sha256,
            publication_contract_sha256=selection.contract_sha256,
        ),
    )
    require(
        admission["scope_profile"] == SCOPE_PROFILE
        and admission["conclusion"] == CONCLUSION
        and admission["historical_profile_id"] == fence.PROFILE
        and admission["arbitrary_root_or_cli_excluded"] is True
        and all(
            admission[name] is False
            for name in (
                "registry_archive_complete",
                "original_native_operation_qualified",
                "ack_recovered",
            )
        ),
        "scope",
    )
    _manifest(manifest)
    _filesystem(filesystem, selection, manifest)
    result = fence.validate_causal_capture(
        raws[1][0], raws[1][1], raws[2][0], raws[2][1]
    )
    require(
        result["checkpoint_sha256"] == selection.checkpoint_sha256,
        "historical-checkpoint",
    )
    _historical(admission["historical"], selection, authority, captured, result)
    execution = admission["execution"]
    _keys(
        execution,
        {
            "producer_manifest_sha256",
            "filesystem_qualification_sha256",
            "allowed_actions",
            "completion_schema_version",
            "runtime_profile_sha256",
            "publication_protocol",
            "event_profile",
            "native_action_dispatched",
            "successor_native_admission_authorized",
        },
    )
    actions = execution["allowed_actions"]
    require(
        type(actions) is list
        and 0 < len(actions) <= len(ACTIONS)
        and all(type(item) is str and item in ACTIONS for item in actions)
        and actions == sorted(set(actions))
        and action in actions,
        "allowed-actions",
    )
    contract = r._decode(selection._contract_raw, selection.contract_sha256)
    require(
        execution["producer_manifest_sha256"]
        == raws[3][1]
        == contract["source_manifest_sha256"]
        and execution["filesystem_qualification_sha256"] == raws[4][1]
        and type(execution["completion_schema_version"]) is int
        and execution["completion_schema_version"] == 2
        and execution["runtime_profile_sha256"] == r.digest(storage.RUNTIME)
        and execution["publication_protocol"] == storage.PROTOCOL
        and execution["event_profile"] == EVENT_PROFILE
        and execution["native_action_dispatched"] is False
        and execution["successor_native_admission_authorized"] is False,
        "execution",
    )
    selection.validate()
    for name, (raw, _sha) in zip(names, raws):
        require(r.state.canonical(decoded[name]) == raw, "decoded-memory")
    require(_configuration() == config, "configuration")
    selection._memory()


@dataclass(frozen=True, slots=True)
class Admission:
    selection: semantics.Selection = field(repr=False)
    action: str
    admission_raw: bytes = field(repr=False)
    admission_sha256: str
    historical_authority_raw: bytes = field(repr=False)
    historical_authority_sha256: str
    historical_capture_raw: bytes = field(repr=False)
    historical_capture_sha256: str
    producer_manifest_raw: bytes = field(repr=False)
    producer_manifest_sha256: str
    filesystem_qualification_raw: bytes = field(repr=False)
    filesystem_qualification_sha256: str
    _fixed: tuple = field(repr=False)
    _configuration_raw: bytes = field(repr=False)

    def _values(self):
        return (
            self.action,
            self.admission_raw,
            self.admission_sha256,
            self.historical_authority_raw,
            self.historical_authority_sha256,
            self.historical_capture_raw,
            self.historical_capture_sha256,
            self.producer_manifest_raw,
            self.producer_manifest_sha256,
            self.filesystem_qualification_raw,
            self.filesystem_qualification_sha256,
        )

    def _snapshot(self):
        require(
            type(self) is Admission
            and type(self._fixed) is tuple
            and len(self._fixed) == 12
            and type(self._configuration_raw) is bytes
            and type(self.action) is str
            and type(self.selection) is semantics.Selection
            and self.selection is self._fixed[0]
            and self._values() == self._fixed[1:]
            and _configuration() == self._configuration_raw,
            "admission-memory",
        )
        for value in self._values()[1::2]:
            require(type(value) is bytes, "snapshot-type")
        for value in self._values()[2::2]:
            r.state.digest(value)

    def _memory(self):
        self._snapshot()
        self.selection._memory()
        self._snapshot()

    def validate(self):
        """Reclose fixed records/Selection; still no IO/source/FS permission."""
        self._memory()
        values = self._values()
        _validate(self.selection, self.action, tuple(zip(values[1::2], values[2::2])))
        self._memory()


def load_execution_admission(
    *,
    selection,
    admission_raw,
    admission_sha256,
    historical_authority_raw,
    historical_authority_sha256,
    historical_capture_raw,
    historical_capture_sha256,
    producer_manifest_raw,
    producer_manifest_sha256,
    filesystem_qualification_raw,
    filesystem_qualification_sha256,
    action
):
    """Load externally selected assertions; never select authority from a node."""
    values = (
        action,
        admission_raw,
        admission_sha256,
        historical_authority_raw,
        historical_authority_sha256,
        historical_capture_raw,
        historical_capture_sha256,
        producer_manifest_raw,
        producer_manifest_sha256,
        filesystem_qualification_raw,
        filesystem_qualification_sha256,
    )
    fixed = (selection, *values)
    config = _configuration()
    _validate(selection, action, tuple(zip(values[1::2], values[2::2])))
    document = Admission(selection, *values, fixed, config)
    document._memory()
    return document
