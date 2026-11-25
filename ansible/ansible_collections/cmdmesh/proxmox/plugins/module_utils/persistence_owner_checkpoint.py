"""Decode accepted writer evidence without current admission or lifecycle IO.

The full historical runtime remains evidence. Consumers must separately admit
current ownership, host epoch, guest state and application exclusion before any
operation; an old kernel/process observation is not a current target binding.
"""

from dataclasses import fields
import json
import os
from pathlib import PurePosixPath
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_writer_execution as writer,
)

state, trial, runtime = writer.state, writer.trial, writer.runtime
DOCUMENT = "cmdmesh.proxmox.persistence.owner-checkpoint"
ROOT_UID = 0
COMPLETION_FIELDS = frozenset(
    {
        "prepared_sha256",
        "phase",
        "runtime",
        "before",
        "after",
        "peer",
        "append_result",
        "journal_files",
        "phase_journal_sha256",
        "runtime_profile",
        "claim_directory_identity",
        "mutation_attempted",
        "application_quiesced",
        "application_write_verified",
        "rebuild_verified",
        "boot_verified",
        "restore_verified",
        "backup_verified",
    }
)


def require(value, code):
    state.require(value, "persistence-owner-checkpoint-" + code)


def _decode(raw, trusted):
    state.digest(trusted)
    require(type(raw) is bytes and 0 < len(raw) <= 4194304, "payload")
    require(state.sha256(raw) == trusted, "hash")
    value = json.loads(raw)
    require(state.canonical(value) == raw, "canonical")
    return value


def _directory(identity):
    require(
        type(identity) is list
        and len(identity) == 5
        and all(type(value) is int and value >= 0 for value in identity)
        and identity[0] > 0
        and identity[1] > 0
        and identity[2:] == [stat.S_IFDIR | 0o700, ROOT_UID, ROOT_UID],
        "directory",
    )


def _file(value, path, checksum, size, *, legacy=False):
    state.keys(value, {"path", "sha256", "identity"})
    state.digest(checksum)
    state.integer(size, 1, 4194304)
    require(value["path"] == path and value["sha256"] == checksum, "file-binding")
    identity = value["identity"]
    require(
        type(identity) is list
        and len(identity) == 9
        and all(type(part) is int and part >= 0 for part in identity)
        and identity[0] > 0
        and identity[1] > 0
        and identity[2]
        in (
            {stat.S_IFREG | 0o600, stat.S_IFREG | 0o644}
            if legacy
            else {stat.S_IFREG | 0o600}
        )
        and identity[3:7] == [ROOT_UID, ROOT_UID, 1, size],
        "file-identity",
    )


def _historical_metadata(prepared):
    own = prepared["boot_runtime"]
    _directory(own["directory"])
    profile_raw = state.canonical(writer.boot.PROFILE)
    _file(
        own["file"],
        str(writer.boot.RUNTIME_ROOT / "profile.json"),
        state.sha256(profile_raw),
        len(profile_raw),
    )
    for path, frame in prepared["history"]["directories"].items():
        identity = frame["identity"]
        require(
            type(identity) is list
            and len(identity) == 9
            and all(type(part) is int and part >= 0 for part in identity)
            and identity[5] >= 2,
            "historical-directory",
        )
        _directory(identity[:5])
        for name, item in frame["files"].items():
            _file(
                item,
                path + "/" + name,
                item["sha256"],
                item["identity"][6],
                legacy=name == "legacy-guard.py",
            )
    for path, item in prepared["history"]["files"].items():
        _file(
            item,
            path,
            item["sha256"],
            item["identity"][6],
            legacy=PurePosixPath(path).name == "legacy-guard.py",
        )


def _peer(prepared, frame, value):
    kind = writer.active.unix_peer.ProcessIdentity
    state.keys(value, {field.name for field in fields(kind)})
    parsed = dict(value)
    for key in ("nspid", "root", "executable", "argv"):
        require(type(parsed[key]) is list, "peer-shape")
        parsed[key] = tuple(parsed[key])
    peer = kind(**parsed)
    writer._base_compatible(prepared, frame)
    mapping = prepared["source_request"]["policy"]["mapping"]
    init = frame["kernel"]["init"]
    require(
        peer.uid == mapping["offset"] + mapping["uid"]
        and peer.gid == mapping["offset"] + mapping["gid"]
        and peer.pid != init["pid"]
        and peer.birth >= init["pstart"]
        and peer.pid_namespace == init["pid_namespace_inode"]
        and peer.nspid == (peer.pid, writer.active.process.main_pid(frame["image"]))
        and peer.argv == writer.active.process.ARGV
        and peer.root[0] == os.makedev(*frame["kernel"]["rootfs"]["device"])
        and peer.cgroup
        == frame["kernel"]["cgroup"]["path"].rsplit("/", 1)[0]
        + "/system.slice/reference-ledger.service\n",
        "peer-binding",
    )


def load_writer_checkpoint(
    *, prepared_raw, prepared_sha256, completion_raw, completion_sha256, records
):
    """Accept only a previously successful externally trusted writer receipt.

    ``records`` contains the 12 raw journal records and complete.json. No file,
    status, process or network observation is performed. Receipt hashes must
    come from successful controller output, never a failed target's candidate.
    """
    require(
        type(prepared_raw) is bytes and 0 < len(prepared_raw) <= 8388608, "preparation"
    )
    prepared = trial.decode_prepared(prepared_raw, prepared_sha256)
    _historical_metadata(prepared)
    completed = _decode(completion_raw, completion_sha256)
    state.keys(completed, COMPLETION_FIELDS)
    require(
        completed["prepared_sha256"] == prepared_sha256
        and completed["phase"] == "retained-application-rebuilt"
        and all(
            completed[key] is True
            for key in (
                "mutation_attempted",
                "application_quiesced",
                "application_write_verified",
                "rebuild_verified",
            )
        )
        and all(
            completed[key] is False
            for key in ("boot_verified", "restore_verified", "backup_verified")
        ),
        "completion",
    )
    runtime.validate(
        prepared["source_request"],
        prepared["image_profile"],
        "os_quiesced",
        completed["runtime"],
    )
    writer._postcondition(prepared, completed["runtime"], completed["after"])
    state.keys(records, writer.NAMES | {"complete.json"})
    require(
        all(type(raw) is bytes and 0 < len(raw) <= 4194304 for raw in records.values())
        and sum(map(len, records.values())) <= 16777216
        and records["complete.json"] == completion_raw,
        "records",
    )
    state.keys(completed["journal_files"], writer.NAMES)
    directory = str(trial.claim_path(prepared["source_request"]))
    for name, item in completed["journal_files"].items():
        raw = records[name]
        _file(item, directory + "/" + name, state.sha256(raw), len(raw))
    require(
        completed["phase_journal_sha256"]
        == state.sha256(state.canonical(completed["journal_files"])),
        "journal-hash",
    )
    decoded = {
        name: _decode(records[name], state.sha256(records[name]))
        for name in writer.NAMES
    }
    writer.validate_records(prepared, prepared_sha256, decoded, completed)
    _peer(prepared, decoded["stop-admission.json"], completed["peer"])
    _directory(completed["claim_directory_identity"])
    own = completed["runtime_profile"]
    state.keys(own, {"directory", "file"})
    _directory(own["directory"])
    profile_raw = state.canonical(trial.PROFILE)
    _file(
        own["file"],
        str(trial.RUNTIME_ROOT / "profile.json"),
        state.sha256(profile_raw),
        len(profile_raw),
    )
    return {
        "document_type": DOCUMENT,
        "schema_version": 1,
        "prepared": prepared,
        "completion": completed,
        "prepared_sha256": prepared_sha256,
        "completion_sha256": completion_sha256,
    }
