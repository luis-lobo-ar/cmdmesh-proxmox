#!/usr/bin/env python3
"""Measure a disposable sibling filesystem probe; emit an unaccepted candidate.

Use a source-only collection on PYTHONPATH. The controller authenticates this
program, selected inputs, source/transport and closed result before building a
separate qualification record. No future receipt hash is embedded here.
"""

import argparse
import errno
import os
from pathlib import Path
import stat
import sys
import uuid
from dataclasses import dataclass

if sys.flags.optimize:
    raise ValueError("ordinary Python required before SDK or input loading")

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_atomic as atomic,
    persistence_owner_attempt as attempt,
    persistence_owner_bootstrap as bootstrap,
    persistence_owner_continuation as continuation,
    persistence_owner_current as current,
    persistence_owner_directory as directory,
    persistence_owner_execution_admission as admission_codec,
    persistence_owner_filesystem as filesystem,
    persistence_owner_publication_witness as publication,
    persistence_owner_resources as resources,
    persistence_owner_semantics as semantics,
    persistence_owner_storage_profile as storage,
    persistence_owner_transition as transition,
)

r = semantics.r


def require(value, code):
    r.require(value, "filesystem-probe-" + code)


@dataclass(frozen=True, slots=True)
class ProbeCandidate:
    raw: bytes
    sha256: str


def _candidate(value):
    raw = r.state.canonical(value)
    require(0 < len(raw) <= 65536, "output-limit")
    return ProbeCandidate(raw, r.state.sha256(raw))


def _trace(raw):
    import base64

    return dict(
        raw_base64=base64.b64encode(raw).decode(),
        bytes=len(raw),
        sha256=r.state.sha256(raw),
    )


def _drain(fd):
    result = bytearray()
    for unused in range(8):
        try:
            part = os.read(fd, 65536 - len(result))
        except BlockingIOError:
            return bytes(result)
        require(part and len(result) + len(part) < 65536, "event-limit")
        result.extend(part)
    require(False, "event-limit")


def _failed_link_events(raw):
    rows = admission_codec._trace(_trace(raw))
    require(2 <= len(rows) <= 16, "second-link-events")
    name = rows[0][0]
    require(
        name not in {"atomic.json", "directory", "extra"}
        and all(item == (name, 2) for item in rows[:-1])
        and rows[-1] == (name, 8),
        "second-link-events",
    )


def _members(fd):
    names = []
    with os.scandir(fd) as entries:
        for item in entries:
            require(len(names) < 3, "membership-budget")
            names.append(item.name)
    return sorted(names)


def _identity(path):
    return attempt._identity(path.lstat())


def _owned_directory(fd, parent_fd, name):
    value = attempt._identity(os.fstat(fd))
    require(
        value[2:5] == [stat.S_IFDIR | 0o700, r.legacy.ROOT_UID, r.legacy.ROOT_UID]
        and value
        == attempt._identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)),
        "directory-binding",
    )
    return value


def _unchanged_payload(path, expected):
    raw, info = r.observe.read_regular(path, 4096)
    require(
        attempt._identity(info) == expected and raw == admission_codec.PROBE_PAYLOAD,
        "probe-file",
    )


def _primitive_sources():
    result = {}
    for name, module in dict(
        atomic=atomic,
        publication_witness=publication,
        directory=directory,
        attempt=attempt,
        resources=resources,
        bootstrap=bootstrap,
        storage_profile=storage,
    ).items():
        path = Path(module.__file__)
        require(
            path.resolve(strict=True) == path and path.suffix == ".py", "source-only"
        )
        before = _identity(path)
        require(
            stat.S_ISREG(before[2]) and before[5] == 1 and 0 < before[6] <= 16777216,
            "source-file",
        )
        raw = path.read_bytes()
        require(_identity(path) == before, "source-changed")
        result[name] = dict(sha256=r.state.sha256(raw), identity=before)
    return result


def _sample(selection, subject):
    """Actual source-owned diagnostic nodes; never any protocol destination."""
    facts = r.observe.decode(subject.raw)
    common = storage.RUNTIME_ROOT.parent
    indices = {row["mount_index"] for row in facts["roles"].values()}
    require(len(indices) == 1, "same-mount-profile-unavailable")
    mount_index = next(iter(indices))
    expected_mount = facts["mounts"][mount_index]
    common_fd = subject._reader.nodes[str(common)]["fd"]
    require(
        filesystem.fd_mount_id(common_fd) == expected_mount["mount_id"], "common-mount"
    )
    base = common / admission_codec.PROBE_DIRECTORY
    base_created = False
    try:
        os.mkdir(base.name, 0o700, dir_fd=common_fd)
        base_created = True
    except FileExistsError as error:
        require(error.errno == errno.EEXIST, "probe-base")
    base_fd = os.open(
        base.name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=common_fd,
    )
    reader = None
    probe = base / ("probe-" + uuid.uuid4().hex)
    created = False
    initial = None
    file_identity = directory_identity = None
    primary = None
    try:
        _owned_directory(base_fd, common_fd, base.name)
        require(
            filesystem.fd_mount_id(base_fd) == expected_mount["mount_id"], "base-mount"
        )
        os.mkdir(probe.name, 0o700, dir_fd=base_fd)
        created = True
        reader = resources._Seal(selection._private_binding.pair_key)
        fd = reader._directory(probe, private=True)
        initial = _owned_directory(fd, base_fd, probe.name)
        os.fsync(base_fd)
        require(
            filesystem.fd_mount_id(fd) == expected_mount["mount_id"]
            and filesystem.statfs(fd)
            == {key: expected_mount[key] for key in ("statfs_type", "statfs_fsid")},
            "probe-mount",
        )
        require(_members(fd) == [], "initial-membership")
        reader._watch(fd, ("owned", ""))
        reader.freeze_fds()
        require(_drain(reader.event) == b"", "initial-events")
        path = probe / "atomic.json"
        receipt = atomic.publish_observed(
            path, admission_codec.PROBE_PAYLOAD, protocol=storage.PROTOCOL
        )
        file_identity = list(receipt.final_identity)
        atomic_events = _drain(reader.event)
        _unchanged_payload(path, file_identity)
        try:
            atomic.publish_observed(
                path, admission_codec.PROBE_PAYLOAD, protocol=storage.PROTOCOL
            )
        except FileExistsError as error:
            require(
                error.errno == errno.EEXIST and error.filename == str(path),
                "second-link",
            )
        else:
            require(False, "second-link")
        second_events = _drain(reader.event)
        _failed_link_events(second_events)
        _unchanged_payload(path, file_identity)

        os.mkdir("directory", 0o700, dir_fd=fd)
        child = os.open(
            "directory",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=fd,
        )
        try:
            directory_identity = _owned_directory(child, fd, "directory")
            os.fsync(child)
            os.fsync(fd)
        finally:
            os.close(child)
        mkdir_events = _drain(reader.event)

        named = os.open(
            "atomic.json", os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd
        )
        try:
            require(attempt._identity(os.fstat(named)) == file_identity, "named-file")
            require(
                os.pwrite(named, admission_codec.PROBE_PAYLOAD, 0)
                == len(admission_codec.PROBE_PAYLOAD),
                "named-write",
            )
            os.fsync(named)
            after = attempt._identity(os.fstat(named))
            require(after[:7] == file_identity[:7], "named-file")
            file_identity = after
        finally:
            os.close(named)
        named_events = _drain(reader.event)
        _unchanged_payload(path, file_identity)

        extra = os.open(
            "extra",
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=fd,
        )
        extra_identity = None
        try:
            require(os.write(extra, b"x") == 1, "extra-write")
            os.fsync(extra)
            extra_identity = attempt._identity(os.fstat(extra))
        finally:
            os.close(extra)
        require(_identity(probe / "extra") == extra_identity, "extra-file")
        os.unlink("extra", dir_fd=fd)
        os.fsync(fd)
        extra_events = _drain(reader.event)

        measurement = r.observe.decode(
            r.state.canonical(
                dict(
                    parent_path=str(probe),
                    parent_identity=initial[:5],
                    mount_index=mount_index,
                    procedure="same-mount-disposable-atomic-event-v1",
                    atomic_receipt=r.asdict(receipt),
                    atomic_events=_trace(atomic_events),
                    mkdir_events=_trace(mkdir_events),
                    named_samebyte_events=_trace(named_events),
                    transient_extra_events=_trace(extra_events),
                    second_link_errno=errno.EEXIST,
                )
            )
        )
        # Validate the measured grammar in isolation. This local digest names
        # the procedure sample, NOT external provenance or accepted authority.
        admission_codec._probe(
            {**measurement, "closed_probe_provenance_sha256": r.digest(measurement)},
            facts["mounts"],
            common,
        )
        require(_members(fd) == ["atomic.json", "directory"], "final-membership")
        require(
            _owned_directory(fd, base_fd, probe.name)[:5] == initial[:5], "probe-parent"
        )
        result = dict(
            probe=measurement,
            second_link_events=_trace(second_events),
            base_created=base_created,
            filesystem_subject=facts,
        )
    except BaseException as error:
        primary = error
        raise
    finally:
        exit_error = primary
        try:
            if created:
                require(initial is not None, "cleanup-unbound-directory")
                require(
                    _owned_directory(fd, base_fd, probe.name)[:5] == initial[:5],
                    "cleanup-probe-binding",
                )
                if file_identity is not None:
                    _unchanged_payload(probe / "atomic.json", file_identity)
                    os.unlink("atomic.json", dir_fd=reader.nodes[str(probe)]["fd"])
                if directory_identity is not None:
                    require(
                        _identity(probe / "directory") == directory_identity,
                        "cleanup-directory",
                    )
                    os.rmdir("directory", dir_fd=reader.nodes[str(probe)]["fd"])
                # An unaccepted post-link final or unknown child prevents this
                # removal. Preserve it; never adopt or recursively delete it.
                os.rmdir(probe.name, dir_fd=base_fd)
                os.fsync(base_fd)
                try:
                    os.stat(probe.name, dir_fd=base_fd, follow_symlinks=False)
                except FileNotFoundError as error:
                    require(error.errno == errno.ENOENT, "cleanup-absence")
                else:
                    require(False, "cleanup-absence")
        except BaseException as error:
            if exit_error is None:
                exit_error = error
            else:
                exit_error.add_note("diagnostic residue preserved; cleanup unqualified")
        try:
            if reader is not None:
                reader.release()
        except BaseException as error:
            if exit_error is None:
                exit_error = error
            else:
                exit_error.add_note("secondary probe observer release failure")
        try:
            os.close(base_fd)
        except BaseException as error:
            if exit_error is None:
                exit_error = error
            else:
                exit_error.add_note("secondary probe base descriptor close failure")
        if primary is None and exit_error is not None:
            raise exit_error
    return {**result, "owned_probe_removed": True}


def _measure(selection):
    """Private filesystem-only procedure, with no native/current qualification."""
    require(type(selection) is semantics.Selection, "selection")
    selection.validate()
    require(os.geteuid() == os.getegid() == r.legacy.ROOT_UID, "owner")
    sources = _primitive_sources()
    args = dict(
        binding=selection._original_binding,
        checkpoint=selection._original_checkpoint,
        checkpoint_sha256=selection.checkpoint_sha256,
        intent_raw=selection._intent_raw,
        intent_sha256=selection._intent_sha256,
        contract_raw=selection._contract_raw,
        contract_sha256=selection.contract_sha256,
    )
    with attempt.inspect_attempt_v2(**args) as before, filesystem.observe_subject(
        selection
    ) as subject:
        first = r.observe.decode(before.raw)
        require(first["status"] != "blocked", "blocked-namespace")
        projection = r.digest(continuation._projection(first))
        measured = _sample(selection, subject)
        with attempt.inspect_attempt_v2(**args) as after:
            require(
                r.digest(continuation._projection(r.observe.decode(after.raw)))
                == projection,
                "namespace-changed",
            )
        subject.check_memberships()
        before.seal.check_memberships()
        subject.close_named()
        before.seal.close_named()
        subject.check_events()
        before.seal.check_events()
    require(_primitive_sources() == sources, "source-changed")
    selection._memory()
    return _candidate(
        dict(
            document_type="cmdmesh.proxmox.owner-filesystem-probe-candidate",
            schema_version=1,
            checkpoint_sha256=selection.checkpoint_sha256,
            intent_sha256=selection._intent_sha256,
            publication_contract_sha256=selection.contract_sha256,
            primitive_source_sha256={
                name: item["sha256"] for name, item in sources.items()
            },
            namespace_projection_sha256=projection,
            **measured,
            candidate_only=True,
            producer_authenticated=False,
            filesystem_qualified=False,
            application_database_read=False,
            native_lifecycle_action_dispatched=False,
            handoff_writes_performed=False
        )
    )


def probe_filesystem(
    selection,
    *,
    phase,
    prior_runtime_raw=None,
    prior_runtime_sha256=None,
    allow_probe=False,
    check_mode=False
):
    """Own real leases, run the finite probe, return only after every exit."""
    require(
        type(allow_probe) is bool
        and allow_probe is True
        and type(check_mode) is bool
        and check_mode is False,
        "explicit-probe-permission",
    )
    require(
        type(selection) is semantics.Selection
        and type(phase) is str
        and phase in {"os_quiesced", "stopped"},
        "selection-phase",
    )
    selection.validate()
    prior = None
    if prior_runtime_raw is not None or prior_runtime_sha256 is not None:
        prior = admission_codec._decode(
            prior_runtime_raw, prior_runtime_sha256, r.LIMIT
        )
        current.validate_current(
            selection._private_checkpoint,
            "os_quiesced",
            dict(phase="os_quiesced", observation=prior, guest_image_verified=True),
        )
    require(phase != "stopped" or prior is not None, "stopped-prior-required")
    with transition._leased(selection._private_checkpoint, phase, prior) as scope:
        require(scope.pending is None, "unexpected-pending")
        with resources.hold_owner_resources(
            selection=selection, entry=scope.entry, action="inspect"
        ) as held:
            result = _measure(selection)
            current._same_entry(
                scope.entry,
                current._entry_leased(selection._private_checkpoint, phase, prior),
            )
            held.database.close_named()
            held.check_memberships()
            held.close_named()
            held.check_events()
        require(scope.pending is None, "unexpected-pending")
    selection._memory()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--allow-probe", action="store_true")
    parser.add_argument("--check-mode", action="store_true")
    args = parser.parse_args()
    require(args.allow_probe and not args.check_mode, "explicit-probe-permission")
    raw = filesystem._bounded(args.inputs, 33554432)
    value = r.observe.decode(raw)
    semantics.codec.admission._json(value)
    r.state.keys(
        value,
        {
            "binding",
            "checkpoint",
            "checkpoint_sha256",
            "intent_raw",
            "intent_sha256",
            "contract_raw",
            "contract_sha256",
            "phase",
            "prior_runtime_raw",
            "prior_runtime_sha256",
        },
    )
    binding = r.legacy.Binding(
        value["binding"]["pair_key"],
        value["binding"]["authority_sha256"],
        r.legacy.api.GuestBinding(**value["binding"]["guest"]),
    )
    selected = semantics.select(
        binding=binding,
        checkpoint=value["checkpoint"],
        checkpoint_sha256=value["checkpoint_sha256"],
        intent_raw=value["intent_raw"].encode(),
        intent_sha256=value["intent_sha256"],
        contract_raw=value["contract_raw"].encode(),
        contract_sha256=value["contract_sha256"],
    )
    prior = value["prior_runtime_raw"]
    result = probe_filesystem(
        selected,
        phase=value["phase"],
        prior_runtime_raw=None if prior is None else prior.encode(),
        prior_runtime_sha256=value["prior_runtime_sha256"],
        allow_probe=args.allow_probe,
        check_mode=args.check_mode,
    )
    sys.stdout.buffer.write(result.raw + b"\n")


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    os.umask(0o077)
    main()
