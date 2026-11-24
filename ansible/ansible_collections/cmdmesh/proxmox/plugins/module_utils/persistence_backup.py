"""Finite stopped-reference backup action, with no adoption or destructive retry.

Preparation is read-only. Execution consumes its separately trusted prepared
hash, then journals before snapshots/NAS writes. An unfinished operation blocks
the pair until reconciliation. Only a closing-checked completion can supply the
manifest hash trusted by a future restore; NAS contents cannot supply that trust.
"""

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
import subprocess

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_observe as observe,
)
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_state as state,
)
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_stream as stream,
)

RUNTIME_ROOT = Path("/var/lib/cmdmesh/persistence")
TOOL_PATHS = {"age": "/usr/bin/age", "zfs": "/usr/sbin/zfs"}
PREPARED = "cmdmesh.proxmox.persistence.prepared-backup"
COMPLETE = "cmdmesh.proxmox.persistence.completed-backup"
PROFILE = {"document_type": "cmdmesh.proxmox.persistence.runtime", "schema_version": 1}
LIMIT = 1048576


def require(value, code):
    state.require(value, "persistence-backup-" + code)


def validate_request(request):
    state.keys(
        request,
        {"schema_version", "operation_id", "source_request", "tools", "recipient"},
    )
    require(
        type(request["schema_version"]) is int and request["schema_version"] == 1,
        "version",
    )
    state.digest(request["operation_id"])
    source = request["source_request"]
    require(
        type(source) is dict and type(source.get("policy")) is dict, "source-request"
    )
    state.source_identity(source.get("source"))
    state.pair_key(source["policy"].get("datasets"))
    state.keys(request["tools"], {"age", "zfs"})
    for name, reference in request["tools"].items():
        state.keys(reference, {"path", "sha256"})
        require(reference["path"] == TOOL_PATHS[name], "tool-path")
        state.digest(reference["sha256"])
    require(
        state.matches(
            r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}", request["recipient"]
        ),
        "recipient",
    )


def check_tools_and_recipient(request):
    paths = {
        name: stream.tool(reference) for name, reference in request["tools"].items()
    }
    # Fixed empty, nonsecret input has bounded standard-age output. This checks
    # its actual recipient parser before any snapshot/NAS mutation.
    try:
        result = subprocess.run(
            [paths["age"], "--encrypt", "--recipient", request["recipient"]],
            input=b"",
            capture_output=True,
            timeout=5,
            env=stream.ENV,
            umask=0o077,
        )
    except (OSError, subprocess.SubprocessError):
        raise state.PersistenceError(
            "persistence-backup-recipient-unavailable"
        ) from None
    require(
        result.returncode == 0
        and not result.stderr
        and 0 < len(result.stdout) <= 1024
        and result.stdout.startswith(b"age-encryption.org/v1\n"),
        "recipient",
    )
    for reference in request["tools"].values():
        stream.tool(reference)


def prepare_backup(request):
    validate_request(request)
    with observe.source_state(request["source_request"], require_stopped=True) as facts:
        require(
            facts["quiesced"] is True and type(facts["application"]) is dict,
            "source-not-quiesced",
        )
        check_tools_and_recipient(request)
        result = {
            "document_type": PREPARED,
            "schema_version": 1,
            "profile_version": 1,
            "request": request,
            "observation_sha256": state.sha256(state.canonical(facts)),
        }
    return result


def load_prepared(raw, trusted_sha256):
    state.digest(trusted_sha256)
    require(type(raw) is bytes and 0 < len(raw) <= LIMIT, "prepared-size")
    require(state.sha256(raw) == trusted_sha256, "prepared-changed")
    value = observe.decode(raw)
    require(raw == state.canonical(value), "prepared-noncanonical")
    state.keys(
        value,
        {
            "document_type",
            "schema_version",
            "profile_version",
            "request",
            "observation_sha256",
        },
    )
    require(
        value["document_type"] == PREPARED
        and all(
            type(value[k]) is int and value[k] == 1
            for k in ("schema_version", "profile_version")
        ),
        "prepared-version",
    )
    state.digest(value["observation_sha256"])
    validate_request(value["request"])
    return value


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_directory(path):
    require(path.resolve(strict=True) == path, "runtime-path")
    info = path.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_gid == os.getegid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "runtime-directory",
    )


def write_private(path, value):
    raw = state.canonical(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        pending = memoryview(raw)
        while pending:
            written = os.write(fd, pending)
            require(written > 0, "journal-write")
            pending = pending[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    sync_directory(path.parent)
    return state.sha256(raw)


def read_private(path):
    raw, info = observe.read_regular(path, LIMIT)
    require(
        info.st_uid == os.geteuid()
        and info.st_gid == os.getegid()
        and stat.S_IMODE(info.st_mode) == 0o600,
        "journal-permissions",
    )
    return observe.decode(raw), raw


def runtime():
    parent = RUNTIME_ROOT.parent
    if not parent.exists():
        info = parent.parent.stat()
        require(
            parent.parent.resolve(strict=True) == parent.parent
            and stat.S_ISDIR(info.st_mode)
            and info.st_uid in {0, os.geteuid()}
            and not info.st_mode & 0o022,
            "runtime-parent",
        )
        parent.mkdir(mode=0o700)
        sync_directory(parent.parent)
    private_directory(parent)
    try:
        RUNTIME_ROOT.mkdir(mode=0o700)
    except FileExistsError:
        private_directory(RUNTIME_ROOT)
        require(
            read_private(RUNTIME_ROOT / "profile.json")[0] == PROFILE, "runtime-profile"
        )
    else:
        for name in ("locks", "operations"):
            (RUNTIME_ROOT / name).mkdir(mode=0o700)
        write_private(RUNTIME_ROOT / "profile.json", PROFILE)
        sync_directory(parent)
    for name in ("locks", "operations"):
        private_directory(RUNTIME_ROOT / name)
    return RUNTIME_ROOT


def validate_completion(completed, prior, intent_raw, operation):
    state.keys(
        completed,
        {
            "document_type",
            "schema_version",
            "profile_version",
            "operation_id",
            "pair_key",
            "intent_sha256",
            "prepared_sha256",
            "manifest",
            "manifest_sha256",
            "manifest_ciphertext",
            "backup_store",
            "prefix_identity",
            "artifact_identities",
            "backup_path",
            "backup_verified",
        },
    )
    request = prior["prepared"]["request"]
    require(
        completed["document_type"] == COMPLETE
        and completed["backup_verified"] is True
        and all(
            type(completed[k]) is int and completed[k] == 1
            for k in ("schema_version", "profile_version")
        )
        and completed["operation_id"] == operation
        and completed["pair_key"] == prior["pair_key"]
        and completed["intent_sha256"] == state.sha256(intent_raw)
        and completed["prepared_sha256"] == prior["prepared_sha256"],
        "unfinished-operation",
    )
    manifest = state.validate_manifest(completed["manifest"])
    require(
        manifest["operation_id"] == operation
        and manifest["source"] == request["source_request"]["source"]
        and state.pair_key(manifest["datasets"]) == prior["pair_key"]
        and completed["manifest_sha256"] == state.sha256(state.canonical(manifest)),
        "completion-manifest",
    )
    cipher = completed["manifest_ciphertext"]
    state.keys(cipher, {"name", "bytes", "sha256"})
    require(cipher["name"] == "manifest.json.age", "completion-manifest")
    state.integer(cipher["bytes"], 1, 2097152)
    state.digest(cipher["sha256"])
    expected = request["source_request"]["backup_store"]
    prefix = (
        "cmdmesh-"
        + manifest["source"]["owner_tag"].removeprefix("cmdmesh-own-")
        + "-"
        + operation
    )
    require(
        completed["backup_path"] == str(Path(expected["mountpoint"]) / prefix),
        "completion-path",
    )
    state.keys(
        completed["artifact_identities"],
        {"data.zfs.age", "config.zfs.age", "manifest.json.age"},
    )
    identities = [
        (completed["prefix_identity"], 0o700),
        *((value, 0o600) for value in completed["artifact_identities"].values()),
    ]
    for value, mode in identities:
        state.keys(value, {"device", "inode", "uid", "gid", "mode"})
        for field in value:
            state.integer(value[field], 0, 2**64 - 1)
        require(
            value["inode"] > 0
            and value["uid"] == expected["file_uid"]
            and value["gid"] == expected["file_gid"]
            and value["mode"] == mode,
            "completion-identity",
        )


@contextmanager
def journal(prepared, prepared_sha256):
    request = prepared["request"]
    key = state.pair_key(request["source_request"]["policy"]["datasets"])
    root = runtime()
    lock = root / "locks" / (key + ".json")
    marker = {
        "document_type": "cmdmesh.proxmox.persistence.pair-lock",
        "schema_version": 1,
        "pair_key": key,
    }
    try:
        write_private(lock, marker)
    except FileExistsError:
        require(read_private(lock)[0] == marker, "pair-lock")
    fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(
            observe.stable(os.fstat(fd)) == observe.stable(lock.lstat()),
            "pair-lock-changed",
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise state.PersistenceError("persistence-backup-pair-busy") from None
        operations = root / "operations"
        entries = list(operations.iterdir())
        require(len(entries) <= 4096, "journal-limit")
        for entry in entries:
            require(state.matches(r"[a-f0-9]{64}", entry.name), "foreign-journal")
            private_directory(entry)
            prior, intent_raw = read_private(entry / "intent.json")
            state.keys(prior, {"pair_key", "prepared_sha256", "prepared"})
            state.digest(prior["pair_key"])
            require(
                prior["prepared_sha256"]
                == state.sha256(state.canonical(prior["prepared"])),
                "journal-prepared-changed",
            )
            load_prepared(state.canonical(prior["prepared"]), prior["prepared_sha256"])
            require(
                prior["pair_key"]
                == state.pair_key(
                    prior["prepared"]["request"]["source_request"]["policy"]["datasets"]
                )
                and prior["prepared"]["request"]["operation_id"] == entry.name,
                "journal-pair-changed",
            )
            require(entry.name != request["operation_id"], "operation-consumed")
            if prior["pair_key"] != key:
                continue
            require((entry / "complete.json").exists(), "unfinished-operation")
            completed, _ = read_private(entry / "complete.json")
            validate_completion(completed, prior, intent_raw, entry.name)
        target = operations / request["operation_id"]
        try:
            target.mkdir(mode=0o700)
        except FileExistsError:
            raise state.PersistenceError(
                "persistence-backup-operation-consumed"
            ) from None
        intent = {
            "pair_key": key,
            "prepared_sha256": prepared_sha256,
            "prepared": prepared,
        }
        intent_sha = write_private(target / "intent.json", intent)
        sync_directory(operations)
        try:
            yield target, key, intent_sha
        except BaseException as error:
            # The consumed intent remains authoritative even if writing this
            # extra diagnostic fails. Failure never grants automatic retry.
            try:
                write_private(
                    target / "failed.json",
                    {
                        "state": "failed-or-uncertain",
                        "error_code": getattr(
                            error, "code", "persistence-backup-interrupted"
                        ),
                    },
                )
            except OSError:
                pass
            raise
    finally:
        os.close(fd)


def native_zfs(reference, arguments):
    executable = stream.tool(reference)
    try:
        result = subprocess.run(
            [executable, *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=20,
            env=stream.ENV,
            umask=0o077,
        )
    except (OSError, subprocess.SubprocessError):
        raise state.PersistenceError(
            "persistence-backup-snapshot-command-uncertain"
        ) from None
    require(
        result.returncode == 0 and not result.stderr and len(result.stdout) <= 262144,
        "snapshot-command",
    )
    stream.tool(reference)
    return result.stdout


def snapshot_names(request):
    datasets = request["source_request"]["policy"]["datasets"]
    return {
        role: datasets[role]["name"] + "@cmdmesh-" + request["operation_id"]
        for role in ("data", "config")
    }


def snapshots(request, target):
    datasets = request["source_request"]["policy"]["datasets"]
    names = snapshot_names(request)
    previous = (
        native_zfs(
            request["tools"]["zfs"],
            [
                "list",
                "-H",
                "-o",
                "name",
                "-t",
                "snapshot",
                "-d",
                "1",
                *[datasets[r]["name"] for r in ("data", "config")],
            ],
        )
        .decode()
        .splitlines()
    )
    require(not set(names.values()) & set(previous), "snapshot-exists")
    # This durable intent precedes the one atomic sibling-pair command.
    write_private(target / "snapshot-intent.json", {"snapshots": names})
    native_zfs(request["tools"]["zfs"], ["snapshot", names["data"], names["config"]])
    result = read_snapshots(request)
    write_private(target / "snapshots.json", result)
    return result


def read_snapshots(request):
    datasets = request["source_request"]["policy"]["datasets"]
    names = snapshot_names(request)
    raw = native_zfs(
        request["tools"]["zfs"],
        [
            "get",
            "-H",
            "-p",
            "-o",
            "name,property,value",
            "guid,createtxg",
            names["data"],
            names["config"],
        ],
    )
    properties = {name: {} for name in names.values()}
    for row in raw.decode().splitlines():
        fields = row.split("\t")
        require(
            len(fields) == 3
            and fields[0] in properties
            and fields[1] in {"guid", "createtxg"}
            and fields[1] not in properties[fields[0]],
            "snapshot-observation",
        )
        state.decimal(fields[2])
        properties[fields[0]][fields[1]] = fields[2]
    require(
        all(set(value) == {"guid", "createtxg"} for value in properties.values()),
        "snapshot-observation",
    )
    result = {
        role: {
            "name": datasets[role]["name"],
            "guid": datasets[role]["guid"],
            "snapshot": name,
            "snapshot_guid": properties[name]["guid"],
            "createtxg": properties[name]["createtxg"],
        }
        for role, name in names.items()
    }
    require(
        len({item["createtxg"] for item in result.values()}) == 1
        and len({item["snapshot_guid"] for item in result.values()}) == 2,
        "snapshot-generation",
    )
    return result


def identity(info):
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
    }


def verify_store(expected, facts, fd):
    require(observe.mount_facts(expected) == facts, "backup-store-changed")
    require(
        identity(os.fstat(fd))
        == {k: facts[k] for k in ("device", "inode", "uid", "gid", "mode")},
        "backup-store-changed",
    )


def readback(directory, name, output_fd, produced, expected):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid == expected["file_uid"]
            and info.st_gid == expected["file_gid"]
            and stat.S_IMODE(info.st_mode) == 0o600
            and identity(info) == identity(os.fstat(output_fd)),
            "ciphertext-identity",
        )
        import hashlib

        checksum = hashlib.sha256()
        count = 0
        while chunk := os.read(fd, 65536):
            count += len(chunk)
            require(count <= produced["ciphertext_bytes"], "ciphertext-size")
            checksum.update(chunk)
        require(
            count == produced["ciphertext_bytes"]
            and checksum.hexdigest() == produced["ciphertext_sha256"],
            "ciphertext-changed",
        )
        require(
            observe.stable(os.fstat(fd)) == observe.stable(info)
            and observe.stable(os.stat(name, dir_fd=directory, follow_symlinks=False))
            == observe.stable(info),
            "ciphertext-changed",
        )
        return {"name": name, "bytes": count, "sha256": checksum.hexdigest()}
    finally:
        os.close(fd)


def encrypted_file(
    target, prefix_fd, name, request, *, snapshot=None, manifest_bytes=None
):
    output = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=prefix_fd,
    )
    armed = None
    try:
        expected = request["source_request"]["backup_store"]
        info = os.fstat(output)
        require(
            info.st_uid == expected["file_uid"]
            and info.st_gid == expected["file_gid"]
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1,
            "ciphertext-permissions",
        )
        os.fsync(prefix_fd)
        armed = os.open(
            target / (name + ".armed.json"),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        sync_directory(target)
        if snapshot is not None:
            result = stream.encrypt_snapshot(
                snapshot,
                request["recipient"],
                output,
                request["tools"],
                journal_fd=armed,
            )
        else:
            result = stream.encrypt_manifest(
                manifest_bytes,
                request["recipient"],
                output,
                {"age": request["tools"]["age"]},
                journal_fd=armed,
            )
        artifact = readback(prefix_fd, name, output, result, expected)
        file_identity = identity(os.fstat(output))
        write_private(
            target / (name + ".result.json"),
            {"pipeline": result, "readback": artifact, "identity": file_identity},
        )
        os.fsync(prefix_fd)
        return artifact, file_identity
    finally:
        if armed is not None:
            os.close(armed)
        os.close(output)


def verify_final_outputs(request, result):
    """Reopen the recorded names after all slow source/tool/snapshot closure."""
    expected = request["source_request"]["backup_store"]
    parent = os.open(
        expected["mountpoint"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    prefix_fd = None
    prefix = Path(result["backup_path"]).name
    names = {"data.zfs.age", "config.zfs.age", "manifest.json.age"}
    try:
        verify_store(expected, result["backup_store"], parent)
        try:
            prefix_fd = os.open(
                prefix, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
            )
        except OSError:
            raise state.PersistenceError(
                "persistence-backup-prefix-unavailable"
            ) from None
        require(
            identity(os.fstat(prefix_fd)) == result["prefix_identity"]
            and set(os.listdir(prefix_fd)) == names,
            "prefix-changed",
        )
        os.fsync(prefix_fd)
        os.fsync(parent)
        for artifact in (
            *result["manifest"]["artifacts"].values(),
            result["manifest_ciphertext"],
        ):
            name = artifact["name"]
            current = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=prefix_fd
            )
            try:
                require(
                    identity(os.fstat(current)) == result["artifact_identities"][name],
                    "ciphertext-identity",
                )
                readback(
                    prefix_fd,
                    name,
                    current,
                    {
                        "ciphertext_bytes": artifact["bytes"],
                        "ciphertext_sha256": artifact["sha256"],
                    },
                    expected,
                )
            finally:
                os.close(current)
        verify_store(expected, result["backup_store"], parent)
        require(
            identity(os.stat(prefix, dir_fd=parent, follow_symlinks=False))
            == result["prefix_identity"]
            and identity(os.fstat(prefix_fd)) == result["prefix_identity"]
            and set(os.listdir(prefix_fd)) == names,
            "prefix-changed",
        )
    finally:
        if prefix_fd is not None:
            os.close(prefix_fd)
        os.close(parent)


def execute_backup(raw, trusted_sha256):
    prepared = load_prepared(raw, trusted_sha256)
    request = prepared["request"]
    # Keep the pair journal/lock alive through the source's closing checks and
    # completion publication. The application context owns its separate flock.
    with observe.source_state(request["source_request"], require_stopped=True) as first:
        require(
            first["quiesced"] is True
            and state.sha256(state.canonical(first)) == prepared["observation_sha256"],
            "source-changed",
        )
        check_tools_and_recipient(request)
    with journal(prepared, trusted_sha256) as (target, key, intent_sha):
        with observe.source_state(
            request["source_request"], require_stopped=True
        ) as facts:
            require(
                facts["quiesced"] is True
                and state.sha256(state.canonical(facts))
                == prepared["observation_sha256"],
                "source-changed",
            )
            expected = request["source_request"]["backup_store"]
            parent = os.open(
                expected["mountpoint"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            prefix_fd = None
            try:
                verify_store(expected, facts["backup_store"], parent)
                prefix = (
                    "cmdmesh-"
                    + request["source_request"]["source"]["owner_tag"].removeprefix(
                        "cmdmesh-own-"
                    )
                    + "-"
                    + request["operation_id"]
                )
                try:
                    os.stat(prefix, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise state.PersistenceError("persistence-backup-prefix-exists")
                pair = snapshots(request, target)
                try:
                    os.mkdir(prefix, 0o700, dir_fd=parent)
                except FileExistsError:
                    raise state.PersistenceError(
                        "persistence-backup-prefix-exists"
                    ) from None
                prefix_fd = os.open(
                    prefix, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
                )
                info = os.fstat(prefix_fd)
                require(
                    info.st_uid == expected["file_uid"]
                    and info.st_gid == expected["file_gid"]
                    and stat.S_IMODE(info.st_mode) == 0o700
                    and info.st_dev == facts["backup_store"]["device"],
                    "prefix-permissions",
                )
                prefix_identity = identity(info)
                os.fsync(prefix_fd)
                os.fsync(parent)
                write_private(
                    target / "prefix.json",
                    {
                        "name": prefix,
                        "identity": prefix_identity,
                        "store": facts["backup_store"],
                    },
                )
                artifacts = {}
                file_identities = {}
                for role in ("data", "config"):
                    verify_store(expected, facts["backup_store"], parent)
                    name = role + ".zfs.age"
                    artifacts[role], file_identities[name] = encrypted_file(
                        target,
                        prefix_fd,
                        name,
                        request,
                        snapshot=pair[role]["snapshot"],
                    )
                manifest = {
                    "document_type": state.DOCUMENT,
                    "schema_version": 1,
                    "profile_version": 1,
                    "operation_id": request["operation_id"],
                    "source": request["source_request"]["source"],
                    "datasets": pair,
                    "application": facts["application"],
                    "recipient": request["recipient"],
                    "artifacts": artifacts,
                }
                state.validate_manifest(manifest)
                manifest_raw = state.canonical(manifest)
                write_private(target / "manifest.json", manifest)
                cipher_manifest, file_identities["manifest.json.age"] = encrypted_file(
                    target,
                    prefix_fd,
                    "manifest.json.age",
                    request,
                    manifest_bytes=manifest_raw,
                )
                verify_store(expected, facts["backup_store"], parent)
                require(
                    identity(os.fstat(prefix_fd)) == prefix_identity
                    and identity(os.stat(prefix, dir_fd=parent, follow_symlinks=False))
                    == prefix_identity
                    and set(os.listdir(prefix_fd))
                    == {"data.zfs.age", "config.zfs.age", "manifest.json.age"},
                    "prefix-changed",
                )
                os.fsync(prefix_fd)
                os.fsync(parent)
                result = {
                    "document_type": COMPLETE,
                    "schema_version": 1,
                    "profile_version": 1,
                    "operation_id": request["operation_id"],
                    "pair_key": key,
                    "intent_sha256": intent_sha,
                    "prepared_sha256": trusted_sha256,
                    "manifest": manifest,
                    "manifest_sha256": state.sha256(manifest_raw),
                    "manifest_ciphertext": cipher_manifest,
                    "backup_store": facts["backup_store"],
                    "prefix_identity": prefix_identity,
                    "artifact_identities": file_identities,
                    "backup_path": str(Path(expected["mountpoint"]) / prefix),
                    "backup_verified": True,
                }
            finally:
                if prefix_fd is not None:
                    os.close(prefix_fd)
                os.close(parent)
        # No trusted completion is written until the source context closes.
        for reference in request["tools"].values():
            stream.tool(reference)
        final_pair = read_snapshots(request)
        write_private(target / "snapshot-final.json", final_pair)
        require(final_pair == pair, "snapshot-changed")
        verify_final_outputs(request, result)
        result["completion_sha256"] = write_private(target / "complete.json", result)
        return result
