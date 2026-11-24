"""Receive an authenticated full reference backup into an empty owned parent.

The caller authenticates/decrypts ciphertexts against an externally trusted backup
receipt before supplying plaintext stream hashes. This module never fetches keys,
trusts a NAS manifest, mounts filesystems or starts an application. A checked
receive is deliberately distinct from application recovery.
"""

from contextlib import contextmanager, ExitStack
import fcntl
import hashlib
import os
from pathlib import Path
import signal
import stat
import subprocess
import time

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_backup as backup,
    persistence_observe as observe,
    persistence_state as state,
    persistence_stream as stream,
)

RUNTIME_ROOT = Path("/var/lib/cmdmesh/persistence-restore")
TOOL_PATHS = {"zfs": "/usr/sbin/zfs", "zpool": "/usr/sbin/zpool"}
PREPARED = "cmdmesh.proxmox.persistence.prepared-receive"
COMPLETE = "cmdmesh.proxmox.persistence.completed-receive"
PROFILE = {
    "document_type": "cmdmesh.proxmox.persistence.receive-runtime",
    "schema_version": 1,
}
MAX_STREAM_BYTES = 67108864
OPTIONS = {
    "mountpoint": "none",
    "canmount": "off",
    "readonly": "on",
    "exec": "off",
    "devices": "off",
    "setuid": "off",
    "sharenfs": "off",
    "sharesmb": "off",
}
RECEIVER = """import os,resource,sys
gate=int(sys.argv[1]);command=sys.argv[2:]
if os.read(gate,4)!=b'RUN\\n':sys.exit(125)
os.close(gate)
resource.setrlimit(resource.RLIMIT_FSIZE,(262144,262144))
os.execve(command[0],command,dict(os.environ))
"""


def require(value, code):
    state.require(value, "persistence-receive-" + code)


def dataset_name(value):
    return state.matches(
        r"[A-Za-z][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_.-]+)+", value
    ) and not ({".", ".."} & set(value.split("/")))


def validate_request(request, model):
    state.keys(
        request,
        {
            "schema_version",
            "operation_id",
            "manifest_sha256",
            "target",
            "tools",
            "streams",
        },
    )
    require(
        type(request["schema_version"]) is int and request["schema_version"] == 1,
        "version",
    )
    state.digest(request["operation_id"])
    state.digest(request["manifest_sha256"])
    target = request["target"]
    state.keys(
        target,
        {"origin", "node", "host_profile", "versions", "pool", "parent", "owner_tag"},
    )
    # Reuse the supported source host/version schema without requiring a target
    # CT to exist. A receive changes datasets only, never guest configuration.
    source = {
        "selector": {
            "origin": target["origin"],
            "node": target["node"],
            "kind": "proxmox.lxc",
            "vmid": 100,
        },
        "host_profile": target["host_profile"],
        "owner_tag": target["owner_tag"],
        "generation_tag": "cmdmesh-gen-" + "0" * 32,
    }
    state.source_identity(source)
    state.keys(target["versions"], {"pve-manager", "pve-container", "zfsutils-linux"})
    for name, prefix in (
        ("pve-manager", "9."),
        ("pve-container", "6."),
        ("zfsutils-linux", "2.4."),
    ):
        version = target["versions"][name]
        require(
            state.matches(r"[A-Za-z0-9.+:~_-]{1,128}", version)
            and version.startswith(prefix),
            "unsupported-version",
        )
    for item in (target["pool"], target["parent"]):
        state.keys(item, {"name", "guid"})
        state.decimal(item["guid"])
    require(
        state.matches(r"[A-Za-z][A-Za-z0-9_.-]*", target["pool"]["name"]), "pool-name"
    )
    parent = target["parent"]["name"]
    require(
        dataset_name(parent) and parent.split("/", 1)[0] == target["pool"]["name"],
        "parent-name",
    )
    require(target["pool"]["guid"] != target["parent"]["guid"], "parent-guid")
    if (
        target["host_profile"]["machine_id_sha256"]
        == model["source"]["host_profile"]["machine_id_sha256"]
    ):
        for original in model["datasets"].values():
            name = original["name"]
            require(
                parent != name
                and not parent.startswith(name + "/")
                and not name.startswith(parent + "/"),
                "source-overlap",
            )
            require(target["parent"]["guid"] != original["guid"], "source-overlap")
    state.keys(request["tools"], TOOL_PATHS)
    for name, reference in request["tools"].items():
        state.keys(reference, {"path", "sha256"})
        require(reference["path"] == TOOL_PATHS[name], "tool-path")
        state.digest(reference["sha256"])
    state.keys(request["streams"], state.ROLES)
    for item in request["streams"].values():
        state.keys(item, {"path", "bytes", "sha256"})
        require(observe.absolute(item["path"]), "stream-path")
        state.integer(item["bytes"], 1, MAX_STREAM_BYTES)
        state.digest(item["sha256"])
    require(
        len({item["path"] for item in request["streams"].values()}) == 2,
        "shared-stream",
    )


def file_identity(info):
    return list(observe.stable(info))


@contextmanager
def inputs(request, *, freeze=False):
    """Hash private inputs; execution receives sealed anonymous copies only."""
    with ExitStack() as stack:
        values = {}
        for role in ("data", "config"):
            item = request["streams"][role]
            path = Path(item["path"])
            require(path.resolve(strict=True) == path, "stream-path")
            info = path.lstat()
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1
                and info.st_size == item["bytes"],
                "stream-permissions",
            )
            parent = path.parent.stat()
            require(
                parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) == 0o700,
                "stream-directory",
            )
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            stack.callback(os.close, fd)
            require(
                file_identity(os.fstat(fd)) == file_identity(info), "stream-changed"
            )
            sealed = None
            if freeze:
                sealed = os.memfd_create(
                    "cmdmesh-receive-" + role, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
                )
                stack.callback(os.close, sealed)
                os.fchmod(sealed, 0o600)
            checksum, count = hashlib.sha256(), 0
            while chunk := os.read(fd, 65536):
                count += len(chunk)
                require(count <= item["bytes"], "stream-changed")
                checksum.update(chunk)
                if sealed is not None:
                    pending = memoryview(chunk)
                    while pending:
                        written = os.write(sealed, pending)
                        require(written > 0, "stream-copy")
                        pending = pending[written:]
            require(
                count == item["bytes"]
                and checksum.hexdigest() == item["sha256"]
                and file_identity(os.fstat(fd))
                == file_identity(info)
                == file_identity(path.lstat()),
                "stream-changed",
            )
            if sealed is not None:
                os.lseek(sealed, 0, os.SEEK_SET)
                fcntl.fcntl(
                    sealed,
                    fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE
                    | fcntl.F_SEAL_GROW
                    | fcntl.F_SEAL_SHRINK
                    | fcntl.F_SEAL_SEAL,
                )
            values[role] = {"identity": file_identity(info), "fd": sealed}
        require(
            values["data"]["identity"][:2] != values["config"]["identity"][:2],
            "shared-stream",
        )
        yield values
        for role, value in values.items():
            require(
                file_identity(Path(request["streams"][role]["path"]).lstat())
                == value["identity"],
                "stream-changed",
            )


def native(reference, arguments):
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
            "persistence-receive-observation-unavailable"
        ) from None
    require(
        result.returncode == 0 and not result.stderr and len(result.stdout) <= 262144,
        "observation-command",
    )
    return result.stdout.decode("utf-8")


def properties(request, name, fields):
    raw = native(
        request["tools"]["zfs"],
        ["get", "-H", "-p", "-o", "name,property,value,source", ",".join(fields), name],
    )
    result = {}
    for row in raw.splitlines():
        values = row.split("\t")
        require(
            len(values) == 4
            and values[0] == name
            and values[1] in fields
            and values[1] not in result,
            "property-rows",
        )
        result[values[1]] = {"value": values[2], "source": values[3]}
    require(set(result) == set(fields), "property-rows")
    return result


def inventory(request):
    raw = native(
        request["tools"]["zfs"],
        [
            "list",
            "-H",
            "-o",
            "name,type",
            "-t",
            "filesystem,volume,snapshot,bookmark",
            "-r",
            request["target"]["parent"]["name"],
        ],
    )
    result = {}
    for row in raw.splitlines():
        values = row.split("\t")
        require(len(values) == 2 and values[0] not in result, "inventory-rows")
        result[values[0]] = values[1]
    return result


def inspect_target(request, model, roles=()):
    require(set(roles) <= state.ROLES and len(set(roles)) == len(roles), "roles")
    target = request["target"]
    host = observe.host_facts(
        {
            "source": {
                "selector": {"node": target["node"]},
                "host_profile": target["host_profile"],
            },
            "versions": target["versions"],
        }
    )
    for reference in request["tools"].values():
        stream.tool(reference)
    raw = native(
        request["tools"]["zpool"],
        [
            "get",
            "-H",
            "-p",
            "-o",
            "property,value",
            "guid,health,readonly",
            target["pool"]["name"],
        ],
    )
    pool = {}
    for row in raw.splitlines():
        values = row.split("\t")
        require(len(values) == 2 and values[0] not in pool, "pool-rows")
        pool[values[0]] = values[1]
    require(
        pool == {"guid": target["pool"]["guid"], "health": "ONLINE", "readonly": "off"},
        "pool-identity",
    )
    parent_name = target["parent"]["name"]
    parent = properties(
        request,
        parent_name,
        ("type", "guid", "mountpoint", "canmount", "mounted", "org.cmdmesh:owner"),
    )
    expected = {
        "type": "filesystem",
        "guid": target["parent"]["guid"],
        "mountpoint": "none",
        "canmount": "off",
        "mounted": "no",
        "org.cmdmesh:owner": target["owner_tag"],
    }
    require(
        {key: item["value"] for key, item in parent.items()} == expected
        and parent["org.cmdmesh:owner"]["source"] == "local",
        "parent-identity",
    )
    expected_inventory, received = {parent_name: "filesystem"}, {}
    for role in roles:
        name = parent_name + "/" + role
        snapshot = name + "@cmdmesh-" + model["operation_id"]
        expected_inventory.update({name: "filesystem", snapshot: "snapshot"})
        props = properties(
            request, name, ("type", "guid", "mounted", "org.cmdmesh:owner", *OPTIONS)
        )
        state.decimal(props["guid"]["value"])
        require(
            {key: value["value"] for key, value in props.items() if key != "guid"}
            == {
                "type": "filesystem",
                "mounted": "no",
                "org.cmdmesh:owner": target["owner_tag"],
                **OPTIONS,
            },
            "received-properties",
        )
        require(
            all(
                props[key]["source"] == "local"
                for key in (*OPTIONS, "org.cmdmesh:owner")
            ),
            "received-properties",
        )
        snap = properties(request, snapshot, ("guid",))
        require(
            snap["guid"]["value"] == model["datasets"][role]["snapshot_guid"],
            "snapshot-guid",
        )
        received[role] = {
            "name": name,
            "guid": props["guid"]["value"],
            "snapshot": snapshot,
            "snapshot_guid": snap["guid"]["value"],
            "properties": props,
        }
    require(inventory(request) == expected_inventory, "target-not-empty-or-unexpected")
    require(
        len({item["guid"] for item in received.values()}) == len(received),
        "shared-received-dataset",
    )
    return {"host": host, "pool": pool, "parent": parent, "received": received}


def check_receiver_platform():
    require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "reaper-unsupported")
    fd = os.pidfd_open(os.getpid())
    os.close(fd)


def preparation(request, model, opened):
    check_receiver_platform()
    facts = inspect_target(request, model)
    return {
        "document_type": PREPARED,
        "schema_version": 1,
        "profile_version": 1,
        "request": request,
        "manifest": model,
        "target_observation": facts,
        "stream_identities": {
            role: value["identity"] for role, value in opened.items()
        },
    }


def prepare_restore(request, manifest_raw):
    model = state.load_manifest(manifest_raw, request["manifest_sha256"])
    require(manifest_raw == state.canonical(model), "manifest-noncanonical")
    validate_request(request, model)
    with inputs(request) as opened:
        return preparation(request, model, opened)


def load_prepared(raw, trusted_sha256):
    state.digest(trusted_sha256)
    require(
        type(raw) is bytes
        and 0 < len(raw) <= 1048576
        and state.sha256(raw) == trusted_sha256,
        "prepared-changed",
    )
    prepared = observe.decode(raw)
    state.keys(
        prepared,
        {
            "document_type",
            "schema_version",
            "profile_version",
            "request",
            "manifest",
            "target_observation",
            "stream_identities",
        },
    )
    require(
        raw == state.canonical(prepared)
        and prepared["document_type"] == PREPARED
        and all(
            type(prepared[key]) is int and prepared[key] == 1
            for key in ("schema_version", "profile_version")
        ),
        "prepared-version",
    )
    request = prepared["request"]
    model = state.load_manifest(
        state.canonical(prepared["manifest"]), request["manifest_sha256"]
    )
    validate_request(request, model)
    return prepared


def runtime():
    parent = RUNTIME_ROOT.parent
    if not parent.exists():
        base = parent.parent
        info = base.stat()
        require(
            base.resolve(strict=True) == base
            and info.st_uid in {0, os.geteuid()}
            and not info.st_mode & 0o022,
            "runtime-parent",
        )
        parent.mkdir(mode=0o700)
        backup.sync_directory(base)
    backup.private_directory(parent)
    try:
        RUNTIME_ROOT.mkdir(mode=0o700)
    except FileExistsError:
        backup.private_directory(RUNTIME_ROOT)
        require(
            state.canonical(backup.read_private(RUNTIME_ROOT / "profile.json")[0])
            == state.canonical(PROFILE),
            "runtime-profile",
        )
    else:
        backup.write_private(RUNTIME_ROOT / "profile.json", PROFILE)
        backup.sync_directory(parent)
    return RUNTIME_ROOT


def claim(prepared, trusted):
    target = prepared["request"]["target"]
    # Aliases, new operation IDs and changed mountpoint names cannot bypass the
    # one-use claim for this exact host/pool/parent GUID.
    key = state.sha256(
        state.canonical(
            [
                target["host_profile"]["machine_id_sha256"],
                target["pool"]["guid"],
                target["parent"]["guid"],
            ]
        )
    )
    root = runtime()
    path = root / key
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        raise state.PersistenceError("persistence-receive-parent-consumed") from None
    backup.sync_directory(root)
    intent_sha256 = backup.write_private(
        path / "intent.json", {"prepared_sha256": trusted, "prepared": prepared}
    )
    return path, intent_sha256


def receive(request, role, fd, directory, *, timeout_seconds=60):
    check_receiver_platform()
    require(
        type(timeout_seconds) in {int, float} and 0.05 <= timeout_seconds <= 600,
        "timeout",
    )
    executable = stream.tool(request["tools"]["zfs"])
    options = {**OPTIONS, "org.cmdmesh:owner": request["target"]["owner_tag"]}
    argv = [executable, "receive", "-u"]
    for key, value in options.items():
        argv.extend(("-o", key + "=" + value))
    argv.append(request["target"]["parent"]["name"] + "/" + role)
    backup.write_private(
        directory / (role + "-dispatch.json"),
        {"argv": argv, "stream_sha256": request["streams"][role]["sha256"]},
    )
    with ExitStack() as stack:
        outputs = []
        for suffix in ("stdout", "stderr"):
            output = os.open(
                directory / (role + "." + suffix),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            stack.callback(os.close, output)
            outputs.append(output)
        backup.sync_directory(directory)
        # Arm the native PID before opening its gate. The small wrapper replaces
        # itself with the fixed executable; there is no sender or shell child.
        import sys

        gate_read, gate_write = os.pipe()
        stack.callback(os.close, gate_read)
        stack.callback(os.close, gate_write)
        child = subprocess.Popen(
            [sys.executable, "-I", "-S", "-B", "-c", RECEIVER, str(gate_read), *argv],
            stdin=fd,
            stdout=outputs[0],
            stderr=outputs[1],
            pass_fds=(gate_read,),
            env=stream.ENV,
            umask=0o077,
            start_new_session=True,
        )
        pidfd = None
        try:
            pidfd = os.pidfd_open(child.pid)
            stack.callback(os.close, pidfd)
            process = stream.process(child.pid)
            require(
                process
                and process["parent"] == os.getpid()
                and process["group"] == process["session"] == child.pid,
                "process-anchor",
            )
            backup.write_private(
                directory / (role + "-process.json"),
                {"pid": child.pid, "process": process},
            )
            require(os.write(gate_write, b"RUN\n") == 4, "process-gate")
            deadline = time.monotonic() + timeout_seconds
            while child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            if child.poll() is None:
                stop_receiver(child, pidfd)
                backup.write_private(
                    directory / (role + "-result.json"),
                    {
                        "timed_out": True,
                        "process_stopped": child.poll() is not None,
                        "returncode": child.poll(),
                    },
                )
                raise state.PersistenceError("persistence-receive-command-uncertain")
        finally:
            if child.poll() is None:
                if pidfd is not None:
                    stop_receiver(child, pidfd)
                else:
                    # The unreaped direct child cannot have its PID reused.
                    try:
                        child.kill()
                    except ProcessLookupError:
                        pass
                    deadline = time.monotonic() + 1
                    while child.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.02)
        result = {
            "timed_out": False,
            "process_stopped": True,
            "returncode": child.returncode,
            "output_bytes": [os.fstat(output).st_size for output in outputs],
        }
        for output in outputs:
            os.fsync(output)
        backup.write_private(directory / (role + "-result.json"), result)
        require(
            child.returncode == 0 and result["output_bytes"] == [0, 0], "command-failed"
        )
    stream.tool(request["tools"]["zfs"])


def stop_receiver(child, pidfd):
    try:
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 1
    while child.poll() is None and time.monotonic() < deadline:
        time.sleep(0.02)


def execute_restore(raw, trusted_sha256):
    prepared = load_prepared(raw, trusted_sha256)
    request, model = prepared["request"], prepared["manifest"]
    directory = None
    try:
        with inputs(request, freeze=True) as opened:
            require(
                state.canonical(preparation(request, model, opened)) == raw,
                "target-or-input-changed",
            )
            directory, intent_sha256 = claim(prepared, trusted_sha256)
            roles = []
            for role in ("data", "config"):
                before = inspect_target(request, model, tuple(roles))
                require(
                    state.canonical({**before, "received": {}})
                    == state.canonical(prepared["target_observation"]),
                    "target-changed",
                )
                receive(request, role, opened[role]["fd"], directory)
                roles.append(role)
                after = inspect_target(request, model, tuple(roles))
                require(
                    state.canonical({**after, "received": {}})
                    == state.canonical(prepared["target_observation"]),
                    "target-changed",
                )
            # Exit the input context and check original files before publishing
            # completion; the sealed descriptors protected the actual commands.
            received = after["received"]
        complete = {
            "document_type": COMPLETE,
            "schema_version": 1,
            "profile_version": 1,
            "operation_id": request["operation_id"],
            "prepared_sha256": trusted_sha256,
            "intent_sha256": intent_sha256,
            "manifest_sha256": request["manifest_sha256"],
            "target": request["target"],
            "received": received,
            "received_verified": True,
            "restore_verified": False,
            "application_verified": False,
            "source_unavailable_verified": False,
        }
        completion_sha256 = backup.write_private(directory / "complete.json", complete)
        return {**complete, "completion_sha256": completion_sha256}
    except BaseException as error:
        if directory is not None:
            try:
                backup.write_private(
                    directory / "failed.json",
                    {
                        "state": "failed-or-uncertain",
                        "error_code": getattr(
                            error, "code", "persistence-receive-interrupted"
                        ),
                    },
                )
            except OSError:
                pass
        raise
