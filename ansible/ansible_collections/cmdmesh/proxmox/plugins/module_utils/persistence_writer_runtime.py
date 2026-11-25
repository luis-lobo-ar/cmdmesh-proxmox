"""Read-only active-writer inspection and a leased reference-application client.

Public collection performs authenticated reads only. Internal lifecycle callers
own service changes and permanent claims; the leased worker owns no native or
application locks. No host-side database bytes or SQL are read while active.
"""

from contextlib import contextmanager, ExitStack
import copy
from dataclasses import asdict, dataclass
import os
from pathlib import Path
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_ledger_api as ledger,
    persistence_retained_runtime as runtime,
    persistence_state as state,
    persistence_writer_paths as paths,
    persistence_writer_peer as process,
    unix_peer,
)

PROC_ROOT = Path("/proc")
FLAGS = {
    "mutation_attempted": False,
    "boot_verified": False,
    "rebuild_verified": False,
    "restore_verified": False,
    "backup_verified": False,
}


def require(value, code):
    state.require(value, "persistence-writer-runtime-" + code)


@dataclass(frozen=True)
class Endpoint:
    parent: int
    config: int
    peer: unix_peer.ProcessIdentity
    identity: dict


def _datasets(policy, guard):
    """Observe GUIDs/mounts/permissions, without the old guard's database read."""
    result = {}
    mapping = policy["mapping"]
    owner = (mapping["offset"] + mapping["uid"], mapping["offset"] + mapping["gid"])
    for role, expected in policy["datasets"].items():
        rows = [
            row.split("\t")
            for row in guard.native(
                [
                    "/usr/sbin/zfs",
                    "get",
                    "-H",
                    "-p",
                    "-o",
                    "property,value",
                    "guid,mounted,mountpoint,org.cmdmesh:owner",
                    expected["name"],
                ]
            )
            .decode()
            .splitlines()
        ]
        require(
            all(len(row) == 2 for row in rows) and len(rows) == len(dict(rows)),
            "dataset-properties",
        )
        properties = dict(rows)
        guard.validate_dataset_properties(policy, role, properties)
        mounts = guard.decode(
            guard.native(
                [
                    "/usr/bin/findmnt",
                    "--json",
                    "--mountpoint",
                    expected["mountpoint"],
                    "-o",
                    "TARGET,SOURCE,FSTYPE,FSROOT",
                ]
            )
        )
        require(
            mounts
            == {
                "filesystems": [
                    {
                        "target": expected["mountpoint"],
                        "source": expected["name"],
                        "fstype": "zfs",
                        "fsroot": "/",
                    }
                ]
            },
            "dataset-mount",
        )
        path = Path(expected["mountpoint"])
        require(path.resolve(strict=True) == path, "dataset-path")
        info = path.lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o700
            and (info.st_uid, info.st_gid) == owner,
            "dataset-directory",
        )
        # SQLite can create/remove its rollback journal in data. Neither data
        # directory timestamps nor byte size are an immutable active-phase fact.
        result[role] = {
            "properties": properties,
            "mount": mounts["filesystems"][0],
            "directory": {
                "device": info.st_dev,
                "inode": info.st_ino,
                "mode": stat.S_IMODE(info.st_mode),
                "uid": info.st_uid,
                "gid": info.st_gid,
            },
        }
    return result


def _base_frame(request, profile, guard, binding, host):
    require(runtime.observe.host_facts(request) == host, "host-changed")
    policy = request["policy"]
    guest = runtime.observe.guest_facts(policy)
    runtime.validate_running_guest(request, profile, guest)
    kernel = runtime.kernel.collect(binding)
    reference = runtime.reference_facts(request)
    ownership = guard.collect_ownership(policy)
    guard.validate_ownership(policy, ownership)
    datasets = _datasets(policy, guard)
    binds = runtime.collect_bindings(binding, kernel, policy["datasets"])
    runtime.validate_bindings(policy, {"datasets": datasets}, binds)
    raw = runtime.observe.native(
        [
            "/usr/sbin/pct",
            "exec",
            str(policy["vmid"]),
            "--",
            "/usr/bin/systemctl",
            "show",
            "reference-ledger.service",
            "--property=MainPID",
            "--value",
        ]
    )
    require(type(raw) is bytes and len(raw) <= 16, "main-pid")
    pid = process.main_pid({"unit": {"MainPID": raw.decode("ascii").strip()}})
    image = runtime.guest_image(request, profile, writer_pid=pid)
    _, helper, _ = runtime.load_profile(request, profile)
    runtime.validate_image(profile, helper, image, kernel, writer_pid=pid)
    return {
        "host": host,
        "guest": guest,
        "kernel": kernel,
        "reference": reference,
        "ownership": ownership,
        "datasets": datasets,
        "bindings": binds,
        "image": image,
    }


def _find_peer(namespace, guest_pid):
    candidates = []
    for path in PROC_ROOT.iterdir():
        if not path.name.isdigit():
            continue
        try:
            if (path / "ns/pid").stat().st_ino != namespace:
                continue
            peer = unix_peer.process_identity(int(path.name))
        except FileNotFoundError:
            continue
        if peer.nspid[-1] == guest_pid:
            candidates.append(peer)
    require(len(candidates) == 1, "peer-count")
    return candidates[0]


def _python(stack, root, owner):
    directory = paths.directory(stack, root, "usr/bin", owner, owner, mode=0o755)
    info = os.stat("python3", dir_fd=directory, follow_symlinks=False)
    name = "python3"
    if stat.S_ISLNK(info.st_mode):
        name = os.readlink("python3", dir_fd=directory)
        require(state.matches(r"python3\.[0-9]{1,2}", name), "python-link")
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
    )
    stack.callback(os.close, descriptor)
    info = os.fstat(descriptor)
    require(
        stat.S_ISREG(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o755
        and (info.st_uid, info.st_gid) == owner
        and info.st_nlink == 1,
        "python-file",
    )
    return info.st_dev, info.st_ino


def _program(stack, root, owner, checksum):
    directory = paths.directory(
        stack, root, "opt/reference-ledger", owner, owner, mode=0o755
    )
    descriptor = os.open(
        "ledger.py",
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=directory,
    )
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        require(
            stat.S_ISREG(before.st_mode)
            and stat.S_IMODE(before.st_mode) == 0o644
            and (before.st_uid, before.st_gid) == owner
            and before.st_nlink == 1
            and 0 < before.st_size <= 65536,
            "program-file",
        )
        require(
            state.sha256(source.read(65537)) == checksum
            and paths.identity(before)
            == paths.identity(os.fstat(source.fileno()))
            == paths.identity(
                os.stat("ledger.py", dir_fd=directory, follow_symlinks=False)
            ),
            "program-changed",
        )


@contextmanager
def _admitted(request, profile, guard, binding, host):
    frame = _base_frame(request, profile, guard, binding, host)
    kernel = frame["kernel"]
    init = unix_peer.process_identity(kernel["init"]["pid"])
    peer = _find_peer(init.pid_namespace, process.main_pid(frame["image"]))
    mapping = request["policy"]["mapping"]
    root_owner = (mapping["offset"], mapping["offset"])
    app_owner = (mapping["offset"] + mapping["uid"], mapping["offset"] + mapping["gid"])
    with ExitStack() as opened:
        root = os.open(
            PROC_ROOT / str(init.pid) / "root",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        opened.callback(os.close, root)
        info = os.fstat(root)
        require(
            (info.st_dev, info.st_ino) == init.root
            and (info.st_uid, info.st_gid) == root_owner
            and stat.S_IMODE(info.st_mode) == 0o755,
            "guest-root",
        )
        python = _python(opened, root, root_owner)
        process.validate(request, profile, kernel, frame["image"], init, peer, python)
        _, image, _ = runtime.load_profile(request, profile)
        _program(opened, root, root_owner, image.PROGRAM_SHA256)
        config = paths.directory(
            opened, root, "etc/reference-ledger", root_owner, app_owner
        )
        data = paths.directory(
            opened, root, "var/lib/reference-ledger", root_owner, app_owner
        )
        run = paths.directory(
            opened, root, "run/reference-ledger", root_owner, app_owner
        )
        datasets = request["policy"]["datasets"]
        paths.backing(config, datasets["config"]["mountpoint"])
        paths.backing(data, datasets["data"]["mountpoint"])
        lease = paths.writer_lease(config, peer.pid, *app_owner)
        directories = {
            "config": (config, "etc/reference-ledger"),
            "data": (data, "var/lib/reference-ledger"),
            "run": (run, "run/reference-ledger"),
        }
        directory_seals = {
            role: list(paths.identity(os.fstat(fd)))[:6]
            for role, (fd, relative) in directories.items()
        }
        socket_seal = unix_peer._socket_seal(run, "api.sock", peer)
        frame.update(
            peer=asdict(peer),
            writer_lease=lease,
            python_executable=list(python),
            endpoint_paths={"directories": directory_seals, "socket": socket_seal},
        )
        endpoint = Endpoint(
            run,
            config,
            peer,
            {
                "instance_id": request["policy"]["application"]["instance_id"],
                "config_sha256": request["policy"]["application"]["config_sha256"],
                "application_uid": mapping["uid"],
            },
        )
        try:
            require(
                unix_peer.process_identity(init.pid) == init
                and unix_peer.process_identity(peer.pid) == peer,
                "process-changed",
            )
            yield frame, endpoint
        finally:
            require(
                unix_peer.process_identity(init.pid) == init
                and unix_peer.process_identity(peer.pid) == peer,
                "process-changed",
            )
            require(
                (os.fstat(root).st_dev, os.fstat(root).st_ino) == init.root,
                "root-changed",
            )
            paths.backing(config, datasets["config"]["mountpoint"])
            paths.backing(data, datasets["data"]["mountpoint"])
            require(
                paths.writer_lease(config, peer.pid, *app_owner) == lease,
                "writer-lease-changed",
            )
            require(_python(opened, root, root_owner) == python, "python-changed")
            _program(opened, root, root_owner, image.PROGRAM_SHA256)
            for role, (descriptor, relative) in directories.items():
                named = paths.directory(opened, root, relative, root_owner, app_owner)
                require(
                    list(paths.identity(os.fstat(named)))[:6]
                    == list(paths.identity(os.fstat(descriptor)))[:6]
                    == directory_seals[role],
                    "endpoint-path-changed",
                )
            require(
                unix_peer._socket_seal(run, "api.sock", peer) == socket_seal,
                "socket-path-changed",
            )
            # These process observations must follow all slow closing file and
            # descriptor proofs, not precede the final program/lease reads.
            require(
                unix_peer.process_identity(init.pid) == init
                and unix_peer.process_identity(peer.pid) == peer,
                "process-changed",
            )


def _stable(frame):
    value = copy.deepcopy(frame)
    value["guest"]["runtime"].pop("uptime")
    return value


class _Client:
    def __init__(self, endpoint, check, frame):
        self.endpoint, self.check, self.frame = endpoint, check, frame
        self.active = True

    def read(self):
        require(self.active, "client-closed")
        self.check()
        endpoint = self.endpoint
        result = ledger.read(
            endpoint.parent, endpoint.peer, endpoint.config, endpoint.identity
        )
        self.check()
        return result

    def append(self, operation_id, value):
        require(self.active, "client-closed")
        self.check()
        endpoint = self.endpoint
        result = ledger.append(
            endpoint.parent,
            endpoint.peer,
            endpoint.config,
            endpoint.identity,
            operation_id,
            value,
        )
        self.check()
        return result


@contextmanager
def _session_leased(request, profile, guard, binding, host):
    """Use caller-held pair EX and both native SH; acquire no application EX."""
    with _admitted(request, profile, guard, binding, host) as (first, endpoint):
        last = [copy.deepcopy(first)]

        def check():
            with _admitted(request, profile, guard, binding, host) as (current, unused):
                require(
                    _stable(current) == _stable(first)
                    and current["guest"]["runtime"]["uptime"]
                    >= last[0]["guest"]["runtime"]["uptime"],
                    "active-frame-changed",
                )
                last[0] = copy.deepcopy(current)
            client.frame = copy.deepcopy(last[0])

        client = _Client(endpoint, check, copy.deepcopy(first))
        try:
            check()
            yield client
            check()
        finally:
            client.active = False


def collect(request, profile):
    """Inspect an already running writer and authenticate a read; never start it."""
    request, profile = copy.deepcopy(request), copy.deepcopy(profile)
    guard, unused, binding = runtime.load_profile(request, profile)
    host = runtime.observe.host_facts(request)
    runtime.observe.load_guard(request["reference_guard"])
    policy = request["policy"]
    with runtime.pair_lock.locked_pair(policy["datasets"]), ExitStack() as leased:
        for vmid in sorted((policy["vmid"], policy["retired_guest"]["vmid"])):
            leased.enter_context(runtime.config_lock.read_guest(vmid))
        with _session_leased(request, profile, guard, binding, host) as client:
            application = client.read()
        frame = client.frame
    return {
        "schema_version": 1,
        "phase": "active_writer",
        "source": request["source"],
        "runtime": frame,
        "os_runtime_verified": True,
        "application_quiesced": False,
        "application_read_verified": True,
        "application": {
            key: application[key]
            for key in ("instance_id", "records_sha256", "record_count")
        },
        **FLAGS,
    }
