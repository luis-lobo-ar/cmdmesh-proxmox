"""Current read-only owner admission from previously accepted writer authority.

Checkpoint input must come from load_writer_checkpoint with externally trusted
hashes. This module does not turn a target-side candidate into accepted authority.
Private workers borrow real caller-held leases; no native lifecycle is exposed.
"""

from contextlib import contextmanager, ExitStack
import copy
from dataclasses import dataclass
import errno
import os
from pathlib import Path
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_checkpoint as checkpoint_codec,
    persistence_retained_boot as boot,
    persistence_retained_runtime as runtime,
)

observe, state = runtime.observe, runtime.state
CGROUP_ROOT = Path("/sys/fs/cgroup/lxc")
ROOT_UID = 0


def require(value, code):
    state.require(value, "persistence-owner-current-" + code)


def same(left, right, code):
    require(state.canonical(left) == state.canonical(right), code)


def _authority(checkpoint):
    state.keys(
        checkpoint,
        {
            "document_type",
            "schema_version",
            "prepared",
            "completion",
            "prepared_sha256",
            "completion_sha256",
        },
    )
    require(
        checkpoint["document_type"] == checkpoint_codec.DOCUMENT
        and type(checkpoint["schema_version"]) is int
        and checkpoint["schema_version"] == 1,
        "checkpoint",
    )
    for key in ("prepared", "completion"):
        state.digest(checkpoint[key + "_sha256"])
        require(
            state.sha256(state.canonical(checkpoint[key]))
            == checkpoint[key + "_sha256"],
            "checkpoint-changed",
        )
    prepared = checkpoint["prepared"]
    request, profile = prepared["source_request"], prepared["image_profile"]
    expected = checkpoint["completion"]["runtime"]
    runtime.validate(request, profile, "os_quiesced", expected)
    return request, profile, expected


def _host(request, host):
    state.keys(host, {"host_profile", "versions", "boot_id", "mount_namespace"})
    same(host["host_profile"], request["source"]["host_profile"], "host-pins")
    same(host["versions"], request["versions"], "host-versions")
    require(
        state.matches(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", host["boot_id"])
        and state.matches(r"mnt:\[[1-9][0-9]*\]", host["mount_namespace"]),
        "host-epoch",
    )


def _retained_identity(guard, retained):
    return {
        key: retained[key]
        for key in (
            "config",
            "rootfs",
            "datasets",
            "application",
            "id_maps",
            "generated_config_stable_sha256",
            "generated_cpu_max",
        )
    } | {"ownership": guard.ownership_seal(retained["ownership"])}


def validate_current(checkpoint, phase, evidence):
    """Validate fresh evidence against accepted portable identity, without IO."""
    require(type(phase) is str and phase in {"os_quiesced", "stopped"}, "phase")
    request, profile, expected = _authority(checkpoint)
    guard, _, _ = runtime.load_profile(request, profile)
    state.keys(evidence, {"phase", "observation", "guest_image_verified"})
    require(
        evidence["phase"] == phase
        and evidence["guest_image_verified"] is (phase == "os_quiesced"),
        "evidence-phase",
    )
    frame = evidence["observation"]
    if phase == "os_quiesced":
        runtime.validate(request, profile, phase, frame)
        retained = frame["retained"]
        _, selected = guard.generated_fingerprint(
            frame["kernel"]["generated_config"].encode()
        )
        # pvestatd can rebalance live cgroups without changing the generated
        # boot-time selection. Runtime validation joins live affinity/limits.
        same(retained["cpu_selection"], selected, "generated-cpu-selection")
        same(
            frame["reference"]["files"],
            expected["reference"]["files"],
            "reference-identity",
        )
    else:
        state.keys(
            frame,
            {
                "schema_version",
                "source",
                "host",
                "guest",
                "guarded",
                "backup_store",
                "application",
                "quiesced",
                "backup_verified",
            },
        )
        require(
            type(frame["schema_version"]) is int
            and frame["schema_version"] == 1
            and frame["quiesced"] is True
            and frame["backup_verified"] is False,
            "stopped-flags",
        )
        same(frame["source"], request["source"], "source")
        _host(request, frame["host"])
        observe.validate_guest(request["policy"], frame["guest"])
        require(frame["guest"]["status"] == "stopped", "not-stopped")
        same(frame["guest"]["config"], profile["config"], "guest-config")
        retained = frame["guarded"]
        guard.validate(request["policy"], retained, request["policy"]["vmid"])
    same(frame["application"], expected["application"], "application-changed")
    same(
        _retained_identity(guard, retained),
        _retained_identity(guard, expected["retained"]),
        "retained-identity",
    )


def _prior_fence(host, prior_runtime):
    if host["boot_id"] != prior_runtime["host"]["boot_id"]:
        return "manager-epoch-changed"
    init = prior_runtime["kernel"]["init"]
    try:
        actual = runtime.kernel.reader.memory.init_state(init["pid"])
    except FileNotFoundError as error:
        require(error.errno == errno.ENOENT, "prior-init-unqualified")
        return "prior-init-absent"
    require(
        type(actual) is tuple
        and len(actual) == 2
        and all(type(part) is int and part > 1 for part in actual),
        "prior-init-unqualified",
    )
    require(actual != (init["pstart"], init["pid_namespace_inode"]), "prior-init-live")
    return "prior-init-reused"


def _kernel_file(path, limit=4096):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == ROOT_UID
            and not info.st_mode & 0o022,
            "cgroup-file",
        )
        data = bytearray()
        while chunk := os.read(fd, limit + 1 - len(data)):
            data.extend(chunk)
            require(len(data) <= limit, "cgroup-limit")
        require(
            observe.stable(info)
            == observe.stable(os.fstat(fd))
            == observe.stable(Path(path).lstat()),
            "cgroup-file-changed",
        )
        return bytes(data)
    finally:
        os.close(fd)


def _empty_cgroup(vmid):
    state.integer(vmid, 100, 999999)
    require(
        CGROUP_ROOT.parent.resolve(strict=True) == CGROUP_ROOT.parent, "cgroup-root"
    )
    # findmnt proves the kernel interface before populated=0 is interpreted as
    # recursive process absence. Native cgroup.procs can legitimately be empty.
    mount = observe.decode(
        observe.native(
            [
                "/usr/bin/findmnt",
                "--json",
                "--target",
                str(CGROUP_ROOT.parent),
                "-o",
                "TARGET,FSTYPE",
            ]
        )
    )
    state.keys(mount, {"filesystems"})
    require(
        type(mount["filesystems"]) is list and len(mount["filesystems"]) == 1,
        "cgroup-mount",
    )
    row = mount["filesystems"][0]
    state.keys(row, {"target", "fstype"})
    require(
        row["fstype"] == "cgroup2"
        and observe.absolute(row["target"])
        and (
            Path(row["target"]) == CGROUP_ROOT.parent
            or Path(row["target"]) in CGROUP_ROOT.parent.parents
        ),
        "cgroup-mount",
    )
    path = CGROUP_ROOT / str(vmid)
    try:
        parent = CGROUP_ROOT.lstat()
        require(
            stat.S_ISDIR(parent.st_mode)
            and parent.st_uid == ROOT_UID
            and not parent.st_mode & 0o022
            and CGROUP_ROOT.resolve(strict=True) == CGROUP_ROOT,
            "cgroup-root",
        )
        info = path.lstat()
    except FileNotFoundError as error:
        require(error.errno == errno.ENOENT, "cgroup-unavailable")
        return {"state": "absent", "mount": row}
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == ROOT_UID
        and not info.st_mode & 0o022
        and path.resolve(strict=True) == path,
        "cgroup-directory",
    )
    raw = _kernel_file(path / "cgroup.events")
    rows = [line.split() for line in raw.splitlines()]
    require(
        len(rows) == 2
        and all(len(row) == 2 for row in rows)
        and len(dict(rows)) == 2
        and dict(rows) == {b"populated": b"0", b"frozen": b"0"},
        "cgroup-populated",
    )
    require(
        _kernel_file(path / "cgroup.procs") == b""
        and _kernel_file(path / "cgroup.events") == raw
        and _kernel_file(path / "cgroup.procs") == b"",
        "cgroup-processes",
    )
    identity = list(observe.stable(info))[:5]
    require(list(observe.stable(path.lstat()))[:5] == identity, "cgroup-changed")
    return {"state": "empty", "mount": row, "identity": identity}


def _root(profile):
    root = profile["rootfs"]
    identity = boot.root_identity(profile)
    same(identity, root["identity"], "root-identity")
    resolved = (
        observe.native(["/usr/sbin/pvesm", "path", root["volume"]]).decode().strip()
    )
    require(resolved == root["path"], "root-path")
    rows = [
        line.split("=", 1)
        for line in observe.native(
            ["/usr/sbin/blkid", "-p", "-o", "export", root["path"]]
        )
        .decode()
        .splitlines()
    ]
    require(
        all(len(row) == 2 for row in rows) and len(dict(rows)) == len(rows),
        "root-filesystem",
    )
    filesystem = dict(rows)
    require(
        filesystem.get("UUID") == root["uuid"] and filesystem.get("TYPE") == "ext4",
        "root-filesystem",
    )
    require(boot.root_identity(profile) == identity, "root-changed")
    return {"path": resolved, "identity": identity, "uuid": root["uuid"]}


def _entry_leased(checkpoint, phase, prior_runtime=None):
    """Pre-data admission under caller pair EX and both native SH leases."""
    require(type(phase) is str and phase in {"os_quiesced", "stopped"}, "phase")
    request, profile, expected = _authority(checkpoint)
    if prior_runtime is None:
        prior_runtime = expected
    validate_current(
        checkpoint,
        "os_quiesced",
        {
            "phase": "os_quiesced",
            "observation": prior_runtime,
            "guest_image_verified": True,
        },
    )
    guard = observe.load_guard(request["reference_guard"])
    host = observe.host_facts(request)
    _host(request, host)
    guest = observe.guest_facts(request["policy"])
    observe.validate_guest(request["policy"], guest)
    require(
        guest["status"] == ("running" if phase == "os_quiesced" else "stopped"),
        "guest-state",
    )
    same(guest["config"], profile["config"], "guest-config")
    if phase == "stopped":
        reference = runtime._stopped_reference_facts(request)
        runtime.validate_stopped_reference(request, reference)
        lxc = observe.native(
            ["/usr/bin/lxc-info", "-n", str(request["policy"]["vmid"]), "-sH"]
        )
        require(lxc == b"STOPPED\n", "lxc-not-stopped")
        stopped = {
            "lxc_state": "STOPPED",
            "cgroup": _empty_cgroup(request["policy"]["vmid"]),
            "prior_fence": _prior_fence(host, prior_runtime),
        }
    else:
        reference = runtime.reference_facts(request)
        stopped = None
    same(reference["files"], expected["reference"]["files"], "reference-identity")
    ownership = guard.collect_ownership(request["policy"])
    guard.validate_ownership(request["policy"], ownership)
    same(
        guard.ownership_seal(ownership),
        guard.ownership_seal(expected["retained"]["ownership"]),
        "ownership-changed",
    )
    return {
        "phase": phase,
        "host": host,
        "guest": guest,
        "reference": reference,
        "root": _root(profile),
        "ownership": ownership,
        "stopped": stopped,
    }


def _same_entry(before, after):
    left, right = copy.deepcopy(before), copy.deepcopy(after)
    first_uptime, last_uptime = (
        left["guest"]["runtime"]["uptime"],
        right["guest"]["runtime"]["uptime"],
    )
    left["guest"] = runtime.stable_guest(left["guest"])
    right["guest"] = runtime.stable_guest(right["guest"])
    same(left, right, "entry-changed")
    require(last_uptime >= first_uptime, "uptime-decreased")


def _close_file(path, identity):
    path = Path(path)
    runtime.control_parents(path)
    require(
        path.resolve(strict=True) == path
        and list(observe.stable(path.lstat())) == identity,
        "control-changed",
    )


def _fast_close(request, profile, entry, observed, guard):
    """Only fixed metadata/process identity probes follow the final worker."""
    same(boot.root_identity(profile), profile["rootfs"]["identity"], "root-changed")
    for path, info in entry["reference"]["files"].items():
        _close_file(path, info["identity"])
    for name, unit in entry["reference"]["units"].items():
        path = Path(f"/etc/systemd/system/{name}.d")
        runtime.attach.control_directory(path)
        require(
            sorted(child.name for child in path.iterdir())
            == unit["directory_membership"],
            "reference-membership",
        )
    policy = request["policy"]
    owner = guard.owner_path(policy)
    _close_file(owner, entry["ownership"]["file"]["identity"])
    require(
        list(observe.stable(owner.parent.lstat()))
        == entry["ownership"]["directory"]["identity"],
        "owner-directory-changed",
    )
    for name, unit in entry["ownership"]["retired"]["units"].items():
        preserved, denial = guard.retired_paths(policy, name)
        _close_file(preserved, unit["preserved_file"]["identity"])
        _close_file(denial, unit["denial_file"]["identity"])
        require(
            sorted(child.name for child in preserved.parent.iterdir())
            == unit["directory_membership"],
            "retired-membership",
        )
    if entry["phase"] == "os_quiesced":
        init = observed["observation"]["kernel"]["init"]
        require(
            runtime.kernel.reader.memory.init_state(init["pid"])
            == (init["pstart"], init["pid_namespace_inode"]),
            "init-changed",
        )


@contextmanager
def _current_leased(checkpoint, entry, raw, prior_runtime=None):
    """Borrow pair/native/application leases and close fresh evidence after yield."""
    with _current_worker_leased(checkpoint, entry, raw, prior_runtime) as first:
        yield first


@dataclass(frozen=True, slots=True)
class _CurrentFrames:
    initial_raw: bytes | None = None
    closing_raw: bytes | None = None

    @property
    def completed(self):
        return self.closing_raw is not None


@contextmanager
def _current_frames_leased(checkpoint, entry, raw, prior_runtime=None):
    """Retain canonical first/final frames; callers still own every outer lease.

    Completion here describes this worker context only. A controller must not
    publish a certificate until all its enclosing lease contexts also succeed.
    """
    frames = _CurrentFrames()
    with _current_worker_leased(checkpoint, entry, raw, prior_runtime, frames):
        yield frames


def _close_frames(frames, initial_raw):
    require(
        type(frames) is _CurrentFrames
        and type(frames.initial_raw) is bytes
        and frames.initial_raw == initial_raw
        and frames.closing_raw is None,
        "frame-capture-changed",
    )


@contextmanager
def _current_worker_leased(checkpoint, entry, raw, prior_runtime=None, frames=None):
    require(
        frames is None
        or (
            type(frames) is _CurrentFrames
            and frames.initial_raw is None
            and frames.closing_raw is None
        ),
        "frame-capture",
    )
    checkpoint, entry = copy.deepcopy(checkpoint), copy.deepcopy(entry)
    prior_runtime = copy.deepcopy(prior_runtime)
    request, profile, _ = _authority(checkpoint)
    phase = entry["phase"]
    guard, _, binding = runtime.load_profile(request, profile)
    guard = observe.load_guard(request["reference_guard"])
    require(
        type(raw) is bytes
        and state.sha256(raw) == request["policy"]["application"]["config_sha256"],
        "configuration-changed",
    )
    _same_entry(entry, _entry_leased(checkpoint, phase, prior_runtime))

    def collect_one():
        if phase == "os_quiesced":
            return runtime._collect_leased(
                request, profile, guard, binding, entry["host"], raw
            )
        with observe._stopped_source_leased(
            request, guard, entry["host"], raw
        ) as facts:
            observed = copy.deepcopy(facts)
        return observed

    first = {
        "phase": phase,
        "observation": collect_one(),
        "guest_image_verified": phase == "os_quiesced",
    }
    validate_current(checkpoint, phase, first)
    initial_raw = state.canonical(first) if frames is not None else None
    if frames is not None:
        object.__setattr__(frames, "initial_raw", initial_raw)
    yield copy.deepcopy(first)
    if frames is not None:
        _close_frames(frames, initial_raw)
    # All slow caller work and entry/control probes precede the closing worker.
    _same_entry(entry, _entry_leased(checkpoint, phase, prior_runtime))
    closing = {
        "phase": phase,
        "observation": collect_one(),
        "guest_image_verified": phase == "os_quiesced",
    }
    validate_current(checkpoint, phase, closing)
    if frames is not None:
        require(state.canonical(first) == initial_raw, "initial-frame-changed")
    if phase == "os_quiesced":
        left, right = copy.deepcopy(first), copy.deepcopy(closing)
        left["observation"]["guest"] = runtime.stable_guest(
            left["observation"]["guest"]
        )
        right["observation"]["guest"] = runtime.stable_guest(
            right["observation"]["guest"]
        )
        same(left, right, "current-changed")
        require(
            closing["observation"]["guest"]["runtime"]["uptime"]
            >= first["observation"]["guest"]["runtime"]["uptime"],
            "uptime-decreased",
        )
    else:
        same(first, closing, "current-changed")
    closing_raw = state.canonical(closing) if frames is not None else None
    _fast_close(request, profile, entry, closing, guard)
    if frames is not None:
        _close_frames(frames, initial_raw)
        require(state.canonical(first) == initial_raw, "initial-frame-changed")
        require(state.canonical(closing) == closing_raw, "closing-frame-changed")
        object.__setattr__(frames, "closing_raw", closing_raw)


def collect(checkpoint, *, phase, prior_runtime=None):
    """Read current owner state, acquiring existing leases and creating no metadata."""
    checkpoint = copy.deepcopy(checkpoint)
    request, _, _ = _authority(checkpoint)
    policy = request["policy"]
    with runtime.pair_lock.locked_pair(policy["datasets"]), ExitStack() as leases:
        for vmid in sorted((policy["vmid"], policy["retired_guest"]["vmid"])):
            leases.enter_context(runtime.config_lock.read_guest(vmid))
        entry = _entry_leased(checkpoint, phase, prior_runtime)
        path = Path(policy["datasets"]["config"]["mountpoint"]) / "application.json"
        uid, gid = (
            policy["mapping"]["offset"] + policy["mapping"][name]
            for name in ("uid", "gid")
        )
        with observe.locked_config(path, uid, gid) as raw:
            with _current_leased(checkpoint, entry, raw, prior_runtime) as result:
                observed = result
    return observed
