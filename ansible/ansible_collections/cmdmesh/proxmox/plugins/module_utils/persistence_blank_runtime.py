"""Read-only kernel and guest proof for a bind-free reference OS boot."""

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import re
import socket
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    memory_remote as memory,
    persistence_blank_guard as guard,
    persistence_observe as observe,
    persistence_recipient as recipient,
    persistence_state as state,
)

ABSENT_PATHS = (
    "/opt/reference-ledger",
    "/etc/systemd/system/reference-ledger.service",
    "/etc/reference-ledger",
    "/var/lib/reference-ledger",
    "/run/reference-ledger",
)
ROOT_UID = 0
LOCK_ROOT = Path("/run/lock/lxc")
API_FIELDS = {"config", "pending", "ha", "status", "source_status"}
KERNEL_FIELDS = {"init", "cgroup", "rootfs", "security", "generated_config"}


def require(value, code):
    state.require(value, "persistence-blank-runtime-" + code)


def mapping(value):
    require(
        type(value) is list
        and len(value) == 1
        and type(value[0]) is list
        and len(value[0]) == 3
        and all(type(part) is int for part in value[0])
        and value == [[0, 100000, 65536]],
        "id-map",
    )


def validate(policy, value):
    state.keys(value, API_FIELDS | KERNEL_FIELDS | {"guest"})
    validate_api(policy, {key: value[key] for key in API_FIELDS})
    validate_kernel(policy, {key: value[key] for key in KERNEL_FIELDS})
    validate_guest(policy, value["guest"], value["rootfs"], value["cgroup"]["cpus"])


def validate_api(policy, value):
    guard.validate_policy(policy)
    state.keys(value, API_FIELDS)
    require(
        state.canonical(value["config"]) == state.canonical(policy["config"]), "config"
    )
    require(
        state.canonical(value["pending"])
        == state.canonical(recipient.ordered_pending(value["pending"])),
        "pending",
    )
    rows = value["ha"]
    require(type(rows) is list and len(rows) <= 128, "ha")
    ids = []
    for row in rows:
        require(
            type(row) is dict
            and state.matches(r"(?:ct|vm):[1-9][0-9]*", row.get("sid")),
            "ha",
        )
        require(
            row["sid"]
            not in {
                f"ct:{policy['vmid']}",
                f"vm:{policy['vmid']}",
                f"ct:{policy['source_vmid']}",
                f"vm:{policy['source_vmid']}",
            },
            "ha-target",
        )
        ids.append(row["sid"])
    require(ids == sorted(set(ids)), "ha-order")
    current = value["status"]
    require(
        type(current) is dict
        and current.get("status") == "running"
        and current.get("name") == policy["config"]["hostname"]
        and current.get("type") == "lxc",
        "status",
    )
    for key, expected in (
        ("vmid", policy["vmid"]),
        ("cpus", 1),
        ("maxmem", 536870912),
        ("maxswap", 0),
        ("maxdisk", 2147483648),
    ):
        require(
            type(current.get(key)) is int and current[key] == expected, "runtime-config"
        )
    source = value["source_status"]
    require(
        type(source) is dict
        and source.get("status") == "stopped"
        and type(source.get("uptime")) is int
        and source["uptime"] == 0
        and type(source.get("pid", 0)) is int
        and source.get("pid", 0) == 0,
        "old-source-not-stopped",
    )


def validate_kernel(policy, value):
    state.keys(value, KERNEL_FIELDS)
    init = value["init"]
    state.keys(
        init,
        {
            "pid",
            "pstart",
            "pid_namespace_inode",
            "host_pid_namespace_inode",
            "uid_map",
            "gid_map",
        },
    )
    require(
        all(
            type(init[key]) is int and init[key] > 1
            for key in (
                "pid",
                "pstart",
                "pid_namespace_inode",
                "host_pid_namespace_inode",
            )
        )
        and init["pid_namespace_inode"] != init["host_pid_namespace_inode"],
        "init-identity",
    )
    mapping(init["uid_map"])
    mapping(init["gid_map"])
    cgroup = value["cgroup"]
    state.keys(
        cgroup,
        {"path", "effective_memory_bytes", "memory_max", "swap_max", "cpu_max", "cpus"},
    )
    require(
        state.matches(
            r"0::/lxc/"
            + str(policy["vmid"])
            + r"/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+",
            cgroup["path"],
        )
        and all(part not in {".", ".."} for part in cgroup["path"].split("/")),
        "cgroup-target",
    )
    require(
        type(cgroup["effective_memory_bytes"]) is int
        and cgroup["effective_memory_bytes"] == 536870912
        and cgroup["memory_max"] == "536870912"
        and cgroup["swap_max"] == "0"
        and cgroup["cpu_max"] == "100000 100000",
        "enforced-limits",
    )
    cpus = cgroup["cpus"]
    require(
        type(cpus) is list
        and len(cpus) == 1
        and type(cpus[0]) is int
        and cpus[0] in policy["cpu_policy"]["allowed"],
        "enforced-cpu",
    )
    root = value["rootfs"]
    state.keys(
        root,
        {
            "path",
            "identity",
            "uuid",
            "resolved_path",
            "backing_file",
            "device",
            "filesystem_type",
        },
    )
    guard.validate_root(
        {key: root[key] for key in ("path", "identity", "uuid", "resolved_path")},
        policy["vmid"],
        observed=True,
    )
    require(
        state.canonical({key: root[key] for key in policy["rootfs"]})
        == state.canonical(policy["rootfs"])
        and root["backing_file"] == root["path"]
        and root["filesystem_type"] == "ext4"
        and type(root["device"]) is list
        and len(root["device"]) == 2
        and all(type(part) is int and part >= 0 for part in root["device"])
        and root["device"][0] == 7,
        "root-backing",
    )
    security = value["security"]
    state.keys(security, {"net_namespace", "host_net_namespace", "apparmor_label"})
    require(
        all(
            state.matches(r"net:\[[1-9][0-9]*\]", security[key])
            for key in ("net_namespace", "host_net_namespace")
        )
        and security["net_namespace"] != security["host_net_namespace"],
        "network-namespace",
    )
    profile = f"lxc-{policy['vmid']}_</var/lib/lxc>"
    nested = f":lxc-{policy['vmid']}_<-var-lib-lxc>:"
    require(
        security["apparmor_label"]
        in {profile + " (enforce)", profile + "//&" + nested + "unconfined (enforce)"},
        "apparmor",
    )
    require(type(value["generated_config"]) is str, "generated-config")
    fingerprint, selected = guard.generated_fingerprint(
        value["generated_config"].encode()
    )
    require(
        fingerprint == policy["generated_config_stable_sha256"]
        and len(selected) <= 1
        and set(selected) <= set(policy["cpu_policy"]["allowed"]),
        "generated-config",
    )


def validate_guest(policy, guest, root, cpus):
    require(
        type(guest) is dict
        and type(guest.get("uid")) is int
        and guest["uid"] == 0
        and type(guest.get("gid")) is int
        and guest["gid"] == 0,
        "guest-user",
    )
    mapping(guest["uid_map"])
    mapping(guest["gid_map"])
    require(
        guest["hostname"] == policy["config"]["hostname"]
        and guest["interfaces"] == ["lo"]
        and type(guest["affinity"]) is list
        and all(type(part) is int for part in guest["affinity"])
        and guest["affinity"] == cpus
        and type(guest["root_device"]) is int
        and guest["root_device"] == os.makedev(*root["device"]),
        "guest-identity",
    )
    require(
        state.matches(r"[a-f0-9]{64}", guest["machine_id_sha256"])
        and guest["machine_id_sha256"] != policy["machine_id_sha256"],
        "guest-machine-id",
    )
    python = guest["python"]
    require(
        type(python) is list
        and len(python) == 3
        and all(type(part) is int and part >= 0 for part in python)
        and python[:2] == [3, 12]
        and state.matches(r"3\.[0-9]+\.[0-9]+", guest["sqlite"])
        and tuple(int(part) for part in guest["sqlite"].split(".")) >= (3, 37, 0),
        "guest-runtime",
    )
    require(
        type(guest["paths_absent"]) is dict
        and set(guest["paths_absent"]) == set(ABSENT_PATHS)
        and all(part is True for part in guest["paths_absent"].values())
        and all(
            guest[key] is True
            for key in ("uid_unused", "gid_unused", "account_names_unused")
        ),
        "guest-not-blank",
    )
    require(
        all(type(guest[key].get("code")) is int for key in ("systemd", "failed_units")),
        "guest-status-type",
    )
    require(
        guest["systemd"] == {"code": 0, "stdout": "running\n", "stderr": ""}
        and guest["failed_units"] == {"code": 0, "stdout": "", "stderr": ""},
        "guest-not-ready",
    )


GUEST = """import grp,hashlib,json,os,pathlib,pwd,re,socket,sqlite3,subprocess,sys
def maps(name):return [[int(p) for p in row.split()] for row in pathlib.Path('/proc/self/'+name).read_text().splitlines()]
machine=pathlib.Path('/etc/machine-id').read_bytes().strip()
if re.fullmatch(b'[a-f0-9]{32}',machine) is None:raise ValueError('guest machine identity')
r={'uid':os.geteuid(),'gid':os.getegid(),'python':list(sys.version_info[:3]),'sqlite':sqlite3.sqlite_version,'hostname':socket.gethostname(),'interfaces':sorted(name for _,name in socket.if_nameindex()),'affinity':sorted(os.sched_getaffinity(0)),'uid_map':maps('uid_map'),'gid_map':maps('gid_map'),'root_device':os.stat('/').st_dev,'machine_id_sha256':hashlib.sha256(machine).hexdigest()}
r['paths_absent']={p:not os.path.lexists(p) for p in ABSENT}
r['uid_unused']=not any(p.pw_uid==1100 for p in pwd.getpwall());r['gid_unused']=not any(g.gr_gid==1100 for g in grp.getgrall())
r['account_names_unused']=not any(p.pw_name=='reference-ledger' for p in pwd.getpwall()) and not any(g.gr_name=='reference-ledger' for g in grp.getgrall())
for key,argv in {'systemd':['/usr/bin/systemctl','is-system-running'],'failed_units':['/usr/bin/systemctl','--failed','--plain','--no-legend','--no-pager']}.items():
 p=subprocess.run(argv,capture_output=True,timeout=15);r[key]={'code':p.returncode,'stdout':p.stdout.decode(),'stderr':p.stderr.decode()}
print(json.dumps(r))
""".replace("ABSENT", repr(ABSENT_PATHS))


def kernel(policy):
    vmid = policy["vmid"]
    pid = memory.lxc_pid(vmid)
    born, pidns = memory.init_state(pid)
    process = Path("/proc") / str(pid)
    device = (process / "root").stat().st_dev
    require(os.major(device) == 7, "root-device")
    backing = memory.read_text(
        f"/sys/dev/block/{os.major(device)}:{os.minor(device)}/loop/backing_file"
    ).strip()
    raw = observe.native(
        ["/usr/sbin/blkid", "-p", "-o", "export", "/dev/loop" + str(os.minor(device))]
    ).decode()
    filesystem = {}
    for line in raw.splitlines():
        key, separator, item = line.partition("=")
        require(separator == "=" and key not in filesystem, "filesystem")
        filesystem[key] = item
    image = Path(policy["rootfs"]["path"])
    require(image.resolve(strict=True) == image, "image-path")
    info = image.lstat()
    volume = policy["config"]["rootfs"].split(",", 1)[0]
    resolved = observe.native(["/usr/sbin/pvesm", "path", volume]).decode().strip()
    limit, cgroup = memory.memory_limit(pid)
    base = Path("/sys/fs/cgroup/lxc") / str(vmid)
    require(base.resolve(strict=True) == base, "cgroup-path")
    generated_path = f"/var/lib/lxc/{vmid}/config"
    generated, generated_info = observe.read_regular(generated_path, 65536)
    require(
        generated_info.st_uid == ROOT_UID and not generated_info.st_mode & 0o022,
        "generated-owner",
    )
    maps = lambda name: [
        [int(part) for part in row.split()]
        for row in memory.read_text(process / name).splitlines()
    ]
    result = {
        "init": {
            "pid": pid,
            "pstart": born,
            "pid_namespace_inode": pidns,
            "host_pid_namespace_inode": memory.namespace_inode(1),
            "uid_map": maps("uid_map"),
            "gid_map": maps("gid_map"),
        },
        "cgroup": {
            "path": cgroup.strip(),
            "effective_memory_bytes": limit,
            "memory_max": memory.read_text(base / "memory.max").strip(),
            "swap_max": memory.read_text(base / "memory.swap.max").strip(),
            "cpu_max": memory.read_text(base / "cpu.max").strip(),
            "cpus": guard.cpu_list(
                memory.read_text(base / "cpuset.cpus.effective").strip()
            ),
        },
        "rootfs": {
            "path": str(image),
            "identity": guard.identity(info),
            "uuid": filesystem.get("UUID"),
            "resolved_path": resolved,
            "backing_file": backing,
            "device": [os.major(device), os.minor(device)],
            "filesystem_type": filesystem.get("TYPE"),
        },
        "security": {
            "net_namespace": os.readlink(process / "ns/net"),
            "host_net_namespace": os.readlink("/proc/1/ns/net"),
            "apparmor_label": memory.read_text(process / "attr/current").strip(),
        },
        "generated_config": generated.decode(),
    }
    require(
        memory.lxc_pid(vmid) == pid and memory.init_state(pid) == (born, pidns),
        "init-changed",
    )
    require(
        observe.native(["/usr/sbin/pvesm", "path", volume]).decode().strip() == resolved
        and observe.native(
            [
                "/usr/sbin/blkid",
                "-p",
                "-o",
                "export",
                "/dev/loop" + str(os.minor(device)),
            ]
        ).decode()
        == raw,
        "backing-changed",
    )
    closing_generated, closing_info = observe.read_regular(generated_path, 65536)
    require(
        closing_generated == generated
        and observe.stable(closing_info) == observe.stable(generated_info),
        "generated-changed",
    )
    require(
        image.resolve(strict=True) == image
        and guard.identity(image.lstat()) == guard.identity(info)
        and (process / "root").stat().st_dev == device
        and memory.read_text(
            f"/sys/dev/block/{os.major(device)}:{os.minor(device)}/loop/backing_file"
        ).strip()
        == backing
        and maps("uid_map") == result["init"]["uid_map"]
        and maps("gid_map") == result["init"]["gid_map"]
        and memory.memory_limit(pid) == (limit, cgroup)
        and memory.read_text(base / "memory.max").strip()
        == result["cgroup"]["memory_max"]
        and memory.read_text(base / "memory.swap.max").strip()
        == result["cgroup"]["swap_max"]
        and memory.read_text(base / "cpu.max").strip() == result["cgroup"]["cpu_max"]
        and guard.cpu_list(memory.read_text(base / "cpuset.cpus.effective").strip())
        == result["cgroup"]["cpus"]
        and os.readlink(process / "ns/net") == result["security"]["net_namespace"]
        and os.readlink("/proc/1/ns/net") == result["security"]["host_net_namespace"]
        and memory.read_text(process / "attr/current").strip()
        == result["security"]["apparmor_label"]
        and memory.init_state(pid) == (born, pidns),
        "closing-kernel-changed",
    )
    return result


def api(policy):
    base = f"/nodes/{policy['node']}/lxc/"
    current = recipient.get(base + str(policy["vmid"]) + "/status/current")
    status = {
        key: current.get(key)
        for key in (
            "status",
            "vmid",
            "name",
            "type",
            "cpus",
            "maxmem",
            "maxswap",
            "maxdisk",
        )
    }
    return {
        "config": recipient.get(base + str(policy["vmid"]) + "/config"),
        "pending": recipient.ordered_pending(
            recipient.get(base + str(policy["vmid"]) + "/pending")
        ),
        "ha": sorted(
            recipient.get("/cluster/ha/resources"), key=lambda row: row["sid"]
        ),
        "status": status,
        "source_status": recipient.get(
            base + str(policy["source_vmid"]) + "/status/current"
        ),
    }


@contextmanager
def target_read_lock(policy):
    guard.validate_policy(policy)
    require(LOCK_ROOT.resolve(strict=True) == LOCK_ROOT, "native-lock-directory")
    path = LOCK_ROOT / f"pve-config-{policy['vmid']}.lock"
    require(path.resolve(strict=True) == path, "native-lock-path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == ROOT_UID
            and before.st_nlink == 1
            and not before.st_mode & 0o022
            and observe.stable(before) == observe.stable(path.lstat()),
            "native-lock-file",
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise state.PersistenceError(
                "persistence-blank-runtime-native-lock-busy"
            ) from None
        yield
        require(
            observe.stable(before)
            == observe.stable(os.fstat(fd))
            == observe.stable(path.lstat()),
            "native-lock-changed",
        )
    finally:
        os.close(fd)


def collect(policy):
    guard.validate_policy(policy)
    require(
        os.geteuid() == ROOT_UID and socket.gethostname() == policy["node"],
        "host-required",
    )
    machine, _ = observe.read_regular("/etc/machine-id", 64)
    require(state.sha256(machine.strip()) == policy["machine_id_sha256"], "wrong-host")
    with target_read_lock(policy):
        return collect_locked(policy)


def collect_locked(policy):
    before_api = api(policy)
    validate_api(policy, before_api)
    before_kernel = kernel(policy)
    validate_kernel(policy, before_kernel)
    guest = observe.decode(
        observe.native(
            [
                "/usr/sbin/pct",
                "exec",
                str(policy["vmid"]),
                "--",
                "/usr/bin/python3",
                "-I",
                "-S",
                "-B",
                "-c",
                GUEST,
            ]
        )
    )
    # Repeat slow API reads before the final kernel identity pass. Counter/uptime
    # changes in a running guest are intentionally outside this projection.
    after_api, after_kernel = api(policy), kernel(policy)
    require(
        state.canonical(before_api) == state.canonical(after_api)
        and state.canonical(before_kernel) == state.canonical(after_kernel),
        "state-changed",
    )
    value = {**after_api, **after_kernel, "guest": guest}
    validate(policy, value)
    return value
