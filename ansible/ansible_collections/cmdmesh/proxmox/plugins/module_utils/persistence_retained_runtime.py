"""Read-only retained-runtime evidence primitives; no lifecycle operations.

These bind checks require previously admitted ownership, host/native leases and
kernel evidence. They do not establish application quiescence or restore health.
"""

from contextlib import ExitStack
import copy
import os
from pathlib import Path
import stat
from types import SimpleNamespace

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_kernel as kernel,
    persistence_attach as attach,
    persistence_config_lock as config_lock,
    persistence_observe as observe,
    persistence_pair_lock as pair_lock,
    persistence_state as state,
    systemd_exec as execution,
)

PROC_ROOT = Path("/proc")
GUEST_BINDS = {"data": "/var/lib/reference-ledger", "config": "/etc/reference-ledger"}
IMAGE_SHA = "21bd1353bc6c95f4e4e4b94010c16c5e74b5ae8fb7434e94e3d39dfdb0357227"
GUARD_SHA = observe.FIXED_HANDOFF_GUARD_SHA256
IMAGE_DIRECTORIES = (
    "/opt",
    "/opt/reference-ledger",
    "/etc",
    "/etc/systemd",
    "/etc/systemd/system",
)
FLAGS = {
    "mutation_attempted": False,
    "boot_verified": False,
    "rebuild_verified": False,
    "restore_verified": False,
    "backup_verified": False,
}

GUEST_IMAGE = r"""import hashlib,json,os,socket,sys
from pathlib import Path
from types import SimpleNamespace
source=sys.argv[1]
if hashlib.sha256(source.encode()).hexdigest()!='21bd1353bc6c95f4e4e4b94010c16c5e74b5ae8fb7434e94e3d39dfdb0357227':raise ValueError('image-source')
ns={'__name__':'cmdmesh_runtime_image'}
exec(compile(source,'<cmdmesh-runtime-image>','exec'),ns)
h=SimpleNamespace(**ns)
h.require(len(sys.argv) in (2,3))
writer=None if len(sys.argv)==2 else int(sys.argv[2])
h.require(writer is None or 1<writer<2**31)
def processes(accounts):
 if writer is None:h.validate_no_writer(accounts)
 else:h.require(accounts['home_exists'] is False and accounts['uid_processes']==accounts['gid_processes']==[writer])
def identity(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
def guest():return {'hostname':socket.gethostname(),'root_device':os.stat('/').st_dev,'affinity':sorted(os.sched_getaffinity(0))}
def directories():
 result={}
 for name in ('/opt','/opt/reference-ledger','/etc','/etc/systemd','/etc/systemd/system'):
  h.directory(name,0o755);result[name]=identity(h.path(name).lstat())
 return result
def artifacts():
 result={}
 for name in (h.PROGRAM,h.UNIT_PATH):
  raw,info=h.regular(name,65536);result[name]={'sha256':hashlib.sha256(raw).hexdigest(),'identity':list(info)}
 return result
environment=h.environment();h.validate_environment(environment)
unit=h.unit();child=h.read_as_application();accounts=h.accounts();processes(accounts)
files=artifacts();dirs=directories();who=guest()
if h.environment()!=environment or h.unit()!=unit or h.account_files()!=accounts['files']:raise ValueError('guest-image-changed')
closing_accounts=h.accounts();processes(closing_accounts)
if closing_accounts!=accounts:raise ValueError('guest-image-changed')
if artifacts()!=files or directories()!=dirs or guest()!=who:raise ValueError('guest-image-changed')
print(json.dumps({'environment':environment,'unit':unit,'accounts':accounts,'application_read':child,'artifacts':files,'directories':dirs,'identity':who}))
"""


def require(value, code):
    state.require(value, "persistence-retained-runtime-" + code)


def known_program(source, checksum, name):
    require(type(source) is str, "program-source")
    raw = source.encode()
    require(0 < len(raw) <= 65536 and state.sha256(raw) == checksum, "program-source")
    namespace = {"__name__": name}
    exec(compile(raw, "<" + name + ">", "exec"), namespace)
    return SimpleNamespace(**namespace)


def load_profile(request, profile):
    state.keys(
        profile,
        {
            "schema_version",
            "guard_python",
            "image_python",
            "config",
            "rootfs",
            "accounts",
        },
    )
    require(
        type(profile["schema_version"]) is int and profile["schema_version"] == 1,
        "profile-version",
    )
    guard = known_program(profile["guard_python"], GUARD_SHA, "cmdmesh_retained_guard")
    image = known_program(profile["image_python"], IMAGE_SHA, "cmdmesh_retained_image")
    observe.validate_request(request, guard)
    policy = request["policy"]
    require(
        type(policy["schema_version"]) is int and policy["schema_version"] == 3,
        "owner-policy",
    )
    state.keys(request["reference_guard"], {"path", "sha256"})
    reference = Path(request["reference_guard"]["path"])
    require(
        observe.absolute(str(reference))
        and request["reference_guard"]["sha256"] == GUARD_SHA,
        "guard-reference",
    )
    require(state.matches(r"/[A-Za-z0-9_./-]+", str(reference)), "guard-reference")
    require(
        all(
            reference != Path(item["mountpoint"])
            and Path(item["mountpoint"]) not in reference.parents
            for item in policy["datasets"].values()
        ),
        "guard-inside-retained-state",
    )
    root = profile["rootfs"]
    state.keys(root, {"path", "identity", "uuid", "volume"})
    require(type(root["identity"]) is list, "root-identity")
    state.integer(policy["cpu_policy"]["count"], 1, 1)
    binding = kernel.KernelBinding(
        node=policy["node"],
        machine_id_sha256=request["source"]["host_profile"]["machine_id_sha256"],
        vmid=policy["vmid"],
        volume=root["volume"],
        root_path=root["path"],
        root_identity=tuple(root["identity"]),
        root_uuid=root["uuid"],
        generated_sha256=policy["generated_config_stable_sha256"],
        allowed_cpus=tuple(policy["cpu_policy"]["allowed"]),
    )
    expected_root = {
        "path": root["path"],
        "volume": root["volume"],
        "uuid": root["uuid"],
        "inode": root["identity"][1],
        "bytes": root["identity"][6],
    }
    require(
        state.canonical(policy["rootfs"]) == state.canonical(expected_root),
        "root-policy-mismatch",
    )
    config = profile["config"]
    require(
        type(config) is dict
        and config.get("arch") == "amd64"
        and config.get("ostype") == "ubuntu"
        and config.get("cpulimit") == "1",
        "image-config",
    )
    for key, expected in (
        ("cores", 1),
        ("memory", 512),
        ("swap", 0),
        ("unprivileged", 1),
        ("onboot", 0),
        ("protection", 1),
    ):
        require(
            type(config.get(key)) is int and config[key] == expected, "image-config"
        )
    state.keys(profile["accounts"], {"base", "subids"})
    state.keys(profile["accounts"]["base"], image.ACCOUNT_DATABASES)
    state.keys(profile["accounts"]["subids"], image.SUBID_DATABASES)
    for value in profile["accounts"]["base"].values():
        state.digest(value)
    for value in profile["accounts"]["subids"].values():
        if value is not None:
            state.digest(value)
    return guard, image, binding


def file_identity(value, *, directory=False):
    require(
        type(value) is list
        and len(value) == 9
        and all(type(part) is int and part >= 0 for part in value),
        "image-file-identity",
    )
    require(
        (stat.S_ISDIR if directory else stat.S_ISREG)(value[2])
        and value[3] == 0
        and not value[2] & 0o7022
        and (value[5] >= 2 if directory else value[5] == 1)
        and value[6] <= 1048576,
        "image-file-identity",
    )


def validate_image(profile, image, evidence, kernel_evidence, *, writer_pid=None):
    """Validate image facts for quiescence or one explicitly identified writer.

    An active image is not complete process, socket or application acceptance.
    Existing quiesced collectors never supply ``writer_pid``.
    """
    require(
        writer_pid is None or type(writer_pid) is int and 1 < writer_pid < 2**31,
        "writer-pid",
    )
    state.keys(
        evidence,
        {
            "environment",
            "unit",
            "accounts",
            "application_read",
            "artifacts",
            "identity",
            "directories",
        },
    )
    environment = evidence["environment"]
    state.keys(
        environment,
        {
            "uid",
            "gid",
            "uid_map",
            "gid_map",
            "interfaces",
            "python",
            "sqlite",
            "systemd",
            "failed",
        },
    )
    require(
        type(environment["python"]) is list
        and len(environment["python"]) == 3
        and all(type(part) is int and part >= 0 for part in environment["python"]),
        "guest-python",
    )
    require(
        type(environment["uid"]) is int
        and type(environment["gid"]) is int
        and state.matches(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", environment["sqlite"]),
        "guest-environment",
    )
    for key in ("systemd", "failed"):
        state.keys(environment[key], {"code", "stdout", "stderr"})
        require(type(environment[key]["code"]) is int, "guest-environment")
    image.validate_environment(environment)
    expected_unit = {
        "LoadState": "loaded",
        "ActiveState": "inactive" if writer_pid is None else "active",
        "SubState": "dead" if writer_pid is None else "running",
        "MainPID": "0" if writer_pid is None else str(writer_pid),
        "UnitFileState": "disabled",
        "User": "1100",
        "Group": "1100",
        "DropInPaths": "",
        "FragmentPath": image.UNIT_PATH,
    }
    require(
        state.canonical(evidence["unit"]) == state.canonical(expected_unit),
        "application-not-quiesced",
    )
    account = evidence["accounts"]
    state.keys(
        account,
        {
            "uid_owners",
            "gid_owners",
            "names_used",
            "account",
            "uid_processes",
            "gid_processes",
            "home_exists",
            "base",
            "subids",
            "files",
        },
    )
    if writer_pid is None:
        image.validate_no_writer(account)
    else:
        require(
            account["home_exists"] is False
            and type(account["uid_processes"]) is list
            and type(account["gid_processes"]) is list
            and all(
                type(pid) is int
                for pid in account["uid_processes"] + account["gid_processes"]
            )
            and account["uid_processes"] == account["gid_processes"] == [writer_pid],
            "writer-processes",
        )
    require(
        account["names_used"] is True
        and account["uid_owners"] == account["gid_owners"] == ["reference-ledger"]
        and state.canonical(account["account"]) == state.canonical(image.ACCOUNT),
        "application-account",
    )
    require(
        state.canonical({key: account[key] for key in ("base", "subids")})
        == state.canonical(profile["accounts"]),
        "account-baseline-changed",
    )
    state.keys(account["files"], {*image.ACCOUNT_DATABASES, *image.SUBID_DATABASES})
    for name, item in account["files"].items():
        if (
            name in image.SUBID_DATABASES
            and profile["accounts"]["subids"][name] is None
        ):
            require(item is None, "account-baseline-changed")
            continue
        state.keys(item, {"sha256", "identity"})
        state.digest(item["sha256"])
        file_identity(item["identity"])
        if name in image.SUBID_DATABASES:
            require(
                item["sha256"] == profile["accounts"]["subids"][name],
                "account-baseline-changed",
            )
    require(
        state.canonical(evidence["application_read"])
        == state.canonical(
            {"uid": 1100, "gid": 1100, "sha256": image.PROGRAM_SHA256, "compiled": True}
        ),
        "application-program",
    )
    expected = {
        image.PROGRAM: image.PROGRAM_SHA256,
        image.UNIT_PATH: state.sha256(image.service_unit()),
    }
    state.keys(evidence["artifacts"], expected)
    for name, digest in expected.items():
        item = evidence["artifacts"][name]
        state.keys(item, {"sha256", "identity"})
        file_identity(item["identity"])
        require(
            item["sha256"] == digest
            and stat.S_IMODE(item["identity"][2]) == 0o644
            and item["identity"][4] == 0
            and item["identity"][6] > 0,
            "application-artifact",
        )
    state.keys(evidence["directories"], IMAGE_DIRECTORIES)
    for identity in evidence["directories"].values():
        file_identity(identity, directory=True)
        require(
            identity[4] == 0 and stat.S_IMODE(identity[2]) == 0o755, "image-directory"
        )
    identity = evidence["identity"]
    state.keys(identity, {"hostname", "root_device", "affinity"})
    require(
        identity["hostname"] == profile["config"]["hostname"]
        and type(identity["root_device"]) is int
        and identity["root_device"] == os.makedev(*kernel_evidence["rootfs"]["device"])
        and state.canonical(identity["affinity"])
        == state.canonical(kernel_evidence["cgroup"]["cpus"]),
        "guest-root-identity",
    )


def validate_bindings(policy, retained, evidence):
    state.keys(evidence, GUEST_BINDS)
    devices = []
    for role, target in GUEST_BINDS.items():
        item = evidence[role]
        state.keys(item, {"host", "guest", "mount"})
        for name in ("host", "guest"):
            state.keys(item[name], {"device", "inode"})
            require(
                all(type(value) is int and value > 0 for value in item[name].values()),
                "bind-identity",
            )
        require(
            item["host"] == item["guest"]
            and item["host"]["inode"]
            == retained["datasets"][role]["directory"]["inode"],
            "bind-identity",
        )
        mount = item["mount"]
        state.keys(
            mount,
            {
                "id",
                "device",
                "root",
                "target",
                "source",
                "filesystem",
                "options",
                "super_options",
            },
        )
        state.integer(mount["id"], 1, 2**64 - 1)
        require(
            state.canonical(mount["device"])
            == state.canonical(
                [os.major(item["host"]["device"]), os.minor(item["host"]["device"])]
            )
            and mount["root"] == "/"
            and mount["target"] == target
            and mount["source"] == policy["datasets"][role]["name"]
            and mount["filesystem"] == "zfs",
            "guest-mount",
        )
        for key in ("options", "super_options"):
            options = mount[key]
            require(
                type(options) is list
                and all(
                    type(option) is str and 0 < len(option) <= 256 for option in options
                )
                and options == sorted(set(options))
                and "rw" in options
                and "ro" not in options,
                "guest-mount",
            )
        devices.append(item["host"]["device"])
    require(len(set(devices)) == 2, "shared-bind-device")


def reference_argv(request):
    program = request["reference_guard"]["path"]
    return [
        "/usr/bin/python3",
        "-I",
        "-S",
        "-B",
        program,
        "--manifest",
        str(Path(program).parent / "policy.json"),
        "--vmid",
        str(request["policy"]["vmid"]),
    ]


def reference_units(request):
    vmid = request["policy"]["vmid"]
    return (f"pve-container@{vmid}.service", f"pve-container-debug@{vmid}.service")


def reference_body(request):
    argv = reference_argv(request)
    return ("[Service]\nExecStartPre=" + " ".join([*argv[:-1], "%i"]) + "\n").encode()


def reference_paths(request):
    program = request["reference_guard"]["path"]
    files = {
        program: GUARD_SHA,
        str(Path(program).parent / "policy.json"): state.sha256(
            state.canonical(request["policy"])
        ),
    }
    for unit in reference_units(request):
        files[f"/etc/systemd/system/{unit}.d/50-cmdmesh-reference.conf"] = state.sha256(
            reference_body(request)
        )
    return files


def validate_reference(request, evidence):
    _validate_reference(request, evidence, "os_quiesced")


def validate_stopped_reference(request, evidence):
    """Validate inactive target declarations without claiming guard execution."""
    _validate_reference(request, evidence, "stopped")


def _validate_reference(request, evidence, phase):
    require(phase in {"os_quiesced", "stopped"}, "reference-phase")
    state.keys(evidence, {"files", "units"})
    expected = reference_paths(request)
    state.keys(evidence["files"], expected)
    for path, checksum in expected.items():
        info = evidence["files"][path]
        state.keys(info, {"path", "sha256", "identity"})
        file_identity(info["identity"])
        require(
            info["path"] == path
            and info["sha256"] == checksum
            and info["identity"][4] == 0
            and stat.S_IMODE(info["identity"][2]) == 0o600,
            "reference-file",
        )
    state.keys(evidence["units"], reference_units(request))
    for index, unit in enumerate(reference_units(request)):
        info = evidence["units"][unit]
        state.keys(
            info,
            {
                "LoadState",
                "ActiveState",
                "MainPID",
                "DropInPaths",
                "commands",
                "directory_membership",
            },
        )
        path = f"/etc/systemd/system/{unit}.d/50-cmdmesh-reference.conf"
        require(
            info["LoadState"] == "loaded"
            and info["ActiveState"]
            == ("active" if phase == "os_quiesced" and index == 0 else "inactive")
            and type(info["MainPID"]) is int
            and (
                1 < info["MainPID"] < 2**32
                if phase == "os_quiesced" and index == 0
                else info["MainPID"] == 0
            )
            and info["DropInPaths"] == [path]
            and info["directory_membership"] == ["50-cmdmesh-reference.conf"],
            "reference-unit",
        )
        require(
            type(info["commands"]) is list and len(info["commands"]) == 1,
            "reference-command",
        )
        command = info["commands"][0]
        state.keys(command, execution.FIELDS)
        execution.decode_commands(
            state.canonical(
                {
                    "type": "a(sasbttttuii)",
                    "data": [[command[field] for field in execution.FIELDS]],
                }
            )
        )
        require(
            command["path"] == reference_argv(request)[0]
            and command["argv"] == reference_argv(request)
            and command["ignore_errors"] is False,
            "reference-command",
        )
        if phase == "os_quiesced" and index == 0:
            require(
                command["code"] == 1
                and command["status"] == 0
                and command["pid"] > 1
                and 0 < command["start_monotonic_us"] <= command["stop_monotonic_us"]
                and 0 < command["start_real_us"] <= command["stop_real_us"],
                "reference-command-unexecuted",
            )


def validate(request, profile, phase, evidence):
    require(phase == "os_quiesced", "phase-unsupported")
    guard, image, binding = load_profile(request, profile)
    state.keys(
        evidence,
        {
            "schema_version",
            "phase",
            "source",
            "host",
            "guest",
            "kernel",
            "retained",
            "bindings",
            "image",
            "application",
            "reference",
            "os_runtime_verified",
            "application_quiesced",
            *FLAGS,
        },
    )
    require(
        type(evidence["schema_version"]) is int
        and evidence["schema_version"] == 1
        and evidence["phase"] == phase
        and evidence["os_runtime_verified"] is True
        and evidence["application_quiesced"] is True
        and all(evidence[key] is value for key, value in FLAGS.items()),
        "result-flags",
    )
    require(
        state.canonical(evidence["source"]) == state.canonical(request["source"]),
        "source-identity",
    )
    host = evidence["host"]
    state.keys(host, {"host_profile", "versions", "boot_id", "mount_namespace"})
    require(
        state.canonical(host["host_profile"])
        == state.canonical(request["source"]["host_profile"])
        and state.canonical(host["versions"]) == state.canonical(request["versions"])
        and state.matches(
            r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", host["boot_id"]
        )
        and state.matches(r"mnt:\[[1-9][0-9]*\]", host["mount_namespace"]),
        "host-identity",
    )
    guest = evidence["guest"]
    state.keys(guest, {"config", "status", "pending", "ha_membership", "runtime"})
    observe.validate_guest(request["policy"], guest)
    require(
        guest["status"] == "running"
        and state.canonical(guest["config"]) == state.canonical(profile["config"]),
        "guest-config",
    )
    kernel.validate(binding, evidence["kernel"])
    require(
        guest["runtime"]["pid"] in (0, evidence["kernel"]["init"]["pid"]), "guest-init"
    )
    retained = evidence["retained"]
    guard.validate(request["policy"], retained, request["policy"]["vmid"])
    require(
        state.canonical(retained["config"]) == state.canonical(guest["config"]),
        "retained-config",
    )
    validate_bindings(request["policy"], retained, evidence["bindings"])
    validate_image(profile, image, evidence["image"], evidence["kernel"])
    validate_reference(request, evidence["reference"])
    application = evidence["application"]
    state.keys(
        application,
        {
            "instance_id",
            "config_sha256",
            "mapping",
            "database_sha256",
            "records_sha256",
            "record_count",
        },
    )
    require(
        application["instance_id"] == request["policy"]["application"]["instance_id"]
        and application["config_sha256"]
        == request["policy"]["application"]["config_sha256"]
        and state.canonical(application["mapping"])
        == state.canonical(request["policy"]["mapping"]),
        "application-identity",
    )
    state.digest(application["database_sha256"])
    state.digest(application["records_sha256"])
    state.integer(application["record_count"], 1, 4096)


def guest_image(request, profile, *, writer_pid=None):
    require(
        writer_pid is None or type(writer_pid) is int and 1 < writer_pid < 2**31,
        "writer-pid",
    )
    return observe.decode(
        observe.native(
            [
                "/usr/sbin/pct",
                "exec",
                str(request["policy"]["vmid"]),
                "--",
                "/usr/bin/python3",
                "-I",
                "-S",
                "-B",
                "-c",
                GUEST_IMAGE,
                profile["image_python"],
            ]
            + ([] if writer_pid is None else [str(writer_pid)])
        )
    )


def control_parents(path):
    for parent in (path.parent, *path.parent.parents):
        attach.control_directory(parent)


def reference_files(request):
    result = {}
    for path, checksum in reference_paths(request).items():
        control_parents(Path(path))
        raw, info = observe.read_regular(path, 65536)
        require(
            state.sha256(raw) == checksum
            and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o600,
            "reference-file",
        )
        result[path] = {
            "path": path,
            "sha256": checksum,
            "identity": list(observe.stable(info)),
        }
    return result


def reference_facts(request):
    return _reference_facts(request, "os_quiesced")


def _stopped_reference_facts(request):
    return _reference_facts(request, "stopped")


def _reference_facts(request, phase):
    files = reference_files(request)
    units = {}
    for unit in reference_units(request):
        path = Path(f"/etc/systemd/system/{unit}.d")
        attach.control_directory(path)
        fields = attach.unit_state(unit)
        require(state.matches(r"0|[1-9][0-9]*", fields["MainPID"]), "reference-unit")
        fields["MainPID"] = int(fields["MainPID"])
        fields["directory_membership"] = sorted(child.name for child in path.iterdir())
        units[unit] = fields
    result = {"files": files, "units": units}
    _validate_reference(request, result, phase)
    require(reference_files(request) == files, "reference-changed")
    return result


def retained_facts(policy, guard):
    ownership = guard.collect_ownership(policy)
    result = {**guard._collect_retained(policy), "ownership": ownership}
    guard.validate(policy, result, policy["vmid"])
    return result


def owner_seal(policy, guard):
    return guard.ownership_files(policy)


def validate_running_guest(request, profile, guest):
    observe.validate_guest(request["policy"], guest)
    require(
        guest["status"] == "running"
        and state.canonical(guest["config"]) == state.canonical(profile["config"]),
        "guest-config",
    )


def stable_guest(guest):
    result = copy.deepcopy(guest)
    result["runtime"].pop("uptime")
    return result


def seal_database(path, checksum, expected):
    for suffix in ("-wal", "-shm", "-journal"):
        require(not os.path.lexists(str(path) + suffix), "database-sidecar")
    raw, info = observe.read_regular(path, 16777216)
    metadata = {
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "inode": info.st_ino,
        "bytes": info.st_size,
        "regular": True,
        "sqlite_header": raw[:16] == b"SQLite format 3\0",
    }
    require(
        state.sha256(raw) == checksum
        and state.canonical(metadata) == state.canonical(expected),
        "database-changed",
    )
    for suffix in ("-wal", "-shm", "-journal"):
        require(not os.path.lexists(str(path) + suffix), "database-sidecar")


def collect(request, image_profile, *, phase="os_quiesced"):
    """Collect an OS-running, application-quiesced frame without lifecycle writes."""
    require(phase == "os_quiesced", "phase-unsupported")
    request, profile = copy.deepcopy(request), copy.deepcopy(image_profile)
    _, _, binding = load_profile(request, profile)
    host = observe.host_facts(request)
    guard = observe.load_guard(request["reference_guard"])
    observe.validate_request(request, guard)
    policy = request["policy"]
    with pair_lock.locked_pair(policy["datasets"]), ExitStack() as leased:
        for vmid in sorted((policy["vmid"], policy["retired_guest"]["vmid"])):
            leased.enter_context(config_lock.read_guest(vmid))
        validate_running_guest(request, profile, observe.guest_facts(policy))
        config = Path(policy["datasets"]["config"]["mountpoint"]) / "application.json"
        uid, gid = (
            policy["mapping"]["offset"] + policy["mapping"][name]
            for name in ("uid", "gid")
        )
        with observe.locked_config(config, uid, gid) as raw:
            result = _collect_leased(request, profile, guard, binding, host, raw)
    return result


def _collect_leased(request, profile, guard, binding, host, raw):
    """Inspect under the caller's pair EX, both native SH and application EX.

    Only admitted internal lifecycle controllers call this worker. It never
    acquires or releases these leases. The public collector owns its own scopes.
    """
    policy = request["policy"]
    require(
        type(raw) is bytes
        and state.sha256(raw) == policy["application"]["config_sha256"],
        "configuration-changed",
    )
    _, image, expected_binding = load_profile(request, profile)
    require(binding == expected_binding, "binding-changed")
    guest = observe.guest_facts(policy)
    validate_running_guest(request, profile, guest)
    kernel_before = kernel.collect(binding)
    reference_before = reference_facts(request)
    binds_before = collect_bindings(binding, kernel_before, policy["datasets"])
    image_before = guest_image(request, profile)
    validate_image(profile, image, image_before, kernel_before)
    retained = retained_facts(policy, guard)
    database = Path(policy["datasets"]["data"]["mountpoint"]) / "ledger.sqlite3"
    application = {
        "instance_id": policy["application"]["instance_id"],
        "config_sha256": policy["application"]["config_sha256"],
        "mapping": dict(policy["mapping"]),
        **observe.read_database(database, policy["application"]["instance_id"]),
    }
    retained_after = retained_facts(policy, guard)
    reference_after = reference_facts(request)
    guest_after = observe.guest_facts(policy)
    validate_running_guest(request, profile, guest_after)
    host_after = observe.host_facts(request)
    require(
        observe.read_database(database, application["instance_id"])
        == {
            key: application[key]
            for key in ("database_sha256", "records_sha256", "record_count")
        },
        "database-changed",
    )
    image_after = guest_image(request, profile)
    binds_after = collect_bindings(binding, kernel_before, policy["datasets"])
    kernel_after = kernel.collect(binding)
    require(
        host_after == host
        and stable_guest(guest_after) == stable_guest(guest)
        and guest_after["runtime"]["uptime"] >= guest["runtime"]["uptime"],
        "host-or-guest-changed",
    )
    require(
        retained_after == retained
        and reference_after == reference_before
        and binds_after == binds_before
        and kernel_after == kernel_before
        and image_after == image_before,
        "runtime-changed",
    )
    seal_database(
        database,
        application["database_sha256"],
        retained_after["application"]["database"],
    )
    observe.load_guard(request["reference_guard"])
    require(
        owner_seal(policy, guard) == guard.ownership_seal(retained_after["ownership"])
        and reference_files(request) == reference_after["files"],
        "control-files-changed",
    )
    init = kernel_after["init"]
    require(
        kernel.reader.memory.init_state(init["pid"])
        == (init["pstart"], init["pid_namespace_inode"]),
        "init-changed",
    )
    result = {
        "schema_version": 1,
        "phase": "os_quiesced",
        "source": copy.deepcopy(request["source"]),
        "host": host_after,
        "guest": guest_after,
        "kernel": kernel_after,
        "retained": retained_after,
        "bindings": binds_after,
        "image": image_after,
        "reference": reference_after,
        "application": application,
        "os_runtime_verified": True,
        "application_quiesced": True,
        **FLAGS,
    }
    validate(request, profile, "os_quiesced", result)
    return result


def selected_mounts(raw, datasets):
    require(type(raw) is str and 0 < len(raw.encode()) <= 1048576, "mount-table")
    rows = raw.splitlines()
    require(0 < len(rows) <= 4096, "mount-table")
    selected = {}
    identifiers = set()
    for row in rows:
        fields = row.split()
        require(len(fields) >= 10 and fields.count("-") == 1, "mount-table")
        separator = fields.index("-")
        require(separator >= 6 and len(fields) == separator + 4, "mount-table")
        require(fields[0].isdigit() and fields[1].isdigit(), "mount-table")
        identifier = int(fields[0])
        require(0 < identifier < 2**64 and identifier not in identifiers, "mount-table")
        identifiers.add(identifier)
        roles = [role for role, target in GUEST_BINDS.items() if fields[4] == target]
        if not roles:
            continue
        role = roles[0]
        device = fields[2].split(":")
        require(
            len(device) == 2 and all(part.isdigit() for part in device), "mount-device"
        )
        options = fields[5].split(",")
        super_options = fields[separator + 3].split(",")
        require(
            role not in selected
            and fields[3] == "/"
            and fields[separator + 1] == "zfs"
            and fields[separator + 2] == datasets[role]["name"]
            and "rw" in options
            and "ro" not in options
            and "rw" in super_options
            and "ro" not in super_options,
            "guest-mount",
        )
        selected[role] = {
            "id": identifier,
            "device": [int(part) for part in device],
            "root": fields[3],
            "target": fields[4],
            "source": fields[separator + 2],
            "filesystem": fields[separator + 1],
            "options": sorted(options),
            "super_options": sorted(super_options),
        }
    require(set(selected) == set(GUEST_BINDS), "guest-mount-missing")
    return selected


def directory_identity(info):
    require(stat.S_ISDIR(info.st_mode), "bind-not-directory")
    return {"device": info.st_dev, "inode": info.st_ino}


def collect_bindings(binding, evidence, datasets):
    """Bind the guest's open directory FDs to actual retained host directories."""
    kernel.validate(binding, evidence)
    state.keys(datasets, GUEST_BINDS)
    init = evidence["init"]
    identity = (init["pstart"], init["pid_namespace_inode"])
    require(kernel.reader.memory.init_state(init["pid"]) == identity, "init-changed")
    process = PROC_ROOT / str(init["pid"])
    table = selected_mounts(
        kernel.reader.memory.read_text(process / "mountinfo"), datasets
    )
    result = {}
    bound = {}
    try:
        with ExitStack() as opened:
            root = os.open(
                process / "root", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            )
            opened.callback(os.close, root)
            require(
                os.fstat(root).st_dev == os.makedev(*evidence["rootfs"]["device"]),
                "root-device-changed",
            )
            for role, target in GUEST_BINDS.items():
                host = Path(datasets[role]["mountpoint"])
                require(
                    host.is_absolute() and host.resolve(strict=True) == host,
                    "host-bind-path",
                )
                before = directory_identity(host.lstat())
                current = root
                for part in target.lstrip("/").split("/"):
                    current = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=current,
                    )
                    opened.callback(os.close, current)
                guest = directory_identity(os.fstat(current))
                require(
                    guest == before == directory_identity(host.lstat())
                    and table[role]["device"]
                    == [os.major(guest["device"]), os.minor(guest["device"])],
                    "guest-bind-backing",
                )
                result[role] = {"host": before, "guest": guest, "mount": table[role]}
                bound[role] = (current, host, before)
            require(
                selected_mounts(
                    kernel.reader.memory.read_text(process / "mountinfo"), datasets
                )
                == table,
                "bind-state-changed",
            )
            for descriptor, host, before in bound.values():
                require(
                    directory_identity(os.fstat(descriptor))
                    == before
                    == directory_identity(host.lstat()),
                    "bind-state-changed",
                )
            require(
                os.fstat(root).st_dev == os.makedev(*evidence["rootfs"]["device"]),
                "root-device-changed",
            )
            require(
                kernel.reader.memory.init_state(init["pid"]) == identity, "init-changed"
            )
    except OSError:
        raise state.PersistenceError(
            "persistence-retained-runtime-bind-unavailable"
        ) from None
    return result
