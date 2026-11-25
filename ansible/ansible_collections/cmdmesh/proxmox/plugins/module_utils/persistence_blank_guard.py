"""Standalone read-only guard for a NIC-free, bind-free reference OS boot.

Install the same fixed invocation in normal and debug instance units. This does
not constrain an administrator deliberately bypassing systemd with lxc-start.
It never initializes data, changes configuration or authorizes an application.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess


class Refused(ValueError):
    """The exact blank guest was not established."""


def require(value):
    if not value:
        raise Refused("blank-reference-boot-refused")


def matches(pattern, value):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value)
            value[key] = item
        return value

    def invalid(unused):
        raise Refused("non-finite-input")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def identity(info):
    return [
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
    ]


def cpu_list(raw, *, allow_empty=False):
    require(type(raw) is str and len(raw) <= 32768)
    if not raw:
        require(allow_empty)
        return []
    require(matches(r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*", raw))
    result = []
    for part in raw.split(","):
        bounds = [int(item) for item in part.split("-")]
        low, high = bounds[0], bounds[-1]
        require(
            0 <= low <= high <= 65535
            and high - low < 4096
            and len(result) + high - low + 1 <= 4096
        )
        result.extend(range(low, high + 1))
    require(result == sorted(set(result)))
    return result


def generated_fingerprint(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 65536)
    lines = raw.splitlines(keepends=True)
    quotas = [line for line in lines if line.strip().startswith(b"lxc.cgroup2.cpu.max")]
    require(quotas == [b"lxc.cgroup2.cpu.max = 100000 100000\n"])
    indexes = [
        index
        for index, line in enumerate(lines)
        if line.strip().startswith(b"lxc.cgroup2.cpuset.cpus")
    ]
    require(len(indexes) == 1)
    index = indexes[0]
    match = re.fullmatch(
        rb"(lxc\.cgroup2\.cpuset\.cpus = )([^\r\n]*)(\n)", lines[index]
    )
    require(match is not None)
    selection = cpu_list(match[2].decode("ascii"), allow_empty=True)
    lines[index] = match[1] + match[3]
    return hashlib.sha256(b"".join(lines)).hexdigest(), selection


def validate_root(value, vmid, *, observed=False):
    keys = {"path", "identity", "uuid"} | ({"resolved_path"} if observed else set())
    require(type(value) is dict and set(value) == keys)
    if observed:
        require(value["resolved_path"] == value["path"])
    require(
        value["path"] == f"/var/lib/vz/images/{vmid}/vm-{vmid}-disk-0.raw"
        and matches(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value["uuid"])
    )
    parts = value["identity"]
    require(
        type(parts) is list
        and len(parts) == 7
        and all(type(part) is int and part >= 0 for part in parts)
        and parts[1] > 0
        and stat.S_ISREG(parts[2])
        and not parts[2] & 0o022
        and parts[3:6] == [0, 0, 1]
        and parts[6] == 2 * 1024**3
    )


def validate_policy(policy):
    require(
        type(policy) is dict
        and set(policy)
        == {
            "schema_version",
            "machine_id_sha256",
            "node",
            "vmid",
            "source_vmid",
            "config",
            "rootfs",
            "generated_config_stable_sha256",
            "cpu_policy",
        }
        and type(policy["schema_version"]) is int
        and policy["schema_version"] == 1
        and matches(r"[a-f0-9]{64}", policy["machine_id_sha256"])
        and matches(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", policy["node"])
        and all(
            type(policy[key]) is int and 100 <= policy[key] <= 999999
            for key in ("vmid", "source_vmid")
        )
        and policy["vmid"] != policy["source_vmid"]
    )
    config = policy["config"]
    require(
        type(config) is dict
        and set(config)
        == {
            "arch",
            "ostype",
            "digest",
            "hostname",
            "description",
            "tags",
            "rootfs",
            "cores",
            "cpulimit",
            "memory",
            "swap",
            "unprivileged",
            "onboot",
            "protection",
        }
        and config["arch"] == "amd64"
        and config["ostype"] == "ubuntu"
        and matches(r"[a-f0-9]{40}", config["digest"])
        and matches(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", config["hostname"])
        and type(config["description"]) is str
        and len(config["description"]) <= 1024
        and config["rootfs"]
        == f"local:{policy['vmid']}/vm-{policy['vmid']}-disk-0.raw,size=2G"
    )
    for key, value in (
        ("cores", 1),
        ("memory", 512),
        ("swap", 0),
        ("unprivileged", 1),
        ("onboot", 0),
        ("protection", 1),
    ):
        require(type(config[key]) is int and config[key] == value)
    limit = config["cpulimit"]
    require(
        (type(limit) in {int, float} and limit == 1)
        or type(limit) is str
        and limit == "1"
    )
    require(type(config["tags"]) is str)
    tags = config["tags"].split(";")
    require(
        len(tags) == len(set(tags)) == 3
        and "cmdmesh-ansible" in tags
        and sum(matches(r"cmdmesh-own-[a-f0-9]{32}", tag) for tag in tags) == 1
        and sum(matches(r"cmdmesh-gen-[a-f0-9]{32}", tag) for tag in tags) == 1
    )
    validate_root(policy["rootfs"], policy["vmid"])
    require(matches(r"[a-f0-9]{64}", policy["generated_config_stable_sha256"]))
    cpu = policy["cpu_policy"]
    require(
        type(cpu) is dict
        and set(cpu) == {"allowed", "count"}
        and type(cpu["count"]) is int
        and cpu["count"] == 1
    )
    allowed = cpu["allowed"]
    require(
        type(allowed) is list
        and 1 <= len(allowed) <= 4096
        and all(type(item) is int and 0 <= item <= 65535 for item in allowed)
        and allowed == sorted(set(allowed))
    )


def validate(policy, facts, vmid):
    validate_policy(policy)
    require(type(vmid) is int and vmid == policy["vmid"])
    require(
        type(facts) is dict
        and set(facts)
        == {
            "machine_id_sha256",
            "node",
            "config",
            "rootfs",
            "source_status",
            "pending",
            "ha",
            "generated_config",
            "cpu_available",
            "target_status",
        }
        and facts["machine_id_sha256"] == policy["machine_id_sha256"]
        and facts["node"] == policy["node"]
        and canonical(facts["config"]) == canonical(policy["config"])
    )
    for source in (facts["source_status"], facts["target_status"]):
        require(
            type(source) is dict
            and source.get("status") == "stopped"
            and type(source.get("uptime")) is int
            and source["uptime"] == 0
            and type(source.get("pid", 0)) is int
            and source.get("pid", 0) == 0
        )
    require(type(facts["generated_config"]) is str)
    fingerprint, selection = generated_fingerprint(facts["generated_config"].encode())
    available = facts["cpu_available"]
    require(
        type(available) is list
        and 1 <= len(available) <= 4096
        and all(type(item) is int and 0 <= item <= 65535 for item in available)
        and available == sorted(set(available))
        and set(available) <= set(policy["cpu_policy"]["allowed"])
        and len(selection) in {0, 1}
        and set(selection) <= set(available)
        and fingerprint == policy["generated_config_stable_sha256"]
    )
    rows = facts["pending"]
    require(type(rows) is list and len(rows) <= 128)
    keys = []
    for row in rows:
        require(
            type(row) is dict
            and matches(r"[A-Za-z0-9_.-]{1,128}", row.get("key"))
            and "pending" not in row
            and not row.get("delete")
        )
        keys.append(row["key"])
    require(len(keys) == len(set(keys)))
    ha = facts["ha"]
    require(type(ha) is list and len(ha) <= 128)
    for row in ha:
        require(
            type(row) is dict
            and matches(r"(?:ct|vm):[1-9][0-9]*", row.get("sid"))
            and row["sid"]
            not in {
                f"ct:{vmid}",
                f"vm:{vmid}",
                f"ct:{policy['source_vmid']}",
                f"vm:{policy['source_vmid']}",
            }
        )
    validate_root(facts["rootfs"], vmid, observed=True)
    require(
        canonical({key: facts["rootfs"][key] for key in policy["rootfs"]})
        == canonical(policy["rootfs"])
    )


def read_file(path, limit):
    path = Path(path)
    require(path.resolve(strict=True) == path)
    with open(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb", closefd=True) as stream:
        before = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == 0
            and before.st_nlink == 1
            and not before.st_mode & 0o022
            and 0 < before.st_size <= limit
        )
        raw = stream.read(limit + 1)
        require(
            len(raw) == before.st_size
            and identity(before)
            == identity(os.fstat(stream.fileno()))
            == identity(path.lstat())
            and before.st_mtime_ns == path.lstat().st_mtime_ns
        )
    return raw


def native(argv):
    result = subprocess.run(
        argv,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=20,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    require(
        result.returncode == 0
        and not result.stderr
        and 0 < len(result.stdout) <= 1048576
    )
    return result.stdout


def collect(policy):
    validate_policy(policy)
    require(os.geteuid() == 0)
    base = f"/nodes/{policy['node']}/lxc/"
    get = lambda path: decode(
        native(["/usr/bin/pvesh", "get", path, "--output-format", "json"])
    )
    image = Path(policy["rootfs"]["path"])
    volume = policy["config"]["rootfs"].split(",", 1)[0]
    resolved = native(["/usr/sbin/pvesm", "path", volume]).decode().strip()
    require(resolved == str(image))
    require(image.resolve(strict=True) == image)
    before = image.lstat()
    raw = native(["/usr/sbin/blkid", "-p", "-o", "export", str(image)]).decode()
    fs = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        require(separator == "=" and key not in fs)
        fs[key] = value
    require(fs.get("TYPE") == "ext4" and identity(before) == identity(image.lstat()))
    machine = read_file("/etc/machine-id", 64)
    require(re.fullmatch(rb"[a-f0-9]{32}\n?", machine) is not None)
    generated = read_file(f"/var/lib/lxc/{policy['vmid']}/config", 65536)
    parent = Path("/sys/fs/cgroup/lxc/cpuset.cpus.effective")
    if not parent.exists():
        parent = Path("/sys/fs/cgroup/cpuset.cpus.effective")
    require(parent.resolve(strict=True) == parent)
    available = cpu_list(parent.read_text().strip())
    facts = {
        "machine_id_sha256": hashlib.sha256(machine.strip()).hexdigest(),
        "node": socket.gethostname(),
        "config": get(base + str(policy["vmid"]) + "/config"),
        "pending": get(base + str(policy["vmid"]) + "/pending"),
        "source_status": get(base + str(policy["source_vmid"]) + "/status/current"),
        "target_status": get(base + str(policy["vmid"]) + "/status/current"),
        "generated_config": generated.decode(),
        "cpu_available": available,
        "ha": get("/cluster/ha/resources"),
        "rootfs": {
            "path": str(image),
            "resolved_path": resolved,
            "identity": identity(before),
            "uuid": fs.get("UUID"),
        },
    }
    # Managed native starts hold PVE's config lock. Close named-file and storage
    # observations after slow API reads rather than authorizing stale facts.
    require(
        resolved == native(["/usr/sbin/pvesm", "path", volume]).decode().strip()
        and image.resolve(strict=True) == image
        and raw
        == native(["/usr/sbin/blkid", "-p", "-o", "export", str(image)]).decode()
        and generated == read_file(f"/var/lib/lxc/{policy['vmid']}/config", 65536)
        and available == cpu_list(parent.read_text().strip())
        and machine == read_file("/etc/machine-id", 64)
        and identity(before) == identity(image.lstat())
        and before.st_mtime_ns == image.lstat().st_mtime_ns
        and before.st_ctime_ns == image.lstat().st_ctime_ns
    )
    return facts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--vmid", type=int, required=True)
    args = parser.parse_args()
    try:
        policy = decode(read_file(args.manifest, 65536))
        validate(policy, collect(policy), args.vmid)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('{"outcome":"refused"}')
        return 1
    print('{"outcome":"blank-os-only"}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
