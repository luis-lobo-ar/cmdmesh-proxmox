"""Canonical fixed read-only node/LXC collector; standalone standard library."""

import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import subprocess
import sys
import time

MAX_BYTES = 2 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 10
SUPPORTED_VERSIONS = {("9.2.21", "6.1.14")}
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class RemoteObservationError(Exception):
    def __init__(self, code="remote-memory-evidence-unavailable"):
        self.code = code
        super().__init__(code)


def finite_float(value):
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError()
    return parsed


def load_json(raw):
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError()
            result[key] = value
        return result

    try:
        if len(raw) > MAX_BYTES:
            raise ValueError()
        return json.loads(
            raw,
            object_pairs_hook=unique,
            parse_float=finite_float,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (ValueError, UnicodeError, RecursionError):
        raise RemoteObservationError("remote-memory-json-invalid") from None


def read_text(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise RemoteObservationError("remote-memory-read-unqualified")
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise RemoteObservationError("remote-memory-read-limit")
    return data.decode("utf-8")


def drain(stream, result):
    for _ in range(256):
        try:
            data = os.read(stream.fileno(), 8192)
        except BlockingIOError:
            return
        if not data:
            return
        result.extend(data)
        if len(result) > MAX_BYTES:
            raise RemoteObservationError("remote-memory-output-limit")


def command(argv):
    # The timeout supervisor also bounds a command if this remote Python process
    # loses its SSH connection. It is part of this Linux/coreutils profile.
    args = [
        "/usr/bin/timeout",
        "--signal=KILL",
        str(COMMAND_TIMEOUT_SECONDS) + "s",
        *argv,
    ]
    process = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    result = bytearray()
    started = time.monotonic()
    try:
        os.set_blocking(process.stdout.fileno(), False)
        while True:
            drain(process.stdout, result)
            status = process.poll()
            if status is not None:
                drain(process.stdout, result)
                if status < 0 or status in (
                    124,
                    128 + signal.SIGKILL,
                    128 + signal.SIGTERM,
                ):
                    raise RemoteObservationError("remote-memory-command-interrupted")
                if status != 0:
                    raise RemoteObservationError("remote-memory-command-failed")
                return result.decode("utf-8")
            if time.monotonic() - started > COMMAND_TIMEOUT_SECONDS + 1:
                raise RemoteObservationError("remote-memory-command-deadline")
            time.sleep(0.01)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()


def certificate_digest(path):
    text = read_text(path)
    matches = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S
    )
    if len(matches) != 1 or text.replace(matches[0], "").strip():
        raise RemoteObservationError("remote-memory-certificate-unqualified")
    try:
        der = ssl.PEM_cert_to_DER_cert(matches[0])
    except ValueError:
        raise RemoteObservationError("remote-memory-certificate-unqualified") from None
    return hashlib.sha256(der).hexdigest()


def custom_certificate_exists():
    return os.path.lexists("/etc/pve/local/pveproxy-ssl.pem")


def local_node_path():
    return Path("/etc/pve/local").resolve(strict=True)


def namespace_inode(pid):
    return os.stat(f"/proc/{pid}/ns/pid").st_ino


def host_identity(expected_node):
    if os.geteuid() != 0:
        raise RemoteObservationError("remote-memory-root-required")
    actual_node = read_text("/proc/sys/kernel/hostname").strip().split(".")[0]
    if not NAME.fullmatch(actual_node) or actual_node != expected_node:
        raise RemoteObservationError("remote-memory-host-mismatch")
    if (
        local_node_path() != Path("/etc/pve/nodes") / actual_node
        or custom_certificate_exists()
    ):
        raise RemoteObservationError("remote-memory-certificate-profile-unsupported")
    machine = read_text("/etc/machine-id").strip()
    if not re.fullmatch(r"[a-f0-9]{32}", machine) or machine == "0" * 32:
        raise RemoteObservationError("remote-memory-machine-id-unqualified")
    return {
        "machine_id_sha256": hashlib.sha256(machine.encode()).hexdigest(),
        "ca_certificate_sha256": certificate_digest("/etc/pve/pve-root-ca.pem"),
        "leaf_certificate_sha256": certificate_digest("/etc/pve/local/pve-ssl.pem"),
    }


def validate_request(request):
    required = {"request_id", "selector", "host_profile", "owner_tag", "generation_tag"}
    if not isinstance(request, dict) or request.keys() != required:
        raise RemoteObservationError("remote-memory-request-invalid")
    selected = request["selector"]
    if not isinstance(selected, dict) or selected.keys() != {
        "origin",
        "node",
        "kind",
        "vmid",
    }:
        raise RemoteObservationError("remote-memory-request-invalid")
    if (
        selected["kind"] != "proxmox.lxc"
        or type(selected["vmid"]) is not int
        or not 100 <= selected["vmid"] <= 999999999
        or not all(
            isinstance(selected[key], str) and NAME.fullmatch(selected[key])
            for key in ("origin", "node")
        )
    ):
        raise RemoteObservationError("remote-memory-request-invalid")
    profile = request["host_profile"]
    if not isinstance(profile, dict) or profile.keys() != {
        "machine_id_sha256",
        "ca_certificate_sha256",
        "leaf_certificate_sha256",
    }:
        raise RemoteObservationError("remote-memory-request-invalid")
    for value in profile.values():
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
            raise RemoteObservationError("remote-memory-request-invalid")
    for field, pattern in (
        ("request_id", r"[a-f0-9]{32}"),
        ("owner_tag", r"cmdmesh-own-[a-f0-9]{32}"),
        ("generation_tag", r"cmdmesh-gen-[a-f0-9]{32}"),
    ):
        if not isinstance(request[field], str) or not re.fullmatch(
            pattern, request[field]
        ):
            raise RemoteObservationError("remote-memory-request-invalid")


def native_versions():
    raw = command(
        [
            "/usr/bin/dpkg-query",
            "-W",
            "-f=${binary:Package}\t${Version}\n",
            "pve-manager",
            "pve-container",
        ]
    )
    rows = [line.split("\t") for line in raw.splitlines()]
    if (
        len(rows) != 2
        or any(len(row) != 2 for row in rows)
        or {row[0] for row in rows} != {"pve-manager", "pve-container"}
    ):
        raise RemoteObservationError("remote-memory-version-unavailable")
    return dict(rows)


def api(node, suffix, extra=()):
    return load_json(
        command(
            [
                "/usr/bin/pvesh",
                "get",
                f"/nodes/{node}/{suffix}",
                *extra,
                "--output-format",
                "json",
            ]
        )
    )


def guest_identity(node, vmid):
    selected = []
    for kind in ("lxc", "qemu"):
        rows = api(node, kind)
        if not isinstance(rows, list) or len(rows) > 20000:
            raise RemoteObservationError("remote-memory-target-evidence-invalid")
        seen = set()
        for row in rows:
            if (
                not isinstance(row, dict)
                or type(row.get("vmid")) is not int
                or not 100 <= row["vmid"] <= 999999999
                or row["vmid"] in seen
            ):
                raise RemoteObservationError("remote-memory-target-evidence-invalid")
            seen.add(row["vmid"])
            if row["vmid"] == vmid:
                selected.append((kind, row))
    if (
        len(selected) != 1
        or selected[0][0] != "lxc"
        or selected[0][1].get("status") != "running"
    ):
        raise RemoteObservationError("remote-memory-target-unqualified")


def configuration(node, vmid):
    config = api(node, f"lxc/{vmid}/config", ("--current", "1"))
    pending = api(node, f"lxc/{vmid}/pending")
    if (
        not isinstance(config, dict)
        or not {"memory", "swap", "digest", "tags"} <= config.keys()
    ):
        raise RemoteObservationError("remote-memory-config-incomplete")
    if not isinstance(pending, list) or len(pending) > 10000:
        raise RemoteObservationError("remote-memory-pending-unqualified")
    seen = set()
    for row in pending:
        if (
            not isinstance(row, dict)
            or "key" not in row
            or not isinstance(row["key"], str)
            or row.keys() - {"key", "value", "pending", "delete"}
            or row["key"] in seen
        ):
            raise RemoteObservationError("remote-memory-pending-unqualified")
        seen.add(row["key"])
        if "pending" in row or "delete" in row:
            raise RemoteObservationError("remote-memory-pending-unqualified")
    if "lock" in config:
        raise RemoteObservationError("remote-memory-config-locked")
    return config


def lxc_pid(vmid):
    raw = command(["/usr/bin/lxc-info", "-n", str(vmid), "-pH"]).strip()
    if not re.fullmatch(r"[1-9][0-9]{0,9}", raw) or int(raw) <= 1:
        raise RemoteObservationError("remote-memory-init-unavailable")
    return int(raw)


def init_state(pid):
    stat = read_text(f"/proc/{pid}/stat")
    parts = stat.rsplit(") ", 1)
    if len(parts) != 2 or not parts[0].startswith(str(pid) + " ("):
        raise RemoteObservationError("remote-memory-init-unavailable")
    fields = parts[1].split()
    if len(fields) < 20 or fields[0] in ("Z", "X") or not fields[19].isdigit():
        raise RemoteObservationError("remote-memory-init-unavailable")
    return int(fields[19]), namespace_inode(pid)


def memory_limit(pid):
    lines = read_text(f"/proc/{pid}/cgroup").splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        raise RemoteObservationError("remote-memory-cgroup-unsupported")
    path = lines[0][3:]
    components = path.split("/")[1:]
    if any(
        part in (".", "..") or "\0" in part or " (deleted)" in part
        for part in components
    ):
        raise RemoteObservationError("remote-memory-cgroup-unqualified")
    root = Path("/sys/fs/cgroup")
    current = root.joinpath(*components)
    limits = []
    while True:
        try:
            raw = read_text(current / "memory.max").strip()
        except FileNotFoundError:
            if (
                current != root
                and "memory" in read_text(current / "cgroup.controllers").split()
            ):
                raise RemoteObservationError(
                    "remote-memory-cgroup-unqualified"
                ) from None
        else:
            if raw != "max":
                if not raw.isdigit():
                    raise RemoteObservationError("remote-memory-cgroup-unqualified")
                limits.append(int(raw))
        if current == root:
            break
        current = current.parent
    if not limits:
        raise RemoteObservationError("remote-memory-limit-unavailable")
    return min(limits), lines[0]


def host_capacity():
    raw = read_text("/proc/meminfo")
    result = {}
    for source, target in (
        ("MemTotal", "total_bytes"),
        ("MemAvailable", "available_bytes"),
    ):
        values = re.findall(r"(?m)^" + source + r":\s+([0-9]+) kB$", raw)
        if len(values) != 1:
            raise RemoteObservationError("remote-memory-capacity-unavailable")
        result[target] = int(values[0]) * 1024
    return result


def collect(request, *, observed_at_unix_ms):
    validate_request(request)
    if (
        type(observed_at_unix_ms) is not int
        or not 0 <= observed_at_unix_ms <= 2**63 - 1
    ):
        raise RemoteObservationError("remote-memory-request-invalid")
    selected = request["selector"]
    node, vmid = selected["node"], selected["vmid"]
    profile = host_identity(node)
    if profile != request["host_profile"]:
        raise RemoteObservationError("remote-memory-host-mismatch")
    boot = host_boot_identity()
    versions = native_versions()
    if (versions["pve-manager"], versions["pve-container"]) not in SUPPORTED_VERSIONS:
        raise RemoteObservationError("remote-memory-version-unsupported")
    if "--digest" not in command(["/usr/sbin/pct", "help", "set"]):
        raise RemoteObservationError("remote-memory-digest-unsupported")
    guest_identity(node, vmid)
    config = configuration(node, vmid)
    pid = lxc_pid(vmid)
    init = init_state(pid)
    limit, cgroup = memory_limit(pid)
    capacity = host_capacity()
    if (
        lxc_pid(vmid) != pid
        or init_state(pid) != init
        or read_text(f"/proc/{pid}/cgroup").strip() != cgroup
    ):
        raise RemoteObservationError("remote-memory-init-changed")
    if host_boot_identity() != boot:
        raise RemoteObservationError("remote-memory-host-boot-changed")
    if not isinstance(config["tags"], str):
        raise RemoteObservationError("remote-memory-config-incomplete")
    other = {
        key: value for key, value in config.items() if key not in ("memory", "digest")
    }
    return {
        "document_type": "cmdmesh.proxmox.lxc-memory.observation",
        "schema_version": 1,
        "request_id": request["request_id"],
        "origin": selected["origin"],
        "node": node,
        "host_profile": profile,
        "host_boot_id_sha256": boot,
        "kind": "proxmox.lxc",
        "vmid": vmid,
        "tags": config["tags"].split(";"),
        "configuration": {
            "digest": config["digest"],
            "memory_mb": config["memory"],
            "swap_mb": config["swap"],
            "other_sha256": hashlib.sha256(
                json.dumps(
                    other, sort_keys=True, separators=(",", ":"), allow_nan=False
                ).encode()
            ).hexdigest(),
            "locked": False,
            "pending": False,
        },
        "runtime": {
            "status": "running",
            "memory_limit_bytes": limit,
            "init_start_ticks": init[0],
            "pid_namespace_inode": init[1],
        },
        "host_capacity": capacity,
        "versions": versions,
        "observed_at_unix_ms": observed_at_unix_ms,
        "complete": True,
        "warnings": [],
    }


def host_boot_identity():
    value = read_text("/proc/sys/kernel/random/boot_id").strip()
    if (
        not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value)
        or value == "00000000-0000-0000-0000-000000000000"
    ):
        raise RemoteObservationError("remote-memory-host-boot-unqualified")
    return hashlib.sha256(value.encode()).hexdigest()


def deadline(_signal, _frame):
    raise RemoteObservationError("remote-memory-deadline")


def main():
    try:
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(45)
        if len(sys.argv) != 2:
            raise RemoteObservationError("remote-memory-request-invalid")
        envelope = load_json(sys.argv[1])
        if not isinstance(envelope, dict) or envelope.keys() != {
            "request",
            "observed_at_unix_ms",
        }:
            raise RemoteObservationError("remote-memory-request-invalid")
        result = collect(
            envelope["request"], observed_at_unix_ms=envelope["observed_at_unix_ms"]
        )
        print(json.dumps(result, separators=(",", ":"), allow_nan=False))
        return 0
    except RemoteObservationError as error:
        code = error.code
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        code = "remote-memory-evidence-unavailable"
    finally:
        signal.alarm(0)
    print(json.dumps({"schema_version": 1, "error": code}))
    return 1


if __name__ == "__main__":
    sys.exit(main())
