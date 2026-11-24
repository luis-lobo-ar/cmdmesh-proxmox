"""Provision one stopped reference rebuild recipient; never initializes or starts.

The old stopped source stays locked and is independently checked before/after.
A permanent target claim precedes the only create POST. Status reads the same
native task and never posts again. This is not application rebuild acceptance.
"""

import hashlib
import http.client
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import time
from urllib.parse import quote, urlencode

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_backup as backup,
    persistence_observe as observe,
    persistence_state as state,
)

RUNTIME_ROOT = Path("/var/lib/cmdmesh/reference-recipients")
PREPARED = "cmdmesh.proxmox.persistence.prepared-recipient"
COMPLETE = "cmdmesh.proxmox.persistence.completed-recipient"
PROFILE = {
    "document_type": "cmdmesh.proxmox.persistence.recipient-runtime",
    "schema_version": 1,
}
WARNING = "WARN: Systemd 255 detected. You may need to enable nesting."
TICKET_PROGRAM = "PVE::Cluster::cfs_update(); die 'auth key not current' unless PVE::AccessControl::check_authkey(1); print JSON::PP::encode_json({ticket=>PVE::AccessControl::assemble_ticket('root@pam'),csrf=>PVE::AccessControl::assemble_csrf_prevention_token('root@pam')});"


def require(value, code):
    state.require(value, "persistence-recipient-" + code)


def validate_request(request):
    state.keys(
        request,
        {
            "schema_version",
            "operation_id",
            "source_request",
            "target",
            "template",
            "storage_id",
        },
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
    target = request["target"]
    state.keys(target, {"vmid", "hostname", "generation_tag"})
    state.integer(target["vmid"], 100, 999999)
    require(
        target["vmid"] != source["source"]["selector"]["vmid"], "source-target-alias"
    )
    require(
        state.matches(r"[a-zA-Z0-9][a-zA-Z0-9-]{0,62}", target["hostname"]), "hostname"
    )
    require(
        state.matches(r"cmdmesh-gen-[a-f0-9]{32}", target["generation_tag"])
        and target["generation_tag"] != source["source"]["generation_tag"],
        "generation",
    )
    require(
        state.matches(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", request["storage_id"]),
        "storage-id",
    )
    template = request["template"]
    state.keys(template, {"volume", "bytes", "sha256"})
    require(
        state.matches(
            re.escape(request["storage_id"])
            + r":vztmpl/ubuntu-24\.04-standard_[a-zA-Z0-9_.-]+_amd64\.tar\.zst",
            template["volume"],
        ),
        "template-volume",
    )
    state.integer(template["bytes"], 1, 268435456)
    state.digest(template["sha256"])


def create_request(request):
    validate_request(request)
    source, target = request["source_request"], request["target"]
    parameters = {
        "vmid": str(target["vmid"]),
        "hostname": target["hostname"],
        "ostemplate": request["template"]["volume"],
        "rootfs": request["storage_id"] + ":2",
        "cores": "1",
        "cpulimit": "1",
        "memory": "512",
        "swap": "0",
        "unprivileged": "1",
        "onboot": "0",
        "start": "0",
        "protection": "1",
        "tags": ";".join(
            ("cmdmesh-ansible", source["source"]["owner_tag"], target["generation_tag"])
        ),
        "description": "Owned CmdMesh reference rebuild recipient; stopped and isolated",
    }
    return parameters


def get(path, *arguments):
    return observe.decode(
        observe.native(
            ["/usr/bin/pvesh", "get", path, *arguments, "--output-format", "json"]
        )
    )


def inventory(request, *, exclude_target=False):
    source, target = request["source_request"]["source"], request["target"]
    rows = get("/cluster/resources", "--type", "vm")
    require(type(rows) is list and len(rows) <= 128, "inventory-limit")
    result, ids = [], set()
    for row in rows:
        require(
            type(row) is dict
            and type(row.get("vmid")) is int
            and row["vmid"] not in ids
            and row.get("node") == source["selector"]["node"]
            and row.get("type") in {"lxc", "qemu"}
            and row.get("status") in {"running", "stopped"},
            "inventory-shape",
        )
        ids.add(row["vmid"])
        if row["vmid"] == target["vmid"]:
            require(exclude_target, "target-already-exists")
            continue
        result.append(
            {
                key: row.get(key)
                for key in (
                    "vmid",
                    "node",
                    "type",
                    "name",
                    "status",
                    "tags",
                    "template",
                )
            }
        )
    require(source["selector"]["vmid"] in ids, "source-missing")
    return sorted(result, key=lambda item: item["vmid"])


def template_facts(request):
    reference = request["template"]
    raw = (
        observe.native(["/usr/sbin/pvesm", "path", reference["volume"]])
        .decode()
        .strip()
    )
    path = Path(raw)
    expected = Path("/var/lib/vz/template/cache") / reference["volume"].split("/", 1)[1]
    require(path == expected and path.resolve(strict=True) == path, "template-path")
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and info.st_uid == 0
        and not info.st_mode & 0o022
        and info.st_size == reference["bytes"],
        "template-identity",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        checksum, count = hashlib.sha256(), 0
        require(
            observe.stable(os.fstat(fd)) == observe.stable(info), "template-changed"
        )
        while chunk := os.read(fd, 65536):
            count += len(chunk)
            require(count <= reference["bytes"], "template-changed")
            checksum.update(chunk)
        require(
            count == reference["bytes"]
            and checksum.hexdigest() == reference["sha256"]
            and observe.stable(os.fstat(fd))
            == observe.stable(info)
            == observe.stable(path.lstat()),
            "template-changed",
        )
    finally:
        os.close(fd)
    return {
        "path": str(path),
        "sha256": reference["sha256"],
        "identity": list(observe.stable(info)),
    }


def normalize_storage(value):
    # PVE serializes its content-type hash in per-process Perl hash order.
    # Sort this one semantic set; retain every member and all other fields.
    require(
        type(value) is dict and type(value.get("content")) is str, "storage-content"
    )
    members = value["content"].split(",")
    require(
        1 <= len(members) <= 16
        and len(members) == len(set(members))
        and all(state.matches(r"[a-z][a-z0-9_-]{0,31}", item) for item in members),
        "storage-content",
    )
    return {**value, "content": ",".join(sorted(members))}


def collect_preflight(request, facts, *, exclude_target=False):
    node = request["source_request"]["source"]["selector"]["node"]
    nodes = get("/nodes")
    require(
        type(nodes) is list
        and len(nodes) == 1
        and nodes[0].get("node") == node
        and nodes[0].get("status") == "online",
        "standalone-node",
    )
    rows = inventory(request, exclude_target=exclude_target)
    storage = normalize_storage(get("/storage/" + request["storage_id"]))
    capacity = get("/nodes/" + node + "/storage/" + request["storage_id"] + "/status")
    require(
        storage.get("type") == "dir"
        and storage.get("path") == "/var/lib/vz"
        and type(storage.get("shared", 0)) is int
        and storage.get("shared", 0) == 0,
        "storage-backing",
    )
    require(
        capacity.get("active") == capacity.get("enabled") == 1
        and capacity.get("type") == "dir"
        and {"rootdir", "vztmpl"} <= set(capacity.get("content", "").split(","))
        and type(capacity.get("avail")) is int
        and capacity["avail"] >= 3 * 1024**3,
        "storage-capacity",
    )
    require(
        Path("/var/lib/vz").resolve(strict=True) == Path("/var/lib/vz"), "storage-path"
    )
    vmid = str(request["target"]["vmid"])
    if not exclude_target:
        for path in (
            "/etc/pve/lxc/" + vmid + ".conf",
            "/etc/pve/qemu-server/" + vmid + ".conf",
            "/var/lib/vz/images/" + vmid,
            "/var/lib/lxc/" + vmid,
        ):
            require(not os.path.lexists(path), "destination-output-exists")
    ha = get("/cluster/ha/resources")
    require(
        type(ha) is list
        and not any(row.get("sid") in {"ct:" + vmid, "vm:" + vmid} for row in ha),
        "ha-target",
    )
    return {
        "source_sha256": state.sha256(state.canonical(facts)),
        "inventory": rows,
        "storage": storage,
        "template": template_facts(request),
        "ha": ha,
    }


def validate_preflight(request, value):
    """Validate a complete portable preparation proof, including at the client."""
    state.keys(value, {"source_sha256", "inventory", "storage", "template", "ha"})
    state.digest(value["source_sha256"])
    source = request["source_request"]["source"]
    rows = value["inventory"]
    require(type(rows) is list and 1 <= len(rows) <= 128, "prepared-inventory")
    ids, selected = [], None
    for row in rows:
        state.keys(row, {"vmid", "node", "type", "name", "status", "tags", "template"})
        state.integer(row["vmid"], 100, 999999999)
        require(
            row["node"] == source["selector"]["node"]
            and row["type"] in {"lxc", "qemu"}
            and row["status"] in {"running", "stopped"},
            "prepared-inventory",
        )
        require(
            type(row["name"]) is str
            and len(row["name"]) <= 128
            and (row["tags"] is None or type(row["tags"]) is str)
            and (
                row["template"] is None
                or type(row["template"]) is int
                and row["template"] in {0, 1}
            ),
            "prepared-inventory",
        )
        ids.append(row["vmid"])
        if row["vmid"] == source["selector"]["vmid"]:
            selected = row
    require(
        ids == sorted(set(ids))
        and request["target"]["vmid"] not in ids
        and selected is not None
        and selected["type"] == "lxc"
        and selected["status"] == "stopped",
        "prepared-inventory",
    )
    tags = (selected["tags"] or "").split(";")
    require(
        [tag for tag in tags if tag.startswith("cmdmesh-own-")] == [source["owner_tag"]]
        and [tag for tag in tags if tag.startswith("cmdmesh-gen-")]
        == [source["generation_tag"]],
        "prepared-source-owner",
    )
    storage = value["storage"]
    require(
        state.canonical(storage) == state.canonical(normalize_storage(storage)),
        "prepared-storage-noncanonical",
    )
    require(
        type(storage) is dict
        and storage.get("type") == "dir"
        and storage.get("path") == "/var/lib/vz"
        and type(storage.get("shared", 0)) is int
        and storage.get("shared", 0) == 0
        and type(storage.get("content")) is str
        and {"rootdir", "vztmpl"} <= set(storage["content"].split(",")),
        "prepared-storage",
    )
    template = value["template"]
    state.keys(template, {"path", "sha256", "identity"})
    expected_path = (
        "/var/lib/vz/template/cache/" + request["template"]["volume"].split("/", 1)[1]
    )
    require(
        template["path"] == expected_path
        and template["sha256"] == request["template"]["sha256"],
        "prepared-template",
    )
    identity = template["identity"]
    require(
        type(identity) is list
        and len(identity) == 9
        and all(type(part) is int and part >= 0 for part in identity)
        and identity[1] > 0
        and stat.S_ISREG(identity[2])
        and not identity[2] & 0o022
        and identity[3] == 0
        and identity[5] == 1
        and identity[6] == request["template"]["bytes"],
        "prepared-template-identity",
    )
    ha = value["ha"]
    require(type(ha) is list and len(ha) <= 128, "prepared-ha")
    for row in ha:
        require(
            type(row) is dict
            and state.matches(r"(?:ct|vm):[1-9][0-9]*", row.get("sid"))
            and row["sid"]
            not in {
                "ct:" + str(request["target"]["vmid"]),
                "vm:" + str(request["target"]["vmid"]),
                "ct:" + str(source["selector"]["vmid"]),
                "vm:" + str(source["selector"]["vmid"]),
            },
            "prepared-ha",
        )


def prepare(request):
    validate_request(request)
    with observe.source_state(request["source_request"], require_stopped=True) as facts:
        require(
            facts["quiesced"] is True and type(facts["application"]) is dict,
            "source-not-quiesced",
        )
        before = collect_preflight(request, facts)
        validate_preflight(request, before)
        value = {
            "document_type": PREPARED,
            "schema_version": 1,
            "profile_version": 1,
            "request": request,
            "preflight": before,
        }
    return value


def load_prepared(raw, trusted):
    state.digest(trusted)
    require(
        type(raw) is bytes and 0 < len(raw) <= 1048576 and state.sha256(raw) == trusted,
        "prepared-changed",
    )
    value = observe.decode(raw)
    state.keys(
        value,
        {"document_type", "schema_version", "profile_version", "request", "preflight"},
    )
    require(
        raw == state.canonical(value)
        and value["document_type"] == PREPARED
        and all(
            type(value[key]) is int and value[key] == 1
            for key in ("schema_version", "profile_version")
        ),
        "prepared-version",
    )
    validate_request(value["request"])
    validate_preflight(value["request"], value["preflight"])
    return value


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


def claim_path(request):
    source = request["source_request"]["source"]
    return RUNTIME_ROOT / state.sha256(
        state.canonical(
            [source["host_profile"]["machine_id_sha256"], request["target"]["vmid"]]
        )
    )


def claim(prepared, trusted):
    runtime()
    directory = claim_path(prepared["request"])
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        raise state.PersistenceError("persistence-recipient-target-consumed") from None
    backup.sync_directory(directory.parent)
    intent_sha = backup.write_private(
        directory / "intent.json", {"prepared": prepared, "prepared_sha256": trusted}
    )
    backup.write_private(
        directory / "write-possible.json",
        {"operation_id": prepared["request"]["operation_id"]},
    )
    return directory, intent_sha


def parse_upid(request, upid):
    node = request["source_request"]["source"]["selector"]["node"]
    vmid = str(request["target"]["vmid"])
    match = (
        re.fullmatch(
            r"UPID:"
            + re.escape(node)
            + r":([0-9A-Fa-f]{8,16}):([0-9A-Fa-f]{8,16}):([0-9A-Fa-f]{8,16}):vzcreate:"
            + vmid
            + r":root@pam:",
            upid,
        )
        if type(upid) is str
        else None
    )
    require(match is not None, "native-task-target")
    pid, pstart, started = (int(part, 16) for part in match.groups())
    require(pid > 1 and pstart > 0 and started > 0, "native-task-identity")
    return {
        "upid": upid,
        "node": node,
        "pid": pid,
        "pstart": pstart,
        "starttime": started,
        "type": "vzcreate",
        "id": vmid,
        "user": "root@pam",
    }


def post_create(request):
    source = request["source_request"]["source"]
    node = source["selector"]["node"]
    ca, _ = observe.read_regular("/etc/pve/pve-root-ca.pem", 65536)
    cert, _ = observe.read_regular("/etc/pve/nodes/" + node + "/pve-ssl.pem", 65536)
    leaf = ssl.PEM_cert_to_DER_cert(cert.decode("ascii"))
    require(
        state.sha256(ssl.PEM_cert_to_DER_cert(ca.decode("ascii")))
        == source["host_profile"]["ca_certificate_sha256"]
        and state.sha256(leaf) == source["host_profile"]["leaf_certificate_sha256"],
        "certificates-changed",
    )
    context = ssl.create_default_context(cadata=ca.decode("ascii"))
    require(
        context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname,
        "tls-policy",
    )
    auth = subprocess.run(
        ["/usr/bin/perl", "-MPVE::AccessControl", "-MJSON::PP", "-e", TICKET_PROGRAM],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=20,
        env=observe.ENV,
        umask=0o077,
    )
    require(
        auth.returncode == 0 and not auth.stderr and 0 < len(auth.stdout) <= 16384,
        "local-authentication",
    )
    credentials = observe.decode(auth.stdout)
    state.keys(credentials, {"ticket", "csrf"})
    require(
        state.matches(r"PVE:root@pam:[^\r\n\s]+", credentials["ticket"])
        and state.matches(r"[^\r\n\s]+", credentials["csrf"]),
        "local-authentication",
    )
    try:
        with socket.create_connection(("127.0.0.1", 8006), timeout=20) as raw:
            with context.wrap_socket(raw, server_hostname=node) as secure:
                require(
                    secure.getpeercert(binary_form=True) == leaf
                    and secure.version() in {"TLSv1.2", "TLSv1.3"},
                    "tls-peer",
                )
                connection = http.client.HTTPConnection(node, 8006, timeout=20)
                connection.sock = secure
                connection.request(
                    "POST",
                    "/api2/json/nodes/" + node + "/lxc",
                    urlencode(create_request(request)),
                    {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "application/json",
                        "Connection": "close",
                        "Cookie": "PVEAuthCookie="
                        + quote(credentials["ticket"], safe=""),
                        "CSRFPreventionToken": credentials["csrf"],
                    },
                )
                response = connection.getresponse()
                body = response.read(262145)
                require(
                    response.status == 200
                    and response.getheader("Content-Type", "").startswith(
                        "application/json"
                    )
                    and len(body) <= 262144,
                    "create-acknowledgement",
                )
                data = observe.decode(body)
                state.keys(data, {"data"})
                parse_upid(request, data["data"])
                result = {"upid": data["data"], "tls_verified": True}
    finally:
        credentials = auth = None
    return result


def task_state(request, upid):
    expected = parse_upid(request, upid)
    path = "/nodes/" + expected["node"] + "/tasks/" + upid
    task = get(path + "/status")
    require(
        type(task) is dict
        and set(task) <= set(expected) | {"status", "exitstatus"}
        and all(
            task.get(key) == value and type(task.get(key)) is type(value)
            for key, value in expected.items()
        )
        and task.get("status") in {"running", "stopped"},
        "native-task-status",
    )
    require(
        (task["status"] == "running" and "exitstatus" not in task)
        or (task["status"] == "stopped" and type(task.get("exitstatus")) is str),
        "native-task-status",
    )
    log = get(path + "/log", "--start", "0", "--limit", "100")
    native_outcome(task, log)
    return task, log


def native_outcome(task, log):
    require(type(log) is list and len(log) < 100, "native-log-incomplete")
    for index, row in enumerate(log, 1):
        require(
            type(row) is dict
            and set(row) == {"n", "t"}
            and type(row["n"]) is int
            and row["n"] == index
            and type(row["t"]) is str
            and len(row["t"]) <= 16384,
            "native-log-shape",
        )
    if task["status"] == "running":
        return {"native_success": None, "accepted": False, "warning_count": 0}
    messages = [row["t"] for row in log]
    warnings = [line for line in messages if line.startswith(("WARN:", "WARNING:"))]
    errors = any(line.startswith(("ERROR:", "TASK ERROR:")) for line in messages)
    code = task["exitstatus"]
    accepted = (
        bool(messages)
        and not errors
        and (
            (code == "OK" and not warnings and messages[-1] == "TASK OK")
            or (
                code == "WARNINGS: 1"
                and warnings == [WARNING]
                and messages[-1] == "TASK WARNINGS: 1"
            )
        )
    )
    return {
        "native_success": code == "OK"
        or re.fullmatch(r"WARNINGS: [1-9][0-9]*", code) is not None,
        "accepted": accepted,
        "warning_count": len(warnings),
    }


def validate_target_config(request, config):
    expected = create_request(request)
    require(
        type(config) is dict
        and set(config)
        <= {
            "digest",
            "arch",
            "ostype",
            "description",
            "hostname",
            "cores",
            "cpulimit",
            "memory",
            "swap",
            "unprivileged",
            "onboot",
            "protection",
            "tags",
            "rootfs",
        },
        "target-config-shape",
    )
    for key, value in (
        ("arch", "amd64"),
        ("ostype", "ubuntu"),
        ("hostname", expected["hostname"]),
    ):
        require(config.get(key) == value, "target-config")
    require(
        config.get("description")
        in {expected["description"], expected["description"] + "\n"},
        "target-description",
    )
    for key, value in (
        ("cores", 1),
        ("memory", 512),
        ("swap", 0),
        ("unprivileged", 1),
        ("protection", 1),
        ("onboot", 0),
    ):
        actual = config.get(key, 0 if key == "onboot" else None)
        require(type(actual) is int and actual == value, "target-config")
    require(
        type(config.get("cpulimit")) in {int, float} and config["cpulimit"] == 1,
        "target-cpu-limit",
    )
    tags = config.get("tags", "").split(";")
    require(
        len(tags) == 3 and set(tags) == set(expected["tags"].split(";")), "target-tags"
    )
    volume = (
        request["storage_id"]
        + ":"
        + str(request["target"]["vmid"])
        + "/vm-"
        + str(request["target"]["vmid"])
        + "-disk-0.raw"
    )
    require(config.get("rootfs") == volume + ",size=2G", "target-rootfs")
    return volume


def ordered_pending(rows):
    require(type(rows) is list and len(rows) <= 4096, "target-pending")
    require(
        all(
            type(row) is dict
            and state.matches(r"[A-Za-z0-9_.-]{1,128}", row.get("key"))
            and "pending" not in row
            and not row.get("delete")
            for row in rows
        ),
        "target-pending",
    )
    require(len({row["key"] for row in rows}) == len(rows), "target-pending")
    return sorted(rows, key=lambda row: row["key"])


def verify_target(request, prepared):
    node, vmid = request["source_request"]["source"]["selector"]["node"], str(
        request["target"]["vmid"]
    )
    path = "/nodes/" + node + "/lxc/" + vmid
    status = get(path + "/status/current")
    require(
        status.get("status") == "stopped"
        and status.get("pid", 0) == 0
        and status.get("uptime", 0) == 0,
        "target-not-stopped",
    )
    config = get(path + "/config")
    volume = validate_target_config(request, config)
    pending = ordered_pending(get(path + "/pending"))
    rootfs = Path(observe.native(["/usr/sbin/pvesm", "path", volume]).decode().strip())
    require(
        rootfs == Path("/var/lib/vz/images") / vmid / ("vm-" + vmid + "-disk-0.raw")
        and rootfs.resolve(strict=True) == rootfs,
        "target-rootfs-path",
    )
    info = rootfs.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and info.st_uid == 0
        and not info.st_mode & 0o022
        and info.st_size == 2 * 1024**3,
        "target-rootfs-identity",
    )
    raw = observe.native(
        ["/usr/sbin/blkid", "-p", "-o", "export", str(rootfs)]
    ).decode()
    fs = {}
    for row in raw.splitlines():
        key, separator, value = row.partition("=")
        require(separator == "=" and key not in fs, "target-filesystem")
        fs[key] = value
    require(
        fs.get("TYPE") == "ext4"
        and state.matches(
            r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", fs.get("UUID")
        )
        and fs["UUID"] != request["source_request"]["policy"]["rootfs"]["uuid"],
        "target-filesystem",
    )
    require(
        config == get(path + "/config")
        and observe.stable(info) == observe.stable(rootfs.lstat())
        and state.canonical(get(path + "/status/current")) == state.canonical(status)
        and state.canonical(ordered_pending(get(path + "/pending")))
        == state.canonical(pending),
        "target-changed",
    )
    return {
        "vmid": int(vmid),
        "config": config,
        "pending": pending,
        "status": status,
        "rootfs": {
            "volume": volume,
            "path": str(rootfs),
            "identity": list(observe.stable(info)),
            "uuid": fs["UUID"],
        },
    }


def observe_attempt(prepared, facts, directory):
    request = prepared["request"]
    require(
        state.canonical(collect_preflight(request, facts, exclude_target=True))
        == state.canonical(prepared["preflight"]),
        "source-or-environment-changed",
    )
    ack_path = directory / "acknowledgement.json"
    if not os.path.lexists(ack_path):
        return {
            "phase": "create-uncertain",
            "provisioned_verified": False,
            "rebuild_verified": False,
            "restore_verified": False,
        }
    ack, _ = backup.read_private(ack_path)
    require(ack.get("tls_verified") is True, "acknowledgement")
    expected = parse_upid(request, ack.get("upid"))
    dispatch, _ = backup.read_private(directory / "dispatch.json")
    require(
        type(dispatch.get("clock")) is int
        and dispatch["clock"] - 2 <= expected["starttime"] <= dispatch["clock"] + 60,
        "native-task-clock",
    )
    task, log = task_state(request, ack["upid"])
    outcome = native_outcome(task, log)
    result = {
        "phase": (
            "create-running" if task["status"] == "running" else "create-unqualified"
        ),
        "task": task,
        "log": log,
        "native_outcome": outcome,
        "provisioned_verified": False,
        "rebuild_verified": False,
        "restore_verified": False,
    }
    if outcome["accepted"]:
        result.update(
            phase="recipient-provisioned",
            target=verify_target(request, prepared),
            provisioned_verified=True,
        )
        closing_task, closing_log = task_state(request, ack["upid"])
        require(
            state.canonical(closing_task) == state.canonical(task)
            and state.canonical(closing_log) == state.canonical(log)
            and native_outcome(closing_task, closing_log) == outcome,
            "native-task-changed",
        )
    return result


def close_result(prepared, result):
    if result["provisioned_verified"] is not True:
        return
    request = prepared["request"]
    target = verify_target(request, prepared)
    task, log = task_state(request, result["task"]["upid"])
    require(
        state.canonical(target) == state.canonical(result["target"])
        and state.canonical(task) == state.canonical(result["task"])
        and state.canonical(log) == state.canonical(result["log"])
        and native_outcome(task, log) == result["native_outcome"],
        "final-target-or-task-changed",
    )


def provision(raw, trusted, *, timeout_seconds=180):
    prepared = load_prepared(raw, trusted)
    request = prepared["request"]
    directory = None
    try:
        with observe.source_state(
            request["source_request"], require_stopped=True
        ) as facts:
            require(
                facts["quiesced"] is True
                and type(facts["application"]) is dict
                and state.canonical(collect_preflight(request, facts))
                == state.canonical(prepared["preflight"]),
                "source-or-environment-changed",
            )
            directory, intent_sha = claim(prepared, trusted)
            backup.write_private(
                directory / "dispatch.json",
                {"clock": int(time.time()), "parameters": create_request(request)},
            )
            ack = post_create(request)
            backup.write_private(directory / "acknowledgement.json", ack)
            deadline = time.monotonic() + timeout_seconds
            while True:
                result = observe_attempt(prepared, facts, directory)
                if result["phase"] != "create-running":
                    break
                require(time.monotonic() < deadline, "create-observation-timeout")
                time.sleep(1)
            require(result["provisioned_verified"] is True, "create-not-qualified")
        close_result(prepared, result)
        complete = {
            "document_type": COMPLETE,
            "schema_version": 1,
            "profile_version": 1,
            "prepared_sha256": trusted,
            "intent_sha256": intent_sha,
            **result,
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
                            error, "code", "persistence-recipient-interrupted"
                        ),
                    },
                )
            except OSError:
                pass
        raise


def status(raw, trusted):
    prepared = load_prepared(raw, trusted)
    directory = claim_path(prepared["request"])
    backup.private_directory(directory)
    intent, _ = backup.read_private(directory / "intent.json")
    require(
        state.canonical(intent)
        == state.canonical({"prepared": prepared, "prepared_sha256": trusted}),
        "retained-intent-changed",
    )
    with observe.source_state(
        prepared["request"]["source_request"], require_stopped=True
    ) as facts:
        result = observe_attempt(prepared, facts, directory)
    close_result(prepared, result)
    return result
