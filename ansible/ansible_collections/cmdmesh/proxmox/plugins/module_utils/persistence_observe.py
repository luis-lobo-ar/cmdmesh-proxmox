"""Read-only source qualification for the fixed reference persistence profile.

The shared pre-start reader is a content-addressed, fixed public dependency, not
an operator-supplied hook. Running observations never claim SQLite consistency.
source_state holds the existing application's flock across a stopped operation.
"""

from contextlib import contextmanager, nullcontext
import copy
import fcntl
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import stat
import subprocess
import time
from types import SimpleNamespace

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_state as state,
)

REFERENCE_GUARD_SHA256 = (
    "8a96f2ce9fcfce64221263f3fee70b399449d5a66d2d6d938a493bcdcf9666e1"
)
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
IDENTITY_SQL = "CREATE TABLE identity (instance_id TEXT NOT NULL)"
ENTRIES_SQL = "CREATE TABLE entries (sequence INTEGER PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE, value TEXT NOT NULL)"
SCHEMA = [
    ("table", "entries", "entries", ENTRIES_SQL),
    ("table", "identity", "identity", IDENTITY_SQL),
    ("index", "sqlite_autoindex_entries_1", "entries", None),
]


def require(condition, code):
    state.require(condition, "persistence-" + code)


def absolute(value):
    return (
        type(value) is str
        and value.startswith("/")
        and value != "/"
        and str(Path(value)) == value
        and ".." not in Path(value).parts
        and not any(c in value for c in "\0\r\n")
    )


def stable(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def read_regular(path, limit):
    path = Path(path)
    require(absolute(str(path)) and path.resolve(strict=True) == path, "file-path")
    before = path.lstat()
    require(
        stat.S_ISREG(before.st_mode)
        and before.st_nlink == 1
        and 0 < before.st_size <= limit,
        "file-type",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(stable(os.fstat(fd)) == stable(before), "file-changed")
        raw = bytearray()
        while chunk := os.read(fd, min(65536, limit + 1 - len(raw))):
            raw.extend(chunk)
            require(len(raw) <= limit, "file-size")
        require(
            stable(os.fstat(fd)) == stable(before)
            and stable(path.lstat()) == stable(before),
            "file-changed",
        )
    finally:
        os.close(fd)
    return bytes(raw), before


def load_guard(reference):
    state.keys(reference, {"path", "sha256"})
    require(reference["sha256"] == REFERENCE_GUARD_SHA256, "guard-unsupported")
    raw, info = read_regular(reference["path"], 65536)
    require(
        info.st_uid in {0, os.geteuid()}
        and not info.st_mode & 0o6022
        and state.sha256(raw) == REFERENCE_GUARD_SHA256,
        "guard-changed",
    )
    namespace = {"__name__": "cmdmesh_reference_guard"}
    exec(compile(raw, "<cmdmesh-reference-guard-v2>", "exec"), namespace)
    return SimpleNamespace(**namespace)


def validate_request(request, guard):
    state.keys(
        request,
        {
            "schema_version",
            "source",
            "policy",
            "reference_guard",
            "backup_store",
            "versions",
        },
    )
    require(
        type(request["schema_version"]) is int and request["schema_version"] == 1,
        "observer-version",
    )
    state.source_identity(request["source"])
    p, source = request["policy"], request["source"]
    guard.validate_policy(p)
    require(
        p["node"] == source["selector"]["node"]
        and p["vmid"] == source["selector"]["vmid"]
        and p["owner_tag"] == source["owner_tag"]
        and p["generation_tag"] == source["generation_tag"]
        and all(type(v) is int for v in p["mapping"].values())
        and p["mapping"] == state.MAPPING,
        "observer-policy-mismatch",
    )
    pair = p["datasets"]
    state.pair_key(pair)
    require(
        all(item["name"].rsplit("/", 1)[-1] == role for role, item in pair.items())
        and len({item["name"].rsplit("/", 1)[0] for item in pair.values()}) == 1,
        "observer-sibling-mismatch",
    )
    store = request["backup_store"]
    state.keys(store, {"mountpoint", "source", "file_uid", "file_gid"})
    require(
        absolute(store["mountpoint"])
        and state.matches(
            r"(?:[A-Za-z0-9.-]+|\[[a-fA-F0-9:]+\]):/[^\s\0]*", store["source"]
        ),
        "backup-store-policy",
    )
    for key in ("file_uid", "file_gid"):
        state.integer(store[key], 0, 2**32 - 2)
    state.keys(request["versions"], {"pve-manager", "pve-container", "zfsutils-linux"})
    for package, prefix in (
        ("pve-manager", "9."),
        ("pve-container", "6."),
        ("zfsutils-linux", "2.4."),
    ):
        version = request["versions"][package]
        require(
            state.matches(r"[A-Za-z0-9.+:~_-]{1,128}", version)
            and version.startswith(prefix),
            "observer-version-unsupported",
        )


def native(argv):
    result = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=20,
        env=ENV,
        umask=0o077,
    )
    require(
        result.returncode == 0 and not result.stderr and len(result.stdout) <= 262144,
        "observation-command",
    )
    return result.stdout


def decode(raw):
    # The manifest decoder supplies duplicate/non-finite/depth checks. Its
    # semantic manifest validator is intentionally not used for native JSON.
    import json

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "observation-duplicate-field")
            result[key] = value
        return result

    def invalid(unused):
        raise state.PersistenceError("persistence-observation-json")

    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise state.PersistenceError("persistence-observation-json") from None


def host_facts(request):
    node = request["source"]["selector"]["node"]
    require(os.geteuid() == 0 and socket.gethostname() == node, "wrong-host")
    machine, _ = read_regular("/etc/machine-id", 64)
    require(re.fullmatch(b"[a-f0-9]{32}\n?", machine) is not None, "host-machine-id")
    fingerprints = {"machine_id_sha256": state.sha256(machine.strip())}
    for field, path in (
        ("ca_certificate_sha256", "/etc/pve/pve-root-ca.pem"),
        ("leaf_certificate_sha256", "/etc/pve/nodes/" + node + "/pve-ssl.pem"),
    ):
        raw, _ = read_regular(path, 65536)
        fingerprints[field] = state.sha256(
            ssl.PEM_cert_to_DER_cert(raw.decode("ascii"))
        )
    require(fingerprints == request["source"]["host_profile"], "wrong-host")
    rows = (
        native(
            [
                "/usr/bin/dpkg-query",
                "-W",
                "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n",
                "pve-manager",
                "pve-container",
                "zfsutils-linux",
            ]
        )
        .decode()
        .splitlines()
    )
    versions = {}
    for row in rows:
        fields = row.split("\t")
        require(
            len(fields) == 3 and fields[2] == "ii " and fields[0] not in versions,
            "host-packages",
        )
        versions[fields[0]] = fields[1]
    require(versions == request["versions"], "host-version-mismatch")
    require(
        os.readlink("/proc/self/ns/mnt") == os.readlink("/proc/1/ns/mnt"),
        "host-mount-namespace",
    )
    return {
        "host_profile": fingerprints,
        "versions": versions,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "mount_namespace": os.readlink("/proc/self/ns/mnt"),
    }


def guest_facts(policy):
    base = "/nodes/" + policy["node"] + "/lxc/" + str(policy["vmid"])
    read = lambda suffix: decode(
        native(["/usr/bin/pvesh", "get", base + suffix, "--output-format", "json"])
    )
    config, status, pending = read("/config"), read("/status/current"), read("/pending")
    ha = decode(
        native(
            [
                "/usr/bin/pvesh",
                "get",
                "/cluster/ha/resources",
                "--output-format",
                "json",
            ]
        )
    )
    require(
        type(ha) is list
        and all(type(row) is dict and type(row.get("sid")) is str for row in ha),
        "ha-observation",
    )
    require(type(status) is dict, "guest-status")
    return {
        "config": config,
        "status": status.get("status"),
        "pending": pending,
        "ha_membership": any(row["sid"] == "ct:" + str(policy["vmid"]) for row in ha),
    }


def validate_guest(policy, facts):
    config = facts["config"]
    require(
        type(config) is dict
        and type(config.get("unprivileged")) is int
        and config["unprivileged"] == 1
        and type(config.get("onboot", 0)) is int
        and config.get("onboot", 0) == 0
        and type(config.get("protection")) is int
        and config["protection"] == 1
        and not any(
            k.startswith(("net", "dev", "lxc"))
            or k in {"hookscript", "features", "lock"}
            for k in config
        ),
        "guest-isolation",
    )
    tags = config.get("tags", "").split(";") if type(config.get("tags")) is str else []
    require(
        [v for v in tags if v.startswith("cmdmesh-own-")] == [policy["owner_tag"]]
        and [v for v in tags if v.startswith("cmdmesh-gen-")]
        == [policy["generation_tag"]],
        "guest-ownership",
    )
    require(
        type(config.get("rootfs")) is str
        and config["rootfs"].split(",", 1)[0] == policy["rootfs"]["volume"],
        "guest-rootfs",
    )
    require(
        {k for k in config if re.fullmatch(r"mp[0-9]+", k)} == {"mp0", "mp1"},
        "guest-binds",
    )
    for index, role, target in (
        (0, "data", "/var/lib/reference-ledger"),
        (1, "config", "/etc/reference-ledger"),
    ):
        mount = config["mp" + str(index)]
        require(type(mount) is str, "guest-binds")
        path, *options = mount.split(",")
        require(
            path == policy["datasets"][role]["mountpoint"]
            and len(options) == 2
            and set(options) == {"mp=" + target, "backup=0"},
            "guest-binds",
        )
    require(
        facts["status"] in {"running", "stopped"} and facts["ha_membership"] is False,
        "guest-state",
    )
    pending = facts["pending"]
    require(
        type(pending) is list
        and all(
            type(row) is dict and "pending" not in row and not row.get("delete")
            for row in pending
        ),
        "guest-pending",
    )


def validate_mount(expected, raw):
    require(
        type(raw) is dict
        and set(raw) == {"filesystems"}
        and type(raw["filesystems"]) is list
        and len(raw["filesystems"]) == 1,
        "backup-mount",
    )
    row = raw["filesystems"][0]
    require(
        type(row) is dict
        and set(row) == {"target", "source", "fstype", "fsroot", "id", "options"},
        "backup-mount",
    )
    require(
        row["target"] == expected["mountpoint"]
        and row["source"] == expected["source"]
        and row["fstype"] == "nfs"
        and row["fsroot"] == "/"
        and type(row["id"]) is int
        and row["id"] > 0
        and type(row["options"]) is str,
        "backup-mount",
    )
    options = set(row["options"].split(","))
    require(
        {
            "rw",
            "hard",
            "vers=3",
            "proto=tcp",
            "nodev",
            "nosuid",
            "noexec",
            "nolock",
            "local_lock=all",
        }
        <= options
        and not (
            {"soft", "softerr", "softreval", "ro", "exec", "suid", "dev"} & options
        ),
        "backup-mount-options",
    )
    return row


def mount_facts(expected):
    path = Path(expected["mountpoint"])
    require(path.resolve(strict=True) == path and path.is_dir(), "backup-mount-path")
    row = validate_mount(
        expected,
        decode(
            native(
                [
                    "/usr/bin/findmnt",
                    "--json",
                    "--mountpoint",
                    str(path),
                    "-o",
                    "TARGET,SOURCE,FSTYPE,FSROOT,ID,OPTIONS",
                ]
            )
        ),
    )
    info = path.lstat()
    # The export root may be shared. Report it, never change or call it private.
    return {
        "mount": row,
        "device": info.st_dev,
        "inode": info.st_ino,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
    }


@contextmanager
def locked_config(path, uid, gid):
    raw, before = read_regular(path, 4096)
    require(
        before.st_uid == uid
        and before.st_gid == gid
        and stat.S_IMODE(before.st_mode) == 0o600,
        "configuration-permissions",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(stable(os.fstat(fd)) == stable(before), "configuration-changed")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise state.PersistenceError("persistence-writer-active") from None
        yield raw
        require(
            stable(os.fstat(fd)) == stable(before)
            and stable(Path(path).lstat()) == stable(before),
            "configuration-changed",
        )
    finally:
        os.close(fd)


def read_database(path, instance_id):
    path = Path(path)
    for suffix in ("-wal", "-shm", "-journal"):
        require(not os.path.lexists(str(path) + suffix), "database-sidecar")
    raw, before = read_regular(path, 16777216)
    db = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True, timeout=0)
    try:
        deadline = time.monotonic() + 5
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        require(
            db.execute("PRAGMA integrity_check").fetchall() == [("ok",)],
            "database-integrity",
        )
        require(
            db.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name"
            ).fetchall()
            == SCHEMA,
            "database-schema",
        )
        require(
            db.execute("SELECT instance_id FROM identity").fetchall()
            == [(instance_id,)],
            "database-identity",
        )
        rows = db.execute(
            "SELECT sequence,operation_id,value FROM entries ORDER BY sequence LIMIT 4097"
        ).fetchall()
        require(
            1 <= len(rows) <= 4096
            and all(
                type(seq) is int
                and seq > 0
                and state.matches(r"[a-f0-9]{32}", operation)
                and type(value) is str
                and len(value.encode()) <= 65536
                for seq, operation, value in rows
            )
            and any(value for _, _, value in rows),
            "database-records",
        )
        encoded = state.canonical(rows)
        require(len(encoded) <= 1048576, "database-record-limit")
    except sqlite3.Error:
        raise state.PersistenceError("persistence-database-unqualified") from None
    finally:
        db.close()
    after, _ = read_regular(path, 16777216)
    require(raw == after and stable(path.lstat()) == stable(before), "database-changed")
    for suffix in ("-wal", "-shm", "-journal"):
        require(not os.path.lexists(str(path) + suffix), "database-sidecar")
    return {
        "database_sha256": state.sha256(raw),
        "records_sha256": state.sha256(encoded),
        "record_count": len(rows),
    }


@contextmanager
def locked_application(policy, guard):
    mapping = policy["mapping"]
    config = Path(policy["datasets"]["config"]["mountpoint"]) / "application.json"
    with locked_config(
        config, mapping["offset"] + mapping["uid"], mapping["offset"] + mapping["gid"]
    ):
        facts = guard.collect(policy)
        guard.validate(policy, facts, policy["vmid"])
        app = {
            "instance_id": policy["application"]["instance_id"],
            "config_sha256": policy["application"]["config_sha256"],
            "mapping": dict(mapping),
        }
        database = Path(policy["datasets"]["data"]["mountpoint"]) / "ledger.sqlite3"
        app.update(read_database(database, app["instance_id"]))
        yield app
        require(
            read_database(database, app["instance_id"])
            == {
                k: app[k] for k in ("database_sha256", "records_sha256", "record_count")
            },
            "database-changed",
        )


@contextmanager
def source_state(request, require_stopped=False):
    guard = load_guard(
        request.get("reference_guard") if type(request) is dict else None
    )
    validate_request(request, guard)
    host = host_facts(request)
    policy = request["policy"]
    guest = guest_facts(policy)
    validate_guest(policy, guest)  # Must precede any declared dataset/file read.
    require(not require_stopped or guest["status"] == "stopped", "source-not-stopped")
    guarded = guard.collect(policy)
    guard.validate(policy, guarded, policy["vmid"])
    store = mount_facts(request["backup_store"])
    stopped = guest["status"] == "stopped"
    with locked_application(policy, guard) if stopped else nullcontext(None) as app:
        yield {
            "schema_version": 1,
            "source": request.get("source"),
            "host": host,
            "guest": guest,
            "guarded": guarded,
            "backup_store": store,
            "quiesced": stopped,
            "application": app,
            "backup_verified": False,
        }
        require(
            host_facts(request) == host
            and guest_facts(policy) == guest
            and mount_facts(request["backup_store"]) == store,
            "source-changed",
        )
        after = guard.collect(policy)
        guard.validate(policy, after, policy["vmid"])
        if not stopped:
            # Live database metadata may change; no live SQL/raw content is read
            # or claimed consistent. Other guard invariants must remain exact.
            before_compare, after_compare = copy.deepcopy(guarded), copy.deepcopy(after)
            for facts in (before_compare, after_compare):
                if "application" in facts:
                    facts["application"].pop("database", None)
        else:
            before_compare, after_compare = guarded, after
        require(after_compare == before_compare, "source-changed")


def observe(request):
    with source_state(request) as facts:
        result = facts
    return result
