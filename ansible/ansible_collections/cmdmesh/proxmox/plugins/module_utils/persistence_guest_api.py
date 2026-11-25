"""Finite verified local PVE guest actions shared by lifecycle controllers.

Current owners use an immutable guest binding. The private create transport is
also used by the original recipient wrapper after its original validation.
Operation ownership, durable dispatch claims and configuration lock handoff are
the controller's responsibility. This module never retries a POST.
"""

from dataclasses import dataclass
import http.client
import os
import re
import socket
import ssl
import subprocess
from urllib.parse import quote, urlencode

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_observe as observe,
    persistence_state as state,
)

WARNING = "WARN: Systemd 255 detected. You may need to enable nesting."
TICKET_PROGRAM = "PVE::Cluster::cfs_update(); die 'auth key not current' unless PVE::AccessControl::check_authkey(1); print JSON::PP::encode_json({ticket=>PVE::AccessControl::assemble_ticket('root@pam'),csrf=>PVE::AccessControl::assemble_csrf_prevention_token('root@pam')});"


def require(value, code):
    # Keep the established wire error codes for the existing recipient API.
    state.require(value, "persistence-recipient-" + code)


@dataclass(frozen=True)
class GuestBinding:
    node: str
    vmid: int
    machine_id_sha256: str
    ca_sha256: str
    leaf_sha256: str

    def __post_init__(self):
        state.require(
            state.matches(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.node),
            "persistence-guest-api-binding",
        )
        state.integer(self.vmid, 100, 999999)
        for value in (self.machine_id_sha256, self.ca_sha256, self.leaf_sha256):
            state.digest(value)

    @classmethod
    def from_source(cls, source):
        state.source_identity(source)
        return cls(
            node=source["selector"]["node"],
            vmid=source["selector"]["vmid"],
            machine_id_sha256=source["host_profile"]["machine_id_sha256"],
            ca_sha256=source["host_profile"]["ca_certificate_sha256"],
            leaf_sha256=source["host_profile"]["leaf_certificate_sha256"],
        )


def check_host(binding):
    state.require(type(binding) is GuestBinding, "persistence-guest-api-binding")
    state.require(
        os.geteuid() == 0 and socket.gethostname() == binding.node,
        "persistence-guest-api-wrong-host",
    )
    raw, _ = observe.read_regular("/etc/machine-id", 64)
    state.require(
        re.fullmatch(b"[a-f0-9]{32}\\n?", raw) is not None
        and state.sha256(raw.strip()) == binding.machine_id_sha256,
        "persistence-guest-api-wrong-host",
    )


def parse_upid(binding, upid, *, kind="vzstart"):
    require(type(binding) is GuestBinding, "native-task-target")
    require(kind in {"vzcreate", "vzstart", "vzshutdown"}, "native-task-operation")
    node, vmid = binding.node, str(binding.vmid)
    match = (
        re.fullmatch(
            r"UPID:"
            + re.escape(node)
            + r":([0-9A-Fa-f]{8,16}):([0-9A-Fa-f]{8,16}):([0-9A-Fa-f]{8,16}):"
            + kind
            + ":"
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
        "type": kind,
        "id": vmid,
        "user": "root@pam",
    }


def post_guest_action(binding, action):
    require(action in {"start", "shutdown"}, "native-guest-operation")
    check_host(binding)
    return _post_bound(binding, action)


def _parameters(binding, action, supplied):
    require(action in {"create", "start", "shutdown"}, "native-operation")
    if action != "create":
        require(supplied is None, "native-parameters")
        return {} if action == "start" else {"timeout": "60", "forceStop": "0"}
    fixed = {
        "cores": "1",
        "cpulimit": "1",
        "memory": "512",
        "swap": "0",
        "unprivileged": "1",
        "onboot": "0",
        "start": "0",
        "protection": "1",
        "description": "Owned CmdMesh reference rebuild recipient; stopped and isolated",
    }
    state.keys(supplied, {*fixed, "vmid", "hostname", "ostemplate", "rootfs", "tags"})
    require(
        all(
            supplied[key] == value and type(supplied[key]) is str
            for key, value in fixed.items()
        ),
        "native-parameters",
    )
    require(
        supplied["vmid"] == str(binding.vmid)
        and state.matches(r"[a-zA-Z0-9][a-zA-Z0-9-]{0,62}", supplied["hostname"])
        and state.matches(
            r"cmdmesh-ansible;cmdmesh-own-[a-f0-9]{32};cmdmesh-gen-[a-f0-9]{32}",
            supplied["tags"],
        ),
        "native-parameters",
    )
    require(
        state.matches(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}:2", supplied["rootfs"]),
        "native-parameters",
    )
    storage = supplied["rootfs"].split(":", 1)[0]
    require(
        state.matches(
            re.escape(storage)
            + r":vztmpl/ubuntu-24\.04-standard_[a-zA-Z0-9_.-]+_amd64\.tar\.zst",
            supplied["ostemplate"],
        ),
        "native-parameters",
    )
    return dict(supplied)


def _post_bound(binding, action, create_parameters=None):
    require(type(binding) is GuestBinding, "native-task-target")
    parameters = _parameters(binding, action, create_parameters)
    node = binding.node
    path = "/api2/json/nodes/" + node + "/lxc"
    kind = {"create": "vzcreate", "start": "vzstart", "shutdown": "vzshutdown"}[action]
    if action != "create":
        path += "/" + str(binding.vmid) + "/status/" + action
    ca, _ = observe.read_regular("/etc/pve/pve-root-ca.pem", 65536)
    cert, _ = observe.read_regular("/etc/pve/nodes/" + node + "/pve-ssl.pem", 65536)
    leaf = ssl.PEM_cert_to_DER_cert(cert.decode("ascii"))
    require(
        state.sha256(ssl.PEM_cert_to_DER_cert(ca.decode("ascii"))) == binding.ca_sha256
        and state.sha256(leaf) == binding.leaf_sha256,
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
                    path,
                    urlencode(parameters),
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
                parse_upid(binding, data["data"], kind=kind)
                result = {"upid": data["data"], "tls_verified": True}
    finally:
        credentials = auth = None
    return result


def get(path, *arguments):
    return observe.decode(
        observe.native(
            ["/usr/bin/pvesh", "get", path, *arguments, "--output-format", "json"]
        )
    )


def task_state(binding, upid, *, kind="vzstart"):
    expected = parse_upid(binding, upid, kind=kind)
    check_host(binding)
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
