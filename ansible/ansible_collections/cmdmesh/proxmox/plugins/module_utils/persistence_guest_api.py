"""Finite verified local PVE guest actions shared by lifecycle controllers.

Current owners use an immutable guest binding. The private create transport is
also used by the original recipient wrapper after its original validation.
Operation ownership, durable dispatch claims and configuration lock handoff are
the controller's responsibility. This module never retries a POST.
"""

from dataclasses import dataclass
import http.client
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time
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


def post_owner_guest_action(binding, action, dispatch_sha256, expected_epoch):
    """Send one fixed owner action and return an unqualified response observation."""
    from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
        persistence_owner_ack as owner_ack,
    )

    require(
        type(action) is str and action in {"start", "shutdown"},
        "native-guest-operation",
    )
    state.digest(dispatch_sha256)
    owner_ack.epoch_shape(expected_epoch)
    check_host(binding)
    return _post_bound(
        binding,
        action,
        owner_context={
            "dispatch_sha256": dispatch_sha256,
            "epoch": expected_epoch.copy(),
        },
    )


def _owner_clock():
    from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
        persistence_owner_ack as owner_ack,
    )

    def epoch():
        return {
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "mount_namespace": os.readlink("/proc/self/ns/mnt"),
        }

    before = epoch()
    monotonic_before = time.monotonic_ns()
    wall = time.time_ns()
    monotonic_after = time.monotonic_ns()
    owner_ack.require(before == epoch(), "sample-epoch-changed")
    value = {
        "epoch": before,
        "wall_ns": wall,
        "monotonic_before_ns": monotonic_before,
        "monotonic_after_ns": monotonic_after,
    }
    owner_ack.clock_shape(value)
    return value


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


def _post_bound(binding, action, create_parameters=None, *, owner_context=None):
    require(type(binding) is GuestBinding, "native-task-target")
    parameters = _parameters(binding, action, create_parameters)
    if owner_context is not None:
        from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
            persistence_owner_ack as owner_ack,
        )

        state.keys(owner_context, {"dispatch_sha256", "epoch"})
        require(action in {"start", "shutdown"}, "native-guest-operation")
        state.digest(owner_context["dispatch_sha256"])
        owner_ack.epoch_shape(owner_context["epoch"])
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
                peer = secure.getpeercert(binary_form=True)
                protocol = secure.version()
                require(
                    peer == leaf and protocol in {"TLSv1.2", "TLSv1.3"},
                    "tls-peer",
                )
                connection = http.client.HTTPConnection(node, 8006, timeout=20)
                connection.sock = secure
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    "Connection": "close",
                    "Cookie": "PVEAuthCookie=" + quote(credentials["ticket"], safe=""),
                    "CSRFPreventionToken": credentials["csrf"],
                }
                encoded_parameters = urlencode(parameters)
                if owner_context is not None:
                    send = _owner_clock()
                    owner_ack.clock_shape(send)
                    owner_ack.require(
                        send["epoch"] == owner_context["epoch"], "epoch-changed"
                    )
                    owner_ack.require(
                        0
                        <= send["monotonic_after_ns"] - send["monotonic_before_ns"]
                        <= owner_ack.MAX_SAMPLE_UNCERTAINTY_NS,
                        "sample-uncertainty",
                    )
                status = content_type = body = None
                complete = True
                try:
                    connection.request("POST", path, encoded_parameters, headers)
                    response = connection.getresponse()
                    status = response.status
                    content_type = response.getheader("Content-Type", "")
                    body = response.read(262145)
                    if response.length is None and not response.chunked:
                        complete = False
                        if len(body) < 262145:
                            tail = response.read(1)
                            body += tail
                            complete = not tail and response.isclosed()
                    else:
                        complete = (
                            response.length == 0
                            or (response.length is None and response.isclosed())
                        ) and (not response.chunked or response.chunk_left is None)
                except (OSError, http.client.HTTPException) as error:
                    if owner_context is None:
                        raise
                    complete = False
                    if isinstance(error, http.client.IncompleteRead):
                        body = error.partial[:262145]
                if owner_context is not None:
                    try:
                        receive = _owner_clock()
                    except (OSError, ValueError):
                        receive = None
                    result = owner_ack.observe_response(
                        binding,
                        action,
                        owner_context["dispatch_sha256"],
                        send,
                        receive,
                        tls_verified=True,
                        tls_peer_sha256=state.sha256(peer),
                        tls_version=protocol,
                        http_status=status,
                        content_type=content_type,
                        body=body,
                        body_complete=complete,
                    )
                else:
                    require(
                        status == 200
                        and complete
                        and content_type.startswith("application/json")
                        and len(body) <= 262144,
                        "create-acknowledgement",
                    )
                    data = observe.decode(body)
                    state.keys(data, {"data"})
                    parse_upid(binding, data["data"], kind=kind)
                    result = {"upid": data["data"], "tls_verified": True}
    finally:
        credentials = auth = headers = None
    return result


def get(path, *arguments):
    return observe.decode(
        observe.native(
            ["/usr/bin/pvesh", "get", path, *arguments, "--output-format", "json"]
        )
    )


def validate_task_status(binding, upid, task, *, kind="vzstart"):
    """Validate one task-status document without host, network or file access."""
    expected = parse_upid(binding, upid, kind=kind)
    require(
        type(task) is dict
        and set(task) <= set(expected) | {"status", "exitstatus"}
        and all(
            task.get(key) == value and type(task.get(key)) is type(value)
            for key, value in expected.items()
        )
        and type(task.get("status")) is str
        and task["status"] in {"running", "stopped"},
        "native-task-status",
    )
    require(
        (task["status"] == "running" and "exitstatus" not in task)
        or (task["status"] == "stopped" and type(task.get("exitstatus")) is str),
        "native-task-status",
    )


def task_state(binding, upid, *, kind="vzstart"):
    expected = parse_upid(binding, upid, kind=kind)
    check_host(binding)
    path = "/nodes/" + expected["node"] + "/tasks/" + upid
    task = get(path + "/status")
    validate_task_status(binding, upid, task, kind=kind)
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
