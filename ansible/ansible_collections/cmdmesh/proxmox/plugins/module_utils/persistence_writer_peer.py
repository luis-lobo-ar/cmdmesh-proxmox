"""Bind a reference-ledger process to admitted guest and image evidence.

Pure validation does not prove that supplied observations are current. The
lifecycle caller must collect and close them while retaining its native leases.
"""

import os

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_kernel as kernel,
    persistence_retained_runtime as runtime,
    persistence_state as state,
    unix_peer,
)

ARGV = (
    "/usr/bin/python3",
    "-I",
    "-S",
    "-B",
    "/opt/reference-ledger/ledger.py",
    "serve",
    "--data",
    "/var/lib/reference-ledger",
    "--config",
    "/etc/reference-ledger",
    "--socket",
    "/run/reference-ledger/api.sock",
)


def require(value, code):
    state.require(value, "persistence-writer-peer-" + code)


def main_pid(image):
    require(type(image) is dict and type(image.get("unit")) is dict, "unit")
    value = image["unit"].get("MainPID")
    require(
        state.matches(r"[1-9][0-9]{0,9}", value) and 1 < int(value) < 2**31, "main-pid"
    )
    return int(value)


def validate(
    request, profile, kernel_evidence, image_evidence, init, peer, python_executable
):
    """Validate one explicit active service without EX, SQL or native commands."""
    require(type(init) is type(peer) is unix_peer.ProcessIdentity, "process-type")
    _, image, binding = runtime.load_profile(request, profile)
    kernel.validate(binding, kernel_evidence)
    guest_pid = main_pid(image_evidence)
    runtime.validate_image(
        profile, image, image_evidence, kernel_evidence, writer_pid=guest_pid
    )
    native_init = kernel_evidence["init"]
    mapping = request["policy"]["mapping"]
    offset = mapping["offset"]
    require(
        (init.pid, init.birth, init.pid_namespace)
        == (
            native_init["pid"],
            native_init["pstart"],
            native_init["pid_namespace_inode"],
        )
        and init.nspid == (init.pid, 1)
        and init.root[0] == os.makedev(*kernel_evidence["rootfs"]["device"])
        and init.uid == init.gid == offset
        and init.cgroup == kernel_evidence["cgroup"]["path"] + "\n",
        "init-binding",
    )
    require(
        type(python_executable) is tuple
        and len(python_executable) == 2
        and all(type(value) is int and value > 0 for value in python_executable),
        "python-executable",
    )
    cgroup = init.cgroup.rstrip("\n").rsplit("/", 1)[0]
    require(
        peer.pid != init.pid
        and peer.birth >= init.birth
        and peer.pid_namespace == init.pid_namespace
        and peer.mount_namespace == init.mount_namespace
        and peer.nspid == (peer.pid, guest_pid)
        and peer.uid == offset + mapping["uid"]
        and peer.gid == offset + mapping["gid"]
        and peer.root == init.root
        and peer.executable == python_executable
        and peer.argv == ARGV
        and peer.cgroup == cgroup + "/system.slice/reference-ledger.service\n",
        "service-binding",
    )
