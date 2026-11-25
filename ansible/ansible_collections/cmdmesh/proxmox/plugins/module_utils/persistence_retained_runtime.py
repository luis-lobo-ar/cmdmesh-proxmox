"""Read-only retained-runtime evidence primitives; no lifecycle operations.

These bind checks require previously admitted ownership, host/native leases and
kernel evidence. They do not establish application quiescence or restore health.
"""

from contextlib import ExitStack
import os
from pathlib import Path
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_kernel as kernel,
    persistence_state as state,
)

PROC_ROOT = Path("/proc")
GUEST_BINDS = {"data": "/var/lib/reference-ledger", "config": "/etc/reference-ledger"}


def require(value, code):
    state.require(value, "persistence-retained-runtime-" + code)


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
                == table
                and kernel.reader.memory.init_state(init["pid"]) == identity,
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
    except OSError:
        raise state.PersistenceError(
            "persistence-retained-runtime-bind-unavailable"
        ) from None
    return result
