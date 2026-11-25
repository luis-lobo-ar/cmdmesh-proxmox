"""Read-only directory backing and actual reference-writer lock observations.

Callers admit the host, guest, image and process first and retain native leases.
These helpers never acquire an application lock or open its database.
"""

import os
from pathlib import Path
import re
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_state as state,
)


def require(value, code):
    state.require(value, "persistence-writer-paths-" + code)


def identity(info):
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


def directory(stack, root, relative, root_owner, owner, *, mode=0o700):
    """Walk only real directories below a caller-admitted root FD."""
    require(
        type(relative) is str
        and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", relative)
        and all(part not in (".", "..") for part in relative.split("/")),
        "relative-path",
    )
    require(mode in (0o700, 0o755), "directory-mode")
    for expected in (root_owner, owner):
        require(
            type(expected) is tuple
            and len(expected) == 2
            and all(type(value) is int and 0 <= value < 2**32 for value in expected),
            "directory-owner",
        )
    parts = relative.split("/")
    current = root
    try:
        for index, part in enumerate(parts):
            current = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=current,
            )
            stack.callback(os.close, current)
            info = os.fstat(current)
            expected_owner = owner if index == len(parts) - 1 else root_owner
            expected_mode = mode if index == len(parts) - 1 else 0o755
            require(
                stat.S_ISDIR(info.st_mode)
                and stat.S_IMODE(info.st_mode) == expected_mode
                and (info.st_uid, info.st_gid) == expected_owner,
                "directory-identity",
            )
        return current
    except OSError:
        raise state.PersistenceError(
            "persistence-writer-paths-directory-unavailable"
        ) from None


def backing(descriptor, host):
    """Require an open guest directory to name the actual retained host directory."""
    try:
        host = Path(host)
        require(host.is_absolute() and host.resolve(strict=True) == host, "host-path")
        actual, expected = os.fstat(descriptor), host.lstat()
        require(
            stat.S_ISDIR(actual.st_mode)
            and stat.S_ISDIR(expected.st_mode)
            and (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino),
            "bind-backing",
        )
    except OSError:
        raise state.PersistenceError(
            "persistence-writer-paths-backing-unavailable"
        ) from None


def _peer_lock_fd(pid, target, uid, gid):
    # /proc/locks retains the acquisition PID when an OFD is inherited. Require
    # that this process still holds a matching locked FD, without opening or
    # duplicating the application's open file description.
    directory = Path("/proc") / str(pid) / "fdinfo"
    entries = list(directory.iterdir())
    require(len(entries) <= 65536, "writer-descriptors")
    matched = 0
    for entry in entries:
        require(entry.name.isdigit(), "writer-descriptors")
        descriptor = directory.parent / "fd" / entry.name
        try:
            before = descriptor.stat()
        except FileNotFoundError:
            continue
        if (os.major(before.st_dev), os.minor(before.st_dev), before.st_ino) != target:
            continue
        require(
            stat.S_ISREG(before.st_mode)
            and (before.st_uid, before.st_gid) == (uid, gid),
            "writer-descriptor",
        )
        with entry.open("rb") as source:
            raw = source.read(65537)
        require(len(raw) <= 65536, "writer-descriptor")
        locks = []
        for row in raw.decode("ascii").splitlines():
            if row.startswith("lock:"):
                fields = row[5:].split()
                require(
                    len(fields) == 8
                    and fields[1:5] == ["FLOCK", "ADVISORY", "WRITE", str(pid)]
                    and fields[6:] == ["0", "EOF"],
                    "writer-descriptor-lock",
                )
                address = fields[5].split(":")
                require(
                    re.fullmatch(r"[a-fA-F0-9]+:[a-fA-F0-9]+:[0-9]+", fields[5])
                    is not None
                    and len(address) == 3
                    and (int(address[0], 16), int(address[1], 16), int(address[2]))
                    == target,
                    "writer-descriptor-lock",
                )
                locks.append(row)
        require(
            identity(descriptor.stat()) == identity(before), "writer-descriptor-changed"
        )
        if locks:
            matched += 1
    require(matched > 0, "writer-descriptor-missing")


def writer_lease(config, pid, uid, gid):
    """Observe the actor's kernel FLOCK; acquire no SH or EX application lock."""
    require(type(pid) is int and 1 < pid < 2**31, "writer-pid")
    require(
        all(type(value) is int and 0 <= value < 2**32 for value in (uid, gid)),
        "writer-credentials",
    )
    try:
        parent = os.fstat(config)
        require(
            stat.S_ISDIR(parent.st_mode)
            and stat.S_IMODE(parent.st_mode) == 0o700
            and (parent.st_uid, parent.st_gid) == (uid, gid),
            "config-directory",
        )
        before = os.stat("application.json", dir_fd=config, follow_symlinks=False)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600
            and (before.st_uid, before.st_gid) == (uid, gid),
            "config-file",
        )
        target = (os.major(before.st_dev), os.minor(before.st_dev), before.st_ino)
        with open("/proc/locks", "rb") as source:
            raw = source.read(1048577)
        require(len(raw) <= 1048576, "lock-table")
        matched = []
        for row in raw.decode("ascii").splitlines():
            fields = row.split()
            offset = 1 if len(fields) > 1 and fields[1] == "->" else 0
            require(len(fields) == 8 + offset, "lock-table")
            address = fields[5 + offset]
            require(
                re.fullmatch(r"[a-fA-F0-9]+:[a-fA-F0-9]+:[0-9]+", address), "lock-table"
            )
            major, minor, inode = address.split(":")
            if (int(major, 16), int(minor, 16), int(inode)) == target:
                require(
                    offset == 0
                    and fields[1:5] == ["FLOCK", "ADVISORY", "WRITE", str(pid)]
                    and fields[6:] == ["0", "EOF"],
                    "writer-lock",
                )
                matched.append(row)
        require(len(matched) == 1, "writer-lock")
        _peer_lock_fd(pid, target, uid, gid)
        require(
            identity(before)
            == identity(
                os.stat("application.json", dir_fd=config, follow_symlinks=False)
            )
            and identity(parent) == identity(os.fstat(config)),
            "configuration-changed",
        )
        return {
            "pid": pid,
            "device": before.st_dev,
            "inode": before.st_ino,
            "configuration_identity": list(identity(before)),
        }
    except (OSError, UnicodeError):
        raise state.PersistenceError(
            "persistence-writer-paths-lock-unavailable"
        ) from None
