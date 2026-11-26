"""Exclusive, complete-or-absent metadata publication on a qualified Linux FS.

This is not a current/worker fence or native permission. Callers own the real
leases and validate the storage profile. A failure after link can leave a full
unaccepted candidate; this helper never overwrites or removes that final name.
"""

import ctypes
from dataclasses import dataclass
import errno
import hashlib
import os
from pathlib import Path
import stat
import sys

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_observe as observe,
    persistence_owner_storage_profile as storage,
    persistence_state as state,
)

PROTOCOL = storage.PROTOCOL
LIMIT = 4194304
PROC_SUPER_MAGIC = 0x9FA0
AT_SYMLINK_FOLLOW = 0x400


@dataclass(frozen=True, slots=True)
class PublicationReceipt:
    """Closed syscall observation; not a lease, witness or publication permission."""

    path: str
    parent_identity: tuple[int, ...]
    anonymous_name: str
    before_identity: tuple[int, ...]
    final_identity: tuple[int, ...]
    payload_sha256: str
    payload_bytes: int
    protocol: str


def require(value, code):
    state.require(value, "persistence-owner-atomic-" + code)


def _private(info, links, size):
    _private_identity(observe.stable(info), links, size)


def _private_identity(identity, links, size):
    require(
        stat.S_ISREG(identity[2])
        and stat.S_IMODE(identity[2]) == 0o600
        and (identity[3], identity[4]) == (os.geteuid(), os.getegid())
        and identity[5] == links
        and identity[6] == size,
        "file-policy",
    )


def _content(fd, raw):
    before = observe.stable(os.fstat(fd))
    require(before[6] == len(raw), "file-size")
    found = bytearray()
    while chunk := os.pread(fd, min(65536, len(raw) + 1 - len(found)), len(found)):
        found.extend(chunk)
        require(len(found) <= len(raw), "file-size")
    require(
        bytes(found) == raw and observe.stable(os.fstat(fd)) == before, "file-content"
    )
    return before


def _anonymous_name(proc, source, parent, directory):
    """Read the held procfd's actual dentry spelling, never infer it from an inode."""
    link = os.readlink(source, dir_fd=proc)
    prefix, suffix = os.fsencode(parent) + b"/", b" (deleted)"
    require(
        type(link) is bytes and link.startswith(prefix) and link.endswith(suffix),
        "anonymous-name",
    )
    name = link[len(prefix) : -len(suffix)]
    require(
        0 < len(name) <= 255
        and name not in (b".", b"..")
        and not any(character in name for character in (b"/", b"\0", b"\r", b"\n")),
        "anonymous-name",
    )
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError as error:
        require(error.errno == errno.ENOENT, "anonymous-name-absence")
    else:
        require(False, "anonymous-name-present")
    return os.fsdecode(name)


def publish_private(path, raw, *, protocol):
    """Preserve the string-returning API using the sole observed syscall path."""
    return publish_observed(path, raw, protocol=protocol).payload_sha256


def publish_observed(path, raw, *, protocol):
    """Publish once and return an immutable receipt only after descriptor closure."""
    require(type(protocol) is str and protocol == PROTOCOL, "storage-profile")
    require(
        sys.platform == "linux"
        and ctypes.sizeof(ctypes.c_void_p) == 8
        and hasattr(os, "O_TMPFILE"),
        "unsupported-platform",
    )
    require(type(raw) is bytes and 0 < len(raw) <= LIMIT, "payload")
    require(isinstance(path, (str, Path)), "path")
    path = Path(path)
    require(observe.absolute(str(path)) and path.name not in {"", ".", ".."}, "path")
    require(not any(ch in path.name for ch in ("\0", "\r", "\n")), "name")
    parent = path.parent
    require(parent.resolve(strict=True) == parent, "parent-path")
    initial = parent.lstat()
    require(
        stat.S_ISDIR(initial.st_mode)
        and stat.S_IMODE(initial.st_mode) == 0o700
        and (initial.st_uid, initial.st_gid) == (os.geteuid(), os.getegid()),
        "parent-policy",
    )
    identity = observe.stable(initial)[:5]
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fstatfs.argtypes = [ctypes.c_int, ctypes.c_void_p]
    libc.fstatfs.restype = ctypes.c_int
    libc.linkat.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    libc.linkat.restype = ctypes.c_int
    fds = []
    primary = None
    try:
        directory = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        fds.append(directory)
        require(observe.stable(os.fstat(directory))[:5] == identity, "parent-changed")
        proc = os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        fds.append(proc)
        # Linux64 statfs starts with native-long f_type; the buffer exceeds its ABI size.
        filesystem = ctypes.create_string_buffer(256)
        result = libc.fstatfs(proc, filesystem)
        if result != 0:
            raise OSError(
                ctypes.get_errno() or errno.EIO, "proc filesystem observation"
            )
        require(
            ctypes.c_long.from_buffer(filesystem).value == PROC_SUPER_MAGIC,
            "proc-filesystem",
        )
        process_directory = os.fstat(proc)
        require(
            stat.S_ISDIR(process_directory.st_mode)
            and (process_directory.st_uid, process_directory.st_gid)
            == (os.geteuid(), os.getegid())
            and not process_directory.st_mode & 0o022,
            "proc-directory",
        )
        temporary = os.open(
            ".", os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=directory
        )
        fds.append(temporary)
        _private(os.fstat(temporary), 0, 0)
        remaining = memoryview(raw)
        while remaining:
            written = os.write(temporary, remaining)
            require(
                type(written) is int and 0 < written <= len(remaining), "short-write"
            )
            remaining = remaining[written:]
        os.fsync(temporary)
        _private(os.fstat(temporary), 0, len(raw))
        before_link = _content(temporary, raw)
        _private_identity(before_link, 0, len(raw))
        source = str(temporary).encode("ascii")
        anonymous = _anonymous_name(proc, source, parent, directory)
        require(
            observe.stable(os.stat(source, dir_fd=proc, follow_symlinks=True))
            == before_link,
            "proc-fd-binding",
        )
        result = libc.linkat(
            proc, source, directory, os.fsencode(path.name), AT_SYMLINK_FOLLOW
        )
        if result != 0:
            raise OSError(
                ctypes.get_errno() or errno.EIO,
                "exclusive metadata publication",
                str(path),
            )
        os.fsync(directory)
        require(
            _anonymous_name(proc, source, parent, directory) == anonymous,
            "anonymous-name-changed",
        )
        require(
            parent.resolve(strict=True) == parent
            and observe.stable(parent.lstat())[:5] == identity
            and observe.stable(os.fstat(directory))[:5] == identity,
            "parent-changed",
        )
        _private(os.fstat(temporary), 1, len(raw))
        final = _content(temporary, raw)
        _private_identity(final, 1, len(raw))
        require(
            final[:2] == before_link[:2]
            and observe.stable(
                os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            )
            == final,
            "final-name-changed",
        )
        return PublicationReceipt(
            path=str(path),
            parent_identity=tuple(identity),
            anonymous_name=anonymous,
            before_identity=tuple(before_link),
            final_identity=tuple(final),
            payload_sha256=hashlib.sha256(raw).hexdigest(),
            payload_bytes=len(raw),
            protocol=protocol,
        )
    except BaseException as error:
        primary = error
        raise
    finally:
        secondary = None
        for fd in reversed(fds):
            try:
                os.close(fd)
            except BaseException as error:
                if secondary is None:
                    secondary = error
        if secondary is not None:
            if primary is None:
                raise secondary
            primary.add_note("secondary atomic publication descriptor-close failure")
