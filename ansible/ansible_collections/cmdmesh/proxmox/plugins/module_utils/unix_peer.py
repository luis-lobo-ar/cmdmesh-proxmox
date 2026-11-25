"""One bounded AF_UNIX exchange with an already admitted Linux process.

This module authenticates a process, not an application or a guest. Callers must
admit the host, guest, program, service, retained binds and socket directory first.
It does not acquire application locks, read a database or retry a request.
"""

from contextlib import ExitStack
from dataclasses import dataclass
import os
import re
import select
import socket
import stat
import struct
import time


class PeerError(ValueError):
    """A static error that never includes request or response bytes."""


def require(value, code):
    if not value:
        raise PeerError("unix-peer-" + code)


def integer(value, low=1):
    return type(value) is int and low <= value < 2**64


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    birth: int
    pid_namespace: int
    mount_namespace: int
    uid: int
    gid: int
    nspid: tuple[int, ...]
    root: tuple[int, int]
    executable: tuple[int, int]
    argv: tuple[str, ...]
    cgroup: str

    def __post_init__(self):
        require(
            all(
                integer(getattr(self, name))
                for name in ("pid", "birth", "pid_namespace", "mount_namespace")
            ),
            "process-identity",
        )
        require(
            integer(self.uid, 0)
            and integer(self.gid, 0)
            and self.uid < 2**32
            and self.gid < 2**32
            and self.pid < 2**31,
            "process-identity",
        )
        require(
            type(self.nspid) is tuple
            and 0 < len(self.nspid) <= 32
            and all(integer(value) for value in self.nspid)
            and self.nspid[0] == self.pid,
            "process-identity",
        )
        for pair in (self.root, self.executable):
            require(
                type(pair) is tuple
                and len(pair) == 2
                and integer(pair[0], 0)
                and integer(pair[1]),
                "process-identity",
            )
        require(
            type(self.argv) is tuple
            and 0 < len(self.argv) <= 128
            and all(
                type(part) is str and part and "\0" not in part for part in self.argv
            ),
            "process-identity",
        )
        require(
            sum(len(part.encode()) + 1 for part in self.argv) <= 32768,
            "process-identity",
        )
        require(
            type(self.cgroup) is str and 0 < len(self.cgroup.encode()) <= 65536,
            "process-identity",
        )


def _read(descriptor, name, limit):
    with os.fdopen(
        os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor),
        "rb",
    ) as source:
        raw = source.read(limit + 1)
    require(0 < len(raw) <= limit, "process-unavailable")
    return raw


def _inode(descriptor, name):
    info = os.stat(name, dir_fd=descriptor)
    return info.st_dev, info.st_ino


def _process(descriptor, pid):
    raw = _read(descriptor, "stat", 65536).decode("ascii")
    parts = raw.rsplit(") ", 1)
    require(len(parts) == 2 and parts[0].startswith(str(pid) + " ("), "process-stat")
    fields = parts[1].split()
    require(
        len(fields) >= 20 and fields[0] not in ("Z", "X", "x") and fields[19].isdigit(),
        "process-stat",
    )
    status = {}
    for row in _read(descriptor, "status", 65536).decode("ascii").splitlines():
        key, separator, value = row.partition(":")
        require(separator and key not in status, "process-status")
        status[key] = value.split()
    for key in ("Uid", "Gid", "NSpid"):
        require(
            key in status
            and status[key]
            and all(part.isdigit() for part in status[key]),
            "process-status",
        )
    require(
        len(status["Uid"]) == len(status["Gid"]) == 4
        and len(set(status["Uid"])) == len(set(status["Gid"])) == 1,
        "process-credentials",
    )
    argv = _read(descriptor, "cmdline", 32768)
    require(argv.endswith(b"\0"), "process-argv")
    return ProcessIdentity(
        pid=pid,
        birth=int(fields[19]),
        pid_namespace=_inode(descriptor, "ns/pid")[1],
        mount_namespace=_inode(descriptor, "ns/mnt")[1],
        uid=int(status["Uid"][0]),
        gid=int(status["Gid"][0]),
        nspid=tuple(int(value) for value in status["NSpid"]),
        root=_inode(descriptor, "root"),
        executable=_inode(descriptor, "exe"),
        argv=tuple(part.decode("utf-8") for part in argv[:-1].split(b"\0")),
        cgroup=_read(descriptor, "cgroup", 65536).decode("ascii"),
    )


def _alive(descriptor):
    require(not select.select([descriptor], [], [], 0)[0], "process-exited")


def process_identity(pid):
    """Observe a process; this alone does not admit its application or guest."""
    require(integer(pid) and pid < 2**31, "process-identity")
    try:
        with ExitStack() as opened:
            live = os.pidfd_open(pid, 0)
            opened.callback(os.close, live)
            process = os.open(
                f"/proc/{pid}",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            opened.callback(os.close, process)
            before = _process(process, pid)
            require(_process(process, pid) == before, "process-changed")
            _alive(live)
            return before
    except (OSError, UnicodeError):
        raise PeerError("unix-peer-process-unavailable") from None


def _socket_seal(parent, name, binding):
    directory = os.fstat(parent)
    require(
        stat.S_ISDIR(directory.st_mode)
        and stat.S_IMODE(directory.st_mode) == 0o700
        and directory.st_uid == binding.uid
        and directory.st_gid == binding.gid,
        "socket-directory",
    )
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    require(
        stat.S_ISSOCK(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_uid == binding.uid
        and info.st_gid == binding.gid
        and info.st_nlink == 1,
        "socket-file",
    )
    return tuple(
        (part.st_dev, part.st_ino, part.st_mode, part.st_uid, part.st_gid)
        for part in (directory, info)
    )


def exchange(parent, name, binding, payload, *, timeout=5, response_limit=1048576):
    """Send one frame only after peer admission, then require a bounded response.

    ``parent`` is a caller-owned, admitted directory FD. ``payload`` is called
    after SO_PEERCRED and current process evidence match ``binding``. It returns
    one newline-terminated byte frame. There is no connect, send or read retry.
    A failed response after sending leaves the application outcome unknown.
    """
    require(
        type(binding) is ProcessIdentity and type(parent) is int and parent >= 0,
        "binding-required",
    )
    require(
        type(name) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name),
        "socket-name",
    )
    require(type(timeout) in (int, float) and 0 < timeout <= 30, "timeout")
    require(
        type(response_limit) is int and 1 <= response_limit <= 1048576, "response-limit"
    )
    require(callable(payload), "payload-supplier")
    deadline = time.monotonic() + timeout

    def remaining():
        value = deadline - time.monotonic()
        require(value > 0, "timeout")
        return value

    try:
        with ExitStack() as opened:
            # Own a duplicate so a caller cannot close this FD during exchange.
            directory = os.dup(parent)
            opened.callback(os.close, directory)
            seal = _socket_seal(directory, name, binding)
            live = os.pidfd_open(binding.pid, 0)
            opened.callback(os.close, live)
            process = os.open(
                f"/proc/{binding.pid}",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            opened.callback(os.close, process)

            def close_proof():
                _alive(live)
                require(_process(process, binding.pid) == binding, "process-changed")
                require(
                    _socket_seal(directory, name, binding) == seal, "socket-changed"
                )
                _alive(live)

            close_proof()
            channel = opened.enter_context(
                socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            )
            channel.settimeout(remaining())
            channel.connect(f"/proc/self/fd/{directory}/{name}")
            peer = struct.unpack(
                "iII", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            require(
                peer == (binding.pid, binding.uid, binding.gid), "credentials-mismatch"
            )
            close_proof()
            try:
                raw = payload()
            except Exception:
                raise PeerError("unix-peer-payload-unavailable") from None
            require(
                type(raw) is bytes
                and 1 < len(raw) <= 70000
                and raw.endswith(b"\n")
                and b"\n" not in raw[:-1],
                "request-frame",
            )
            close_proof()
            channel.settimeout(remaining())
            channel.sendall(raw)
            del raw
            result = bytearray()
            while True:
                channel.settimeout(remaining())
                part = channel.recv(min(65536, response_limit + 1 - len(result)))
                if not part:
                    break
                result.extend(part)
                require(len(result) <= response_limit, "response-oversized")
            require(
                result.endswith(b"\n") and b"\n" not in result[:-1], "response-frame"
            )
            close_proof()
            remaining()
            return bytes(result)
    except (OSError, UnicodeError, struct.error):
        raise PeerError("unix-peer-exchange-unavailable") from None
