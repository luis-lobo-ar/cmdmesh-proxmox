"""Read Proxmox's native guest lock without imposing a blank-guest policy."""

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_observe as observe,
    persistence_state as state,
)

LOCK_ROOT = Path("/run/lock/lxc")
ROOT_UID = 0


class ConfigLockError(state.PersistenceError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__("persistence-native-config-" + reason)


def require(value, reason):
    if not value:
        raise ConfigLockError(reason)


def _initialize_file(path):
    require(os.geteuid() == ROOT_UID, "owner")
    try:
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
    except FileExistsError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


@contextmanager
def _locked(vmid, initialize, mode):
    require(type(vmid) is int and 100 <= vmid <= 999999, "target")
    require(type(initialize) is bool, "mode")
    require(LOCK_ROOT.resolve(strict=True) == LOCK_ROOT, "directory")
    info = LOCK_ROOT.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == ROOT_UID
        and not info.st_mode & 0o022,
        "directory",
    )
    path = LOCK_ROOT / f"pve-config-{vmid}.lock"
    if initialize:
        _initialize_file(path)
    require(path.resolve(strict=True) == path, "path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == ROOT_UID
            and before.st_nlink == 1
            and not before.st_mode & 0o022
            and observe.stable(before) == observe.stable(path.lstat()),
            "file",
        )
        try:
            fcntl.flock(fd, mode | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ConfigLockError("busy") from None
        yield
        require(
            observe.stable(before)
            == observe.stable(os.fstat(fd))
            == observe.stable(path.lstat()),
            "changed",
        )
    finally:
        os.close(fd)


def read_guest(vmid, *, initialize=False):
    """Hold SH for reads or guard publication; initialization is an explicit write."""
    return _locked(vmid, initialize, fcntl.LOCK_SH)


def require_write_available(vmid):
    """Fail early on a held lease, then release EX before the native mutation."""
    with _locked(vmid, False, fcntl.LOCK_EX):
        pass
