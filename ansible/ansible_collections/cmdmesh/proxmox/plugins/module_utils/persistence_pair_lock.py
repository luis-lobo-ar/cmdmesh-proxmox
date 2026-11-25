"""Share the existing retained-pair mutex without creating an operation claim."""

from contextlib import contextmanager
import fcntl
import os
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_backup as backup,
    persistence_observe as observe,
    persistence_state as state,
)


def require(value, code):
    state.require(value, "persistence-pair-" + code)


def existing_runtime():
    root = backup.RUNTIME_ROOT
    try:
        for path in (root.parent, root, root / "locks"):
            backup.private_directory(path)
        _, raw = backup.read_private(root / "profile.json")
        require(raw == state.canonical(backup.PROFILE), "runtime-profile")
    except OSError:
        raise state.PersistenceError("persistence-pair-runtime-unavailable") from None
    return root


@contextmanager
def locked_pair(datasets, *, initialize=False):
    """Acquire the backup-compatible EX mutex, then close the same file identity.

    This does not admit an operation, inspect prior claims, or establish source
    quiescence. Operation controllers must enforce those contracts separately.
    Initialization is an explicit write and belongs behind their mutation gate.
    """
    require(type(initialize) is bool, "mode")
    key = state.pair_key(datasets)
    if initialize:
        backup.runtime()
    root = existing_runtime()
    path = root / "locks" / (key + ".json")
    marker = {
        "document_type": "cmdmesh.proxmox.persistence.pair-lock",
        "schema_version": 1,
        "pair_key": key,
    }
    expected = state.canonical(marker)
    if initialize:
        try:
            backup.write_private(path, marker)
        except FileExistsError:
            pass
    try:
        _, raw = backup.read_private(path)
        require(raw == expected, "marker")
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "file")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise state.PersistenceError("persistence-pair-lock-unavailable") from None
    try:
        before = observe.stable(info)
        require(
            observe.stable(os.fstat(fd)) == before
            and observe.stable(path.lstat()) == before,
            "file-changed",
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise state.PersistenceError("persistence-pair-busy") from None
        # Close the admission read after acquiring EX, never on an earlier file.
        _, raw = backup.read_private(path)
        require(
            raw == expected and observe.stable(path.lstat()) == before, "file-changed"
        )
        yield {"pair_key": key, "path": str(path)}
        _, raw = backup.read_private(path)
        require(
            raw == expected
            and observe.stable(path.lstat()) == before
            and observe.stable(os.fstat(fd)) == before,
            "file-changed",
        )
    finally:
        os.close(fd)
