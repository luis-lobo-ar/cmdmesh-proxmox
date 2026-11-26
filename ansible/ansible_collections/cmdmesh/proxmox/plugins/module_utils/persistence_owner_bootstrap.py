"""Short, owner-neutral runtime bootstrap exclusion; no operation admission."""

from contextlib import contextmanager
import errno
import fcntl
import os

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_atomic as atomic,
    persistence_owner_attempt as attempt,
)

r, profile = attempt.r, attempt.profile
LOCK_NAME = "owner-handoff-bootstrap-v2.lock.json"


def require(value, code):
    r.require(value, "bootstrap-" + code)


def _configuration():
    return (
        r.state.canonical(profile.RUNTIME),
        profile.RUNTIME_ROOT,
        profile.PROTOCOL,
        r.RUNTIME_ROOT,
        r.legacy.RUNTIME_ROOT,
        r.legacy.ROOT_UID,
        LOCK_NAME,
        attempt._WALK_ROOT,
    )


@contextmanager
def locked_runtime_bootstrap(*, initialize=False):
    """Hold one nonblocking FD mutex only around runtime mkdir/profile operations.

    The caller must release it before SQL, current/native workers or other slow
    operations. No pair identifier selects this shared mutex. Initialization is
    an explicit atomic write; an existing canonical marker is never replaced.
    """
    require(type(initialize) is bool, "mode")
    expected = _configuration()
    require(
        profile.RUNTIME_ROOT == r.RUNTIME_ROOT
        and profile.RUNTIME_ROOT != r.legacy.RUNTIME_ROOT
        and profile.RUNTIME_ROOT.parent == r.legacy.RUNTIME_ROOT.parent
        and profile.PROTOCOL == atomic.PROTOCOL,
        "profile-path",
    )
    require(os.geteuid() == os.getegid() == r.legacy.ROOT_UID, "owner")
    path = profile.RUNTIME_ROOT.parent / LOCK_NAME
    marker = r._document(
        "bootstrap-lock",
        runtime_path=str(profile.RUNTIME_ROOT),
        runtime_profile_sha256=r.state.sha256(expected[0]),
        publication_protocol=profile.PROTOCOL,
    )
    raw = r.state.canonical(marker)
    process = os.getpid()
    if initialize:
        try:
            atomic.publish_private(path, raw, protocol=profile.PROTOCOL)
        except FileExistsError as error:
            require(
                error.errno == errno.EEXIST and error.filename == str(path),
                "initialize",
            )
    reader = attempt._Reader()
    primary = None
    try:
        reader.directory_identity(path.parent, private=True)
        item = reader.file(path)
        require(type(item) is dict and reader.raws[str(path)][0] == raw, "lock-record")
        descriptor = reader.nodes[str(path)]["fd"]
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise r.state.PersistenceError(
                "persistence-owner-retirement-bootstrap-busy"
            ) from None
        reader.check_memberships()
        reader.close_named()
        reader.check_events()
        require(
            _configuration() == expected and os.getpid() == process,
            "configuration-changed",
        )
        yield
        reader.check_memberships()
        reader.close_named()
        require(reader.raws[str(path)][0] == raw, "raw-memory")
        require(
            _configuration() == expected and os.getpid() == process,
            "configuration-changed",
        )
        reader.check_events()
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            # Closing this exact held FD releases its flock; never open a new
            # descriptor or unlock early while its observations still matter.
            reader.release()
        except BaseException:
            if primary is None:
                raise
            primary.add_note("secondary bootstrap observer release failure")
    require(
        _configuration() == expected and os.getpid() == process, "configuration-changed"
    )
