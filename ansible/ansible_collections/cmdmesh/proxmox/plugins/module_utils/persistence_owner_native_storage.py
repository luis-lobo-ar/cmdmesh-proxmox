"""Private v4 namespace bootstrap, not native or managed-storage admission.

The future admitted coordinator owns the pair lease and qualifies its installed
source/filesystem. It holds this owner-neutral domain mutex only around short
initialization operations, never current/SQL/native workers. Partial/foreign
state is preserved. No legacy or retirement namespace is migrated or reset.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import errno
import fcntl
import os
from pathlib import PurePosixPath
import stat
import uuid

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_atomic as atomic,
    persistence_owner_attempt as attempt,
    persistence_owner_filesystem as filesystem,
    persistence_owner_metadata_executor as metadata,
    persistence_owner_request_journal as journal,
)

LOCK_NAME = "owner-native-v4-bootstrap-v1.lock.json"
PROTOCOL = "named-exclusive-fsync-replace-fsync-v1"
PROFILE = "owner-native-v4-storage-v1"
PROBE_PREFIX = "owner-native-v4-probe-"
state = journal.state


def require(value, code):
    state.require(value, "persistence-owner-native-storage-" + code)


def _configuration():
    root = str(journal.RUNTIME_ROOT)
    require(
        journal.VERSION == 4
        and journal.ACTION_PROFILE == "owner-os-action-v3"
        and journal.STAGES == ("dispatch", "ack-observed", "ack", "terminal")
        and journal.RUNTIME
        == {
            "document_type": "cmdmesh.proxmox.owner-journal.runtime",
            "schema_version": 4,
            "action_profile": "owner-os-action-v3",
        }
        and PurePosixPath(root).is_absolute()
        and str(PurePosixPath(root)) == root
        and ".." not in PurePosixPath(root).parts
        and journal.RUNTIME_ROOT
        not in {attempt.r.RUNTIME_ROOT, attempt.r.legacy.RUNTIME_ROOT}
        and journal.RUNTIME_ROOT.parent
        == attempt.r.RUNTIME_ROOT.parent
        == attempt.r.legacy.RUNTIME_ROOT.parent
        and journal.ROOT_UID == attempt.r.legacy.ROOT_UID,
        "configuration",
    )
    return state.canonical(
        dict(
            profile=PROFILE,
            protocol=PROTOCOL,
            runtime=journal.RUNTIME,
            root=root,
            stages=journal.STAGES,
            bootstrap_name=LOCK_NAME,
            bootstrap_protocol=atomic.PROTOCOL,
            owner=journal.ROOT_UID,
            walk_root=str(attempt._WALK_ROOT),
            probe_prefix=PROBE_PREFIX,
        )
    )


@contextmanager
def _locked_bootstrap(*, initialize=False):
    """One fixed shared mutex; creating it initializes no journal or authority."""
    require(type(initialize) is bool, "mode")
    expected = _configuration()
    require(os.geteuid() == os.getegid() == journal.ROOT_UID, "owner")
    parent = journal.RUNTIME_ROOT.parent
    journal.backup.private_directory(parent)
    path = parent / LOCK_NAME
    raw = state.canonical(
        dict(
            document_type="cmdmesh.proxmox.owner-native-bootstrap-lock",
            schema_version=1,
            configuration_sha256=state.sha256(expected),
        )
    )
    if initialize:
        try:
            atomic.publish_private(path, raw, protocol=atomic.PROTOCOL)
        except FileExistsError as error:
            require(
                error.errno == errno.EEXIST and error.filename == str(path),
                "initialize",
            )
    reader = attempt._Reader()
    process = os.getpid()
    primary = None
    try:
        reader.directory_identity(parent, private=True)
        item = reader.file(path)
        require(type(item) is dict and reader.raws[str(path)][0] == raw, "lock-record")
        descriptor = reader.nodes[str(path)]["fd"]
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise state.PersistenceError(
                "persistence-owner-native-storage-bootstrap-busy"
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
            reader.release()
        except BaseException:
            if primary is None:
                raise
            primary.add_note("secondary native bootstrap release failure")
    require(
        _configuration() == expected and os.getpid() == process, "configuration-changed"
    )


@dataclass(frozen=True, slots=True)
class _Initialization:
    would_change: bool
    seal: journal.Seal
    absent: tuple
    configuration_raw: bytes
    _seal_raw: bytes


def _seal_raw(seal):
    return state.canonical([seal.files, seal.directories, seal.members])


def _inspect_initialization(binding):
    """Read only absent or unused genesis state; never adopt an operation head."""
    require(type(binding) is journal.Binding, "binding")
    configuration = _configuration()
    journal._profile(binding)
    seal = journal.Seal()
    journal._directory(journal.RUNTIME_ROOT.parent, seal)
    absent = []
    if not os.path.lexists(journal.RUNTIME_ROOT):
        absent.append(journal.RUNTIME_ROOT)
    else:
        journal._global(seal)
        target = journal.RUNTIME_ROOT / binding.pair_key
        if not os.path.lexists(target):
            absent.append(target)
        else:
            view = journal._inspect(binding, journal._digest(journal._genesis(binding)))
            seal = view.seal
    result = _Initialization(
        bool(absent), seal, tuple(absent), configuration, _seal_raw(seal)
    )
    _close_initialization(result)
    return result


def _close_initialization(view):
    require(
        type(view) is _Initialization and type(view.configuration_raw) is bytes,
        "initialization",
    )
    require(
        _configuration() == view.configuration_raw
        and _seal_raw(view.seal) == view._seal_raw,
        "initialization-memory",
    )
    journal._close(view.seal)
    require(
        not any(os.path.lexists(path) for path in view.absent), "initialization-changed"
    )


def _initialize_journal(binding):
    """Internal metadata helper; caller must own pair EX and admitted mutation.

    A complete unused genesis is idempotent. Missing, partial, foreign or used
    pair contents are not repaired. A return remains an unaccepted candidate.
    """
    before = _inspect_initialization(binding)
    _close_initialization(before)
    with _locked_bootstrap(initialize=True):
        before = _inspect_initialization(binding)
        _close_initialization(before)
        result = journal._initialize(binding)
        after = _inspect_initialization(binding)
        require(not after.would_change, "initialization-incomplete")
        _close_initialization(after)
    return result


@dataclass(frozen=True, slots=True)
class ProbeCandidate:
    raw: bytes
    sha256: str


def probe_protocol(*, allow_mutation=False, check_mode=False):
    """Exercise the named-write/replace primitives in one owned sibling.

    This diagnostic writes no v4 journal and supplies no operation admission.
    The source-authenticated controller must accept the closed result before
    constructing a separate filesystem qualification. Failed probes retain
    their scratch. Successful cleanup requires exact owned names/identities.
    """
    require(
        type(allow_mutation) is bool
        and allow_mutation
        and type(check_mode) is bool
        and not check_mode,
        "probe-mode",
    )
    configuration = _configuration()
    require(os.geteuid() == os.getegid() == journal.ROOT_UID, "owner")
    parent = journal.RUNTIME_ROOT.parent
    journal.backup.private_directory(parent)
    process = os.getpid()
    epoch, release = filesystem._epoch(), os.uname().release
    with metadata._Stack() as stack:
        reader = attempt._Reader()
        stack.callback(reader.release)
        parent_identity = reader.directory_identity(parent, private=True)[:5]
        parent_fd = reader.nodes[str(parent)]["fd"]
        mount_id = filesystem.fd_mount_id(parent_fd)
        table = filesystem.parse_mountinfo(
            filesystem._bounded("/proc/self/mountinfo", filesystem.MOUNTINFO_LIMIT)
        )
        mount = {**table[mount_id], **filesystem.statfs(parent_fd)}
        name = PROBE_PREFIX + uuid.uuid4().hex
        path = parent / name
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        stack.callback(os.close, fd)
        scratch = list(journal.observe.stable(os.fstat(fd)))[:5]
        require(
            scratch[2:] == [stat.S_IFDIR | 0o700, journal.ROOT_UID, journal.ROOT_UID]
            and scratch[0] == parent_identity[0]
            and filesystem.fd_mount_id(fd) == mount_id,
            "probe-directory",
        )
        require(
            list(
                journal.observe.stable(
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                )
            )[:5]
            == scratch,
            "probe-directory-binding",
        )
        journal.backup.sync_directory(parent)
        require(
            list(journal.observe.stable(os.fstat(fd)))[:5] == scratch
            and list(
                journal.observe.stable(
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                )
            )[:5]
            == scratch,
            "probe-directory-binding",
        )
        first = dict(
            document_type="cmdmesh.proxmox.owner-native-storage-probe.payload",
            schema_version=1,
            generation=1,
        )
        second = {**first, "generation": 2}
        head, staging = path / "HEAD.json", path / "HEAD.next"
        first_sha = journal._write(head, first)
        initial = list(journal.observe.stable(head.lstat()))
        try:
            journal._write(head, second)
        except FileExistsError as error:
            require(
                error.errno == errno.EEXIST and error.filename == str(head),
                "probe-exclusive",
            )
            exclusive_errno = error.errno
        else:
            require(False, "probe-overwrite")
        old_raw, old_info = journal.observe.read_regular(head, journal.LIMIT)
        require(
            old_raw == state.canonical(first)
            and list(journal.observe.stable(old_info)) == initial,
            "probe-original",
        )
        second_sha = journal._write(staging, second)
        os.replace(staging, head)
        journal.backup.sync_directory(path)
        replaced_raw, replaced_info = journal.observe.read_regular(head, journal.LIMIT)
        replaced = list(journal.observe.stable(replaced_info))
        require(
            replaced_raw == state.canonical(second)
            and initial[1] != replaced[1]
            and replaced[0] == scratch[0]
            and replaced[2:6]
            == [stat.S_IFREG | 0o600, journal.ROOT_UID, journal.ROOT_UID, 1],
            "probe-replacement",
        )
        with os.scandir(fd) as entries:
            members = [item.name for item in entries]
        require(members == ["HEAD.json"], "probe-membership")
        require(
            list(journal.observe.stable(head.lstat())) == replaced, "probe-final-file"
        )
        require(
            list(journal.observe.stable(path.lstat()))[:5] == scratch,
            "probe-final-directory",
        )
        os.unlink("HEAD.json", dir_fd=fd)
        os.fsync(fd)
        os.rmdir(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        require(not os.path.lexists(path), "probe-cleanup")
        current_fd = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        stack.callback(os.close, current_fd)
        require(
            filesystem.fd_mount_id(current_fd) == mount_id
            and filesystem.statfs(current_fd)
            == {key: mount[key] for key in ("statfs_type", "statfs_fsid")},
            "probe-mount-changed",
        )
        current_table = filesystem.parse_mountinfo(
            filesystem._bounded("/proc/self/mountinfo", filesystem.MOUNTINFO_LIMIT)
        )
        require(current_table[mount_id] == table[mount_id], "probe-mount-changed")
        reader.check_memberships()
        reader.close_named()
        require(
            _configuration() == configuration and os.getpid() == process,
            "probe-configuration-changed",
        )
        require(
            filesystem._epoch() == epoch and os.uname().release == release,
            "probe-epoch-changed",
        )
        reader.check_events()
        value = dict(
            document_type="cmdmesh.proxmox.owner-native-storage-probe",
            schema_version=1,
            protocol=PROTOCOL,
            configuration_sha256=state.sha256(configuration),
            host_epoch=epoch,
            kernel_release=release,
            parent=dict(path=str(parent), identity=parent_identity),
            mount=mount,
            scratch_identity=scratch,
            initial_file=initial,
            replaced_file=replaced,
            initial_sha256=first_sha,
            replacement_sha256=second_sha,
            exclusive_errno=exclusive_errno,
            scratch_removed=True,
            filesystem_qualified=False,
            native_action_dispatched=False,
        )
        raw = state.canonical(value)
        require(0 < len(raw) <= 65536, "probe-output")
        result = ProbeCandidate(raw, state.sha256(raw))
    require(
        _configuration() == configuration and os.getpid() == process,
        "probe-configuration-changed",
    )
    require(
        filesystem._epoch() == epoch and os.uname().release == release,
        "probe-epoch-changed",
    )
    return result
