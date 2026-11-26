"""Bounded live Linux metadata-filesystem facts, without qualification or writes.

Retained descriptors bind measured ancestors to named paths. This is not a
mount-change event monitor or a publication witness. The executor still needs
the selected qualification, real leases and per-publication event/receipt checks.
Missing suffixes describe the initial observation, never continuing absence.
"""

from contextlib import contextmanager
import ctypes
from dataclasses import dataclass, field
import errno
import os
from pathlib import Path
import re
import stat
import sys

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_attempt as attempt,
    persistence_owner_bootstrap as bootstrap,
    persistence_owner_publication_witness as publication,
    persistence_owner_resources as resources,
    persistence_owner_semantics as semantics,
)

r, profile = semantics.r, semantics.storage
MOUNTINFO_LIMIT = 2097152
PROC_MAGIC = 0x9FA0


def require(value, code):
    r.require(value, "filesystem-subject-" + code)


def _bounded(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        require(0 < len(data) <= limit, "read-limit")
        return bytes(data)
    finally:
        os.close(fd)


def _integer(value, maximum=(1 << 64) - 1, minimum=1):
    require(re.fullmatch(rb"0|[1-9][0-9]{0,19}", value) is not None, "integer")
    result = int(value)
    require(minimum <= result <= maximum, "integer")
    return result


def _word(value, *, path=False):
    require(0 < len(value) <= 4096, "word")
    escapes = {b"040": b" ", b"011": b"\t", b"012": b"\n", b"134": b"\\"}
    require(re.search(rb"\\(?!040|011|012|134)", value) is None, "escape")
    decoded = re.sub(rb"\\(040|011|012|134)", lambda match: escapes[match[1]], value)
    result = os.fsdecode(decoded)
    require(not any(c in result for c in ("\0", "\n", "\r", "\t")), "word")
    if path:
        require(
            result.startswith("/")
            and str(Path(result)) == result
            and ".." not in Path(result).parts,
            "mount-path",
        )
    return result


def _options(value):
    parts = value.split(b",")
    require(0 < len(parts) <= 128 and len(set(parts)) == len(parts), "options")
    result = [_word(part) for part in parts]
    require(all(len(item) <= 4096 for item in result), "options")
    return sorted(result)


def parse_mountinfo(raw):
    """Parse bounded kernel mountinfo bytes, retaining distinct mount IDs."""
    require(
        type(raw) is bytes
        and 0 < len(raw) <= MOUNTINFO_LIMIT
        and raw.endswith(b"\n")
        and b"\0" not in raw,
        "mountinfo",
    )
    lines = raw.splitlines()
    require(0 < len(lines) <= 16384, "mount-count")
    result = {}
    for line in lines:
        require(len(line) <= 32768 and line.count(b" - ") == 1, "mount-line")
        left, right = line.split(b" - ")
        fields, tail = left.split(b" "), right.split(b" ")
        require(
            6 <= len(fields) <= 38 and len(tail) == 3 and all(fields) and all(tail),
            "mount-line",
        )
        mount_id, parent_id = (_integer(value) for value in fields[:2])
        require(mount_id not in result, "duplicate-mount")
        device = fields[2].split(b":")
        require(len(device) == 2, "device")
        for value in fields[6:]:
            require(
                len(value) <= 256 and re.fullmatch(rb"[a-z_]+(?::[0-9]+)?", value),
                "optional-field",
            )
        filesystem = _word(tail[0])
        require(len(filesystem) <= 128, "filesystem")
        root = _word(fields[3])
        if not (
            filesystem == "nsfs"
            and re.fullmatch(
                r"(?:mnt|net|pid|user|uts|ipc|cgroup|time):\[[1-9][0-9]*\]", root
            )
        ):
            root = _word(fields[3], path=True)
        result[mount_id] = dict(
            mount_id=mount_id,
            parent_id=parent_id,
            device=[_integer(value, (1 << 32) - 1, 0) for value in device],
            root=root,
            target=_word(fields[4], path=True),
            options=_options(fields[5]),
            filesystem=filesystem,
            source=_word(tail[1]),
            super_options=_options(tail[2]),
        )
    return result


def fd_mount_id(fd):
    require(type(fd) is int and fd >= 0, "descriptor")
    raw = _bounded(f"/proc/self/fdinfo/{fd}", 4096)
    matches = re.findall(rb"^mnt_id:\s*([0-9]+)$", raw, re.MULTILINE)
    require(len(matches) == 1, "fdinfo")
    return _integer(matches[0])


class _StatFS(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_long),
        ("block_size", ctypes.c_long),
        ("counts", ctypes.c_ulong * 5),
        ("fsid", ctypes.c_int * 2),
        ("name_length", ctypes.c_long),
        ("fragment_size", ctypes.c_long),
        ("flags", ctypes.c_long),
        ("spare", ctypes.c_long * 4),
    ]


def statfs(fd):
    require(
        type(fd) is int
        and fd >= 0
        and sys.platform == "linux"
        and ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_long) == 8
        and ctypes.sizeof(_StatFS) == 120,
        "linux-abi",
    )
    library = ctypes.CDLL(None, use_errno=True)
    library.fstatfs.argtypes = [ctypes.c_int, ctypes.POINTER(_StatFS)]
    library.fstatfs.restype = ctypes.c_int
    result = _StatFS()
    if library.fstatfs(fd, ctypes.byref(result)) != 0:
        raise OSError(ctypes.get_errno() or errno.EIO, "filesystem observation")
    return dict(
        statfs_type=result.type & ((1 << 64) - 1), statfs_fsid=list(result.fsid)
    )


def destination_paths(selection):
    require(type(selection) is semantics.Selection, "selection")
    root = profile.RUNTIME_ROOT
    pair = root / selection._private_binding.pair_key
    require(root.parent == r.legacy.RUNTIME_ROOT.parent, "common-parent")
    return {
        "bootstrap-lock": root.parent / bootstrap.LOCK_NAME,
        "runtime-directory": root,
        "runtime-profile": root / "runtime.json",
        "pair-directory": pair,
        "intent": pair / "intent.json",
        "legacy-marker": r.legacy.RUNTIME_ROOT
        / selection._private_binding.pair_key
        / profile.MARKER,
        "completion": pair / "complete.json",
    }


def _epoch():
    boot = _bounded("/proc/sys/kernel/random/boot_id", 64)
    require(
        re.fullmatch(rb"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\n", boot), "boot"
    )
    namespace = os.readlink("/proc/self/ns/mnt")
    require(re.fullmatch(r"mnt:\[[1-9][0-9]*\]", namespace), "namespace")
    return dict(boot_id=boot[:-1].decode("ascii"), mount_namespace=namespace)


class _Subject:
    def __init__(self, selection):
        self._selection = self._expected_selection = selection
        self._process = os.getpid()
        self._paths = destination_paths(selection)
        self._path_raw = r.state.canonical(
            {key: str(value) for key, value in self._paths.items()}
        )
        self._reader = self._expected_reader = None
        self._proc = None
        self._owned = None
        self._reader_view = self._facts_raw = None
        self._closed = self._poisoned = self._enumerated = False
        self._raw = self._expected_raw = None
        self._mounts = {}
        try:
            self._reader = self._expected_reader = resources._Seal(
                selection._private_binding.pair_key
            )
            self._owned = self._reader, None
            self._reader._directory(profile.RUNTIME_ROOT.parent, private=True)
            self._proc = os.open(
                "/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            )
            self._owned = self._reader, self._proc
            self._proc_identity = tuple(attempt._identity(os.fstat(self._proc))[:5])
            require(
                stat.S_ISDIR(self._proc_identity[2])
                and not self._proc_identity[2] & 0o022
                and self._proc_identity[3:] == (os.geteuid(), os.getegid()),
                "proc-directory",
            )
            table = parse_mountinfo(_bounded("/proc/self/mountinfo", MOUNTINFO_LIMIT))
            roles = {}
            for role, path in self._paths.items():
                ancestor, missing, fd = self._nearest(path.parent)
                require(role != "legacy-marker" or not missing, "missing-legacy-parent")
                mount = self._mount(fd, table)
                require(
                    "rw" in mount["options"] and "ro" not in mount["options"],
                    "readonly-mount",
                )
                roles[role] = dict(
                    destination=str(path),
                    parent=str(path.parent),
                    ancestor_path=str(ancestor),
                    ancestor_identity=attempt._identity(os.fstat(fd))[:5],
                    missing_suffix=missing,
                    mount_index=mount["mount_id"],
                )
            proc_mount = self._mount(self._proc, table)
            require(proc_mount["statfs_type"] == PROC_MAGIC, "proc-filesystem")
            ids = sorted(self._mounts)
            require(len(ids) <= 8, "mount-count")
            for value in roles.values():
                value["mount_index"] = ids.index(value["mount_index"])
            release = os.uname().release
            require(0 < len(release) <= 256 and release.isascii(), "kernel")
            self._subject = dict(
                binding=r.asdict(selection._private_binding),
                host_epoch=_epoch(),
                kernel_release=release,
                abi="linux64-procfd-v1",
            )
            self._raw = self._expected_raw = r.state.canonical(
                dict(
                    document_type="cmdmesh.proxmox.owner-retirement.filesystem-subject",
                    schema_version=1,
                    observation_scope="initial-nearest-ancestors-with-retained-identities",
                    subject=self._subject,
                    mounts=[self._mounts[key][0] for key in ids],
                    roles=roles,
                    procfs=dict(
                        mount_index=ids.index(proc_mount["mount_id"]),
                        type_magic=PROC_MAGIC,
                    ),
                )
            )
            self._sha256 = r.state.sha256(self._raw)
            self._reader.freeze_fds()
            self._reader_view = resources._seal_view(self._reader)
            self._facts_raw = self._facts_memory()
            self.check_memberships()
            self.close_named()
            self.check_events()
            self._enumerated = False
        except BaseException as error:
            try:
                self.release()
            except BaseException:
                error.add_note("secondary filesystem subject release failure")
            raise

    @property
    def raw(self):
        return self._raw

    @property
    def sha256(self):
        return self._sha256

    @property
    def closed(self):
        return self._closed

    def _nearest(self, parent):
        current, missing = parent, []
        while True:
            try:
                fd = self._reader._directory(current, private=True)
            except FileNotFoundError as error:
                require(
                    error.errno == errno.ENOENT
                    and current != profile.RUNTIME_ROOT.parent
                    and len(missing) < 2,
                    "ancestor",
                )
                missing.insert(0, current.name)
                current = current.parent
            else:
                return current, missing, fd

    def _mount(self, fd, table):
        mount_id = fd_mount_id(fd)
        require(mount_id in table, "mount-id")
        facts = {**table[mount_id], **statfs(fd)}
        info = os.fstat(fd)
        require(
            [os.major(info.st_dev), os.minor(info.st_dev)] == facts["device"],
            "mount-device",
        )
        if mount_id in self._mounts:
            require(self._mounts[mount_id][0] == facts, "mount-conflict")
        else:
            self._mounts[mount_id] = facts, fd
        return facts

    def _memory(self):
        require(
            os.getpid() == self._process
            and self._selection is self._expected_selection
            and self._reader is self._expected_reader
            and self._raw is self._expected_raw
            and type(self._raw) is bytes
            and r.state.sha256(self._raw) == self._sha256,
            "memory",
        )
        require(
            self._owned[0] is self._reader
            and self._owned[1] == self._proc
            and self._facts_memory() == self._facts_raw,
            "handle-memory",
        )
        if not self._closed:
            require(
                resources._seal_view(self._reader) == self._reader_view, "reader-memory"
            )
        require(
            r.state.canonical(
                {
                    key: str(value)
                    for key, value in destination_paths(self._selection).items()
                }
            )
            == self._path_raw,
            "path-memory",
        )
        self._selection._memory()

    def _facts_memory(self):
        return r.state.canonical(
            dict(
                subject=self._subject,
                mounts={
                    str(key): [facts, fd] for key, (facts, fd) in self._mounts.items()
                },
                proc=self._proc,
                proc_identity=self._proc_identity,
            )
        )

    @publication._poison_on_failure
    def check_memberships(self):
        require(not self._closed and not self._poisoned, "released")
        self._selection.validate()
        self._memory()
        table = parse_mountinfo(_bounded("/proc/self/mountinfo", MOUNTINFO_LIMIT))
        for expected, fd in self._mounts.values():
            require(
                {**table.get(fd_mount_id(fd), {}), **statfs(fd)} == expected,
                "mount-changed",
            )
        require(
            _epoch() == self._subject["host_epoch"]
            and os.uname().release == self._subject["kernel_release"],
            "epoch-changed",
        )
        self._reader.check_memberships()
        self._enumerated = True
        self._memory()

    @publication._poison_on_failure
    def close_named(self):
        require(
            not self._closed and self._enumerated and not self._poisoned,
            "membership-stage",
        )
        self._reader.close_named()
        for expected, fd in self._mounts.values():
            require(
                fd_mount_id(fd) == expected["mount_id"]
                and statfs(fd)
                == {key: expected[key] for key in ("statfs_type", "statfs_fsid")},
                "mount-changed",
            )
        require(
            tuple(attempt._identity(os.fstat(self._proc))[:5])
            == self._proc_identity
            == tuple(attempt._identity(os.stat("/proc/self/fd"))[:5]),
            "proc-binding",
        )
        self._memory()

    @publication._poison_on_failure
    def check_events(self):
        require(
            not self._closed and self._enumerated and not self._poisoned,
            "membership-stage",
        )
        self._reader.check_events()
        self._memory()

    def release(self):
        if self._closed:
            return
        self._closed = True
        first = None
        reader, proc = self._owned if self._owned is not None else (None, None)
        if proc is not None:
            try:
                os.close(proc)
            except BaseException as error:
                first = error
        if reader is not None:
            try:
                reader.release()
            except BaseException as error:
                if first is None:
                    first = error
        if first is not None:
            raise first


@contextmanager
def observe_subject(selection):
    """Read and retain fixed-role facts. This does not qualify a filesystem."""
    require(type(selection) is semantics.Selection, "selection")
    selection.validate()
    require(os.geteuid() == os.getegid() == r.legacy.ROOT_UID, "owner")
    held = _Subject(selection)
    primary = None
    try:
        yield held
        require(not held._poisoned and not held.closed, "poisoned")
        if not held._enumerated:
            held.check_memberships()
        held.close_named()
        held.check_events()
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            held.release()
        except BaseException:
            if primary is None:
                raise
            primary.add_note("secondary filesystem subject release failure")
    held._memory()


@dataclass(frozen=True, slots=True)
class QualifiedSubject:
    """Matched live facts, not source authentication or publication permission."""

    admission: object = field(repr=False)
    _subject: _Subject = field(repr=False)
    _references: tuple = field(repr=False)

    @property
    def raw(self):
        return self._subject.raw

    @property
    def sha256(self):
        return self._subject.sha256

    @property
    def closed(self):
        return self._subject.closed

    def _memory(self):
        require(
            type(self) is QualifiedSubject
            and type(self._references) is tuple
            and len(self._references) == 2
            and self.admission is self._references[0]
            and self._subject is self._references[1]
            and self.admission.selection is self._subject._selection,
            "qualified-memory",
        )
        self.admission._memory()
        self._subject._memory()

    def check_memberships(self):
        self._memory()
        self._subject.check_memberships()
        self._memory()

    def close_named(self):
        self._memory()
        self._subject.close_named()
        self._memory()

    def check_events(self):
        self._memory()
        self._subject.check_events()
        self._memory()


def _qualification(admission):
    return r._decode(
        admission.filesystem_qualification_raw,
        admission.filesystem_qualification_sha256,
        1048576,
    )


def _match_subject(raw, qualified):
    observed = r.observe.decode(raw)
    require(
        observed["observation_scope"]
        == "initial-nearest-ancestors-with-retained-identities",
        "observation-scope",
    )
    require(observed["subject"] == qualified["subject"], "qualification-subject")
    for role, actual in observed["roles"].items():
        expected = qualified["roles"][role]
        require(
            {key: value for key, value in actual.items() if key != "mount_index"}
            == {
                key: value
                for key, value in expected.items()
                if key not in {"mount_index", "probe_index"}
            },
            "qualification-role",
        )
        require(
            observed["mounts"][actual["mount_index"]]
            == qualified["mounts"][expected["mount_index"]],
            "qualification-mount",
        )
    require(
        observed["procfs"]["type_magic"] == qualified["procfs"]["type_magic"]
        and observed["mounts"][observed["procfs"]["mount_index"]]
        == qualified["mounts"][qualified["procfs"]["mount_index"]],
        "qualification-procfs",
    )


@contextmanager
def hold_qualified_subject(*, selection, admission):
    """Match selected write qualification before any metadata/bootstrap write.

    Read-only inspect/requalification must use their distinct executor paths.
    This context performs no write probe and grants no native permission.
    """
    from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
        persistence_owner_execution_admission as codec,
    )

    require(
        type(admission) is codec.Admission
        and admission.selection is selection
        and admission.action
        in {
            "begin",
            "finish-runtime",
            "record-intent",
            "publish-marker",
            "record-completion",
        },
        "qualified-admission",
    )
    admission.validate()
    with observe_subject(selection) as observed:
        _match_subject(observed.raw, _qualification(admission))
        held = QualifiedSubject(admission, observed, (admission, observed))
        held._memory()
        yield held
        held._memory()
    held._memory()


def assert_destination_parent(*, admission, subject, role, fd):
    """Check an actual publisher/mkdir-held FD against its fixed destination.

    Call with the real witness FD before publication, and retain that witness
    through the final closure. This check cannot substitute for its event proof.
    """
    require(
        type(subject) is QualifiedSubject
        and subject.admission is admission
        and not subject.closed,
        "qualified-parent",
    )
    subject._memory()
    paths = destination_paths(admission.selection)
    require(
        type(role) is str and role in paths and type(fd) is int and fd >= 0,
        "parent-role",
    )
    qualified = _qualification(admission)
    parent = paths[role].parent
    first = attempt._identity(os.fstat(fd))
    require(
        first[2] == stat.S_IFDIR | 0o700
        and first[3:5] == [r.legacy.ROOT_UID, r.legacy.ROOT_UID]
        and parent.resolve(strict=True) == parent
        and attempt._identity(parent.lstat())[:5] == first[:5],
        "parent-binding",
    )
    mount_id = fd_mount_id(fd)
    table = parse_mountinfo(_bounded("/proc/self/mountinfo", MOUNTINFO_LIMIT))
    require(mount_id in table, "parent-mount-id")
    actual = {**table[mount_id], **statfs(fd)}
    expected = qualified["mounts"][qualified["roles"][role]["mount_index"]]
    require(
        actual == expected
        and _epoch() == qualified["subject"]["host_epoch"]
        and os.uname().release == qualified["subject"]["kernel_release"]
        and attempt._identity(os.fstat(fd))[:5]
        == first[:5]
        == attempt._identity(parent.lstat())[:5],
        "parent-filesystem",
    )
    subject._memory()
