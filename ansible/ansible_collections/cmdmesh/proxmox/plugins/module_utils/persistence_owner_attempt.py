"""Bounded read-only retirement-attempt forensics under caller-owned leases.

This uses Linux FD/inotify syscalls, but no lifecycle command, subprocess, lock
acquisition, fsync or metadata publisher. A candidate is usable only after its
context exits successfully. It is never a fence or publication permission.
"""

import base64
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import errno
import os
from pathlib import Path
import re
import stat
import struct

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_retirement as r,
    persistence_owner_storage_profile as profile,
)

_WALK_ROOT = Path("/")
FILE_LIMIT = 4194304
AGGREGATE_LIMIT = 16777216
NAME_LIMIT = 64
OUTPUT_LIMIT = 33554432
EVENT_BATCH_LIMIT = 8
EVENT_BYTES_LIMIT = 262144
_MASK = 0x2 | 0x4 | 0x8 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x2000
_SELF = 0x400 | 0x800 | 0x2000 | 0x4000 | 0x8000


def require(value, code):
    r.require(value, "attempt-" + code)


def _identity(info):
    return list(r.observe.stable(info))


class _Reader:
    """One FD observer; two-stage membership then joined named closure."""

    def __init__(self):
        self.nodes = {}
        self.observed = {}
        self.absent = {}
        self.members = {}
        self.watches = {}
        self.raws = {}
        self.budget = 0
        self.enumerated = False
        self.closed = False
        self.lib = ctypes.CDLL(None, use_errno=True)
        self.lib.inotify_init1.argtypes = [ctypes.c_int]
        self.lib.inotify_init1.restype = ctypes.c_int
        self.lib.inotify_add_watch.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint32,
        ]
        self.lib.inotify_add_watch.restype = ctypes.c_int
        self.event = self.lib.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        require(self.event >= 0, "observer")

    def _watch(self, fd, policy):
        wd = self.lib.inotify_add_watch(
            self.event, os.fsencode("/proc/self/fd/" + str(fd)), _MASK
        )
        require(wd >= 0, "watch")
        policies = self.watches.setdefault(wd, [])
        if policy not in policies:
            policies.append(policy)

    def _directory(self, path, *, private=False, full=False):
        path = Path(path)
        key = str(path)
        require(path.is_absolute() and _WALK_ROOT in (path, *path.parents), "path")
        if key in self.nodes:
            node = self.nodes[key]
            require(node["kind"] == "directory", "duplicate-kind")
            require(
                not private or stat.S_IMODE(node["identity"][2]) == 0o700, "directory"
            )
            if full:
                require(
                    _identity(os.fstat(node["fd"])) == node["identity"],
                    "directory-changed",
                )
                node["prefix"] = 9
            return node["fd"]
        if path == _WALK_ROOT:
            fd = os.open(
                path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
        else:
            fd = os.open(
                path.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self._directory(path.parent),
            )
        try:
            first = _identity(os.fstat(fd))
            require(
                stat.S_ISDIR(first[2])
                and first[3:5] == [r.legacy.ROOT_UID, r.legacy.ROOT_UID]
                and not first[2] & 0o22
                and (not private or stat.S_IMODE(first[2]) == 0o700)
                and first == _identity(path.lstat()),
                "directory",
            )
            self.nodes[key] = dict(
                fd=fd, identity=first, prefix=9 if full else 5, kind="directory"
            )
            return fd
        except BaseException:
            os.close(fd)
            raise

    def entry(self, path):
        path = Path(path)
        parent = self._directory(path.parent)
        self._watch(parent, ("selected", path.name))
        try:
            first = _identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
        except FileNotFoundError as error:
            require(error.errno == errno.ENOENT, "absence")
            self.absent[str(path)] = parent, path.name
            return None
        key = str(path)
        require(
            key not in self.observed or self.observed[key] == first,
            "duplicate-identity",
        )
        self.observed[key] = first
        return first

    def directory_identity(self, path, *, private=False):
        """Return the actual held-directory observation for the layout collector."""
        return _identity(os.fstat(self._directory(path, private=private)))

    def directory(self, path, *, shared=False):
        first = self.entry(path)
        if first is None:
            return None
        if not (
            stat.S_ISDIR(first[2])
            and stat.S_IMODE(first[2]) == 0o700
            and first[3:5] == [r.legacy.ROOT_UID, r.legacy.ROOT_UID]
        ):
            return False
        fd = self._directory(path, private=True, full=not shared)
        self._watch(fd, ("shared", self.pair_key) if shared else ("owned", ""))
        return fd

    def file(self, path, limit=FILE_LIMIT):
        first = self.entry(path)
        if first is None:
            return None
        if not (
            first[2] == stat.S_IFREG | 0o600
            and first[3:5] == [r.legacy.ROOT_UID, r.legacy.ROOT_UID]
            and first[5] == 1
        ):
            return False
        effective_limit = min(limit, AGGREGATE_LIMIT - self.budget)
        require(0 <= first[6] <= effective_limit, "read-budget")
        key = str(path)
        parent = self._directory(Path(path).parent)
        fd = os.open(
            Path(path).name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        try:
            require(_identity(os.fstat(fd)) == first, "file-race")
            self._watch(fd, ("file", ""))
            raw = bytearray()
            while part := os.read(fd, min(65536, effective_limit + 1 - len(raw))):
                raw.extend(part)
                require(len(raw) <= effective_limit, "read-budget")
            raw = bytes(raw)
            require(
                len(raw) == first[6] and _identity(os.fstat(fd)) == first, "file-race"
            )
            require(key not in self.nodes, "duplicate-file")
            self.nodes[key] = dict(fd=fd, identity=first, prefix=9, kind="file")
            self.raws[key] = raw, r.state.sha256(raw)
            self.budget += len(raw)
            return dict(
                identity=first,
                sha256=r.state.sha256(raw),
                raw_base64=base64.b64encode(raw).decode(),
            )
        except BaseException:
            os.close(fd)
            raise

    def _scan(self, path, shared):
        found = {}
        fd = self.nodes[str(path)]["fd"]
        with os.scandir(fd) as entries:
            for count, item in enumerate(entries, 1):
                require(count <= NAME_LIMIT, "membership-limit")
                info = _identity(item.stat(follow_symlinks=False))
                if (
                    shared
                    and item.name != self.pair_key
                    and re.fullmatch(r"[a-f0-9]{64}", item.name)
                ):
                    if info[2] == stat.S_IFDIR | 0o700 and info[3:5] == [
                        r.legacy.ROOT_UID,
                        r.legacy.ROOT_UID,
                    ]:
                        continue
                found[item.name] = info
        return found

    def membership(self, path, *, shared=False):
        found = self._scan(path, shared)
        key = str(path)
        require(
            key not in self.members
            or self.members[key] == (shared, tuple(sorted(found))),
            "membership-conflict",
        )
        self.members[key] = shared, tuple(sorted(found))
        return found

    def check_memberships(self):
        require(not self.closed, "released")
        for path, (shared, names) in self.members.items():
            require(
                tuple(sorted(self._scan(Path(path), shared))) == names,
                "membership-changed",
            )
        self.enumerated = True

    def close_named(self):
        require(self.enumerated and not self.closed, "membership-stage")
        for path, node in self.nodes.items():
            first = node["identity"][: node["prefix"]]
            require(
                _identity(os.fstat(node["fd"]))[: node["prefix"]]
                == first
                == _identity(Path(path).lstat())[: node["prefix"]],
                "named-changed",
            )
        for path, first in self.observed.items():
            # Shared directories have intentionally stable5 policy; unrelated
            # valid sibling-pair changes must not freeze their mtime/ctime.
            node = self.nodes.get(path)
            prefix = node["prefix"] if node is not None else 9
            require(
                _identity(Path(path).lstat())[:prefix] == first[:prefix],
                "observed-changed",
            )
        for path, (fd, name) in self.absent.items():
            try:
                os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError as error:
                require(error.errno == errno.ENOENT, "absence")
            else:
                require(False, "absence-changed")
        for raw, checksum in self.raws.values():
            require(
                type(raw) is bytes and r.state.sha256(raw) == checksum, "raw-memory"
            )

    def check_events(self):
        require(not self.closed, "released")
        consumed = 0
        for _batch in range(EVENT_BATCH_LIMIT):
            require(EVENT_BYTES_LIMIT - consumed >= 16, "event-budget")
            try:
                data = os.read(self.event, min(65536, EVENT_BYTES_LIMIT - consumed))
            except BlockingIOError:
                return
            require(bool(data), "observer-eof")
            consumed += len(data)
            require(consumed <= EVENT_BYTES_LIMIT, "event-budget")
            offset = 0
            while offset < len(data):
                require(len(data) - offset >= 16, "event-frame")
                wd, mask, _cookie, size = struct.unpack_from("iIII", data, offset)
                require(size <= 4096 and offset + 16 + size <= len(data), "event-frame")
                name = os.fsdecode(
                    data[offset + 16 : offset + 16 + size].split(b"\0", 1)[0]
                )
                offset += 16 + size
                require(not mask & _SELF and wd in self.watches, "event")
                for kind, selected in self.watches[wd]:
                    if kind == "selected" and name and name != selected:
                        continue
                    if (
                        kind == "shared"
                        and name != selected
                        and re.fullmatch(r"[a-f0-9]{64}", name)
                        and mask & 0x40000000
                    ):
                        continue
                    require(False, "event")
        require(False, "event-budget")

    def release(self):
        failed = False
        for fd in [*(node["fd"] for node in self.nodes.values()), self.event]:
            try:
                os.close(fd)
            except OSError:
                failed = True
        self.nodes.clear()
        self.closed = True
        require(not failed, "release")


@dataclass(frozen=True, slots=True)
class Observation:
    raw: bytes
    sha256: str
    seal: _Reader


def _collect(reader, owner, intent, intent_raw, intent_sha):
    files, unsafe, unknown, directories = {}, {}, {}, {}
    blocked = []

    def directory(path, *, shared=False):
        result = reader.directory(path, shared=shared)
        if result is False:
            unsafe[str(path)] = reader.observed[str(path)]
            blocked.append("unsafe-directory")
        elif result is not None:
            directories[str(path)] = reader.nodes[str(path)]["identity"]
        return result

    def file(path, limit=FILE_LIMIT):
        result = reader.file(path, limit)
        if result is False:
            unsafe[str(path)] = reader.observed[str(path)]
            blocked.append("unsafe-file")
        elif result is not None:
            files[str(path)] = result
        return result

    def members(path, allowed, *, shared=False):
        found = reader.membership(path, shared=shared)
        for name, identity in found.items():
            if name not in allowed:
                unknown[str(path / name)] = identity
                blocked.append("unknown-member")
                reader.observed[str(path / name)] = identity
        return found

    legacy = r.legacy.RUNTIME_ROOT / owner.pair_key
    for path, expected in intent["shared_directories"].items():
        identity = reader.directory_identity(Path(path), private=True)
        require(identity[:5] == expected, "legacy-parent-changed")
        directories[path] = identity
    shared = file(r.legacy.RUNTIME_ROOT / "runtime.json")
    require(
        type(shared) is dict
        and shared["identity"] == intent["shared_runtime"]["identity"]
        and shared["sha256"] == intent["shared_runtime"]["sha256"],
        "legacy-runtime-changed",
    )
    require(
        directory(r.legacy.RUNTIME_ROOT, shared=True) is not False,
        "legacy-runtime-directory",
    )
    members(r.legacy.RUNTIME_ROOT, {"runtime.json", owner.pair_key}, shared=True)
    old_raws = {}
    for rel, expected in intent["basis"]["directories"].items():
        path = legacy / rel
        require(directory(path) not in (None, False), "legacy-directory")
        require(directories[str(path)][:5] == expected, "legacy-directory-changed")
        names = set(intent["basis"]["members"][rel])
        members(path, names | ({profile.MARKER} if not rel else set()))
    for rel, expected in intent["basis"]["files"].items():
        path = legacy / rel
        item = file(path)
        require(
            type(item) is dict
            and item["identity"] == expected["identity"]
            and item["sha256"] == expected["sha256"],
            "legacy-file-changed",
        )
        old_raws[rel] = reader.raws[str(path)][0]
    r._validate_legacy(
        owner, intent["basis"], old_raws, intent["anchor"], intent["caller_evidence"]
    )
    marker_path = legacy / profile.MARKER
    marker = file(marker_path, r.MARKER_LIMIT)

    root = profile.RUNTIME_ROOT
    root_fd = directory(root, shared=True)
    pair = root / owner.pair_key
    runtime = stored = completion = None
    pair_fd = None
    runtime_kind = "absent"
    if root_fd not in (None, False):
        root_names = members(root, {"runtime.json", owner.pair_key}, shared=True)
        runtime = file(root / "runtime.json")
        if type(runtime) is dict:
            raw = reader.raws[str(root / "runtime.json")][0]
            if raw == r.state.canonical(profile.RUNTIME):
                runtime_kind = "current"
            elif raw == r.state.canonical(r.RUNTIME):
                runtime_kind = "legacy-v1"
                blocked.append("legacy-runtime-profile")
            else:
                runtime_kind = "invalid"
                blocked.append("runtime-profile")
        elif runtime is None and root_names:
            blocked.append("runtime-missing-with-members")
        pair_fd = directory(pair)
        if pair_fd not in (None, False):
            members(pair, {"intent.json", "complete.json"})
            stored = file(pair / "intent.json")
            completion = file(pair / "complete.json")
    marker_ok = type(marker) is dict and reader.raws[str(marker_path)][
        0
    ] == r.state.canonical(r._marker(owner, intent_sha))
    intent_ok = (
        type(stored) is dict and reader.raws[str(pair / "intent.json")][0] == intent_raw
    )
    if stored is not None and not intent_ok:
        blocked.append("invalid-intent")
    if marker is not None and not marker_ok:
        blocked.append("invalid-marker")
    if marker is not None and not intent_ok:
        blocked.append("marker-without-intent")
    complete_ok = False
    if completion is not None:
        if type(completion) is dict and intent_ok and marker_ok:
            try:
                body = r.validate_handoff(
                    owner,
                    intent_raw,
                    intent_sha,
                    reader.raws[str(pair / "complete.json")][0],
                    completion["sha256"],
                )
                require(
                    body["intent_file"]
                    == {
                        "path": str(pair / "intent.json"),
                        "sha256": stored["sha256"],
                        "identity": stored["identity"],
                    },
                    "completion-intent",
                )
                require(
                    body["marker_file"]
                    == {
                        "path": str(marker_path),
                        "sha256": marker["sha256"],
                        "identity": marker["identity"],
                    },
                    "completion-marker",
                )
                complete_ok = True
            except (ValueError, TypeError, UnicodeError, RecursionError):
                pass
        if not complete_ok:
            blocked.append("invalid-completion")
    if blocked:
        status = "blocked"
    elif complete_ok:
        status = "complete-candidate"
    elif marker_ok:
        status = "h0-marker"
    elif intent_ok:
        status = "h0-only"
    elif pair_fd not in (None, False):
        status = "empty-claim"
    elif root_fd not in (None, False) and runtime is None:
        status = "bootstrap-incomplete"
    else:
        status = "unused"
    return dict(
        document_type="cmdmesh.proxmox.owner-retirement.attempt-observation",
        schema_version=1,
        binding=r.asdict(owner),
        accepted_intent_sha256=intent_sha,
        expected_publication_protocol=profile.PROTOCOL,
        status=status,
        runtime_profile=runtime_kind,
        blocked_reasons=sorted(set(blocked)),
        files=files,
        directories=directories,
        directory_closure_fields={
            path: reader.nodes[path]["prefix"] for path in directories
        },
        ancestors={
            path: node["identity"][:5]
            for path, node in reader.nodes.items()
            if node["kind"] == "directory" and path not in directories
        },
        absent=sorted(reader.absent),
        memberships={
            path: list(names) for path, (_shared, names) in reader.members.items()
        },
        membership_policy={
            path: "selected-pair-and-unknowns" if shared else "exact"
            for path, (shared, _names) in reader.members.items()
        },
        unsafe_entries=unsafe,
        unknown_entries=unknown,
        readonly=True,
        forensic_only=True,
        candidate_only=True,
        publication_authorized=False,
        original_request_fenced=False,
        native_action_dispatched=False,
        metadata_resolution_recorded=False,
        successor_native_admission_authorized=False,
    )


@contextmanager
def inspect_attempt(binding, intent_raw, intent_sha256):
    """Borrow true caller pair/native/application leases; never acquire/release them."""
    owner, binding_raw = r._binding(binding)
    intent = r._intent(owner, intent_raw, intent_sha256)
    expected_profile = r.state.canonical(profile.RUNTIME)
    expected_paths = (profile.RUNTIME_ROOT, profile.MARKER, profile.PROTOCOL)
    require(
        profile.RUNTIME_ROOT == r.RUNTIME_ROOT and profile.MARKER == r.MARKER,
        "profile-path",
    )
    reader = _Reader()
    reader.pair_key = owner.pair_key
    primary = None
    try:
        body = _collect(reader, owner, intent, intent_raw, intent_sha256)
        raw = r.state.canonical(body)
        require(len(raw) <= OUTPUT_LIMIT, "output-limit")
        checksum = r.state.sha256(raw)
        view = Observation(raw, checksum, reader)
        reader.check_memberships()
        reader.close_named()
        reader.check_events()
        r._close_binding(binding, owner, binding_raw)
        # A composed caller may join this post-yield scan with other readers.
        # Do not add another directory walk after its final fixed probes.
        reader.enumerated = False
        yield view
        if not reader.enumerated:
            reader.check_memberships()
        reader.close_named()
        require(
            type(view.raw) is bytes
            and type(view.sha256) is str
            and view.seal is reader
            and view.raw == raw
            and view.sha256 == checksum
            and r.state.canonical(body) == raw,
            "memory",
        )
        require(
            r.state.canonical(profile.RUNTIME) == expected_profile
            and expected_paths
            == (profile.RUNTIME_ROOT, profile.MARKER, profile.PROTOCOL),
            "profile-changed",
        )
        r._close_binding(binding, owner, binding_raw)
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
            primary.add_note("secondary attempt observer release failure")
    require(
        type(view.raw) is bytes
        and type(view.sha256) is str
        and view.seal is reader
        and view.raw == raw
        and view.sha256 == checksum
        and r.state.canonical(body) == raw,
        "memory",
    )
    require(
        r.state.canonical(profile.RUNTIME) == expected_profile
        and expected_paths == (profile.RUNTIME_ROOT, profile.MARKER, profile.PROTOCOL)
        and profile.RUNTIME_ROOT == r.RUNTIME_ROOT,
        "profile-changed",
    )
    r._close_binding(binding, owner, binding_raw)
