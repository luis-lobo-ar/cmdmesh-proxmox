"""Observe one fixed private namespace mkdir, then an empty-child handoff.

The caller owns actual actor/pair/bootstrap exclusion and filesystem qualification.
This context creates no files, acquires no leases and grants no publication rights.
Arm the next file-publication witness before closing this context; write its file
only afterwards. Inotify cannot attribute writers or observe inside a directory
before it exists: exclusive cooperating-writer ownership remains load-bearing.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import errno
import os
import re
import stat
import struct

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_attempt as attempt,
    persistence_owner_publication_witness as publication,
    persistence_owner_semantics as semantics,
)

r, profile = attempt.r, attempt.profile


def require(value, code):
    r.require(value, "directory-witness-" + code)


def _configuration():
    return (
        profile.RUNTIME_ROOT,
        r.RUNTIME_ROOT,
        r.legacy.RUNTIME_ROOT,
        r.legacy.ROOT_UID,
        attempt._WALK_ROOT,
        attempt._MASK,
        attempt._SELF,
        attempt.NAME_LIMIT,
        attempt.EVENT_BATCH_LIMIT,
        attempt.EVENT_BYTES_LIMIT,
    )


@dataclass(frozen=True, slots=True)
class DirectoryReceipt:
    path: str
    role: str
    parent_identity: tuple[int, ...]
    identity: tuple[int, ...]


class _Creation:
    def __init__(self, selection, role):
        require(type(selection) is semantics.Selection, "selection")
        require(type(role) is str and role in ("runtime-root", "pair"), "role")
        selection.validate()
        self._selection = self._expected_selection = selection
        self.role = role
        self.path = (
            profile.RUNTIME_ROOT
            if role == "runtime-root"
            else profile.RUNTIME_ROOT / selection._private_binding.pair_key
        )
        self._spec = (role, self.path)
        self._config = _configuration()
        self._process = os.getpid()
        self._attempted = self._poisoned = self._created = self._seen = False
        self._closed = self._completed = self._enumerated = False
        self._receipt = self._created_receipt = self._receipt_raw = None
        self._parent = self._child = self._dependency = None
        self._anchor = None
        self._expected_child = None
        try:
            self._memory()
            self._parent = attempt._Reader()
            self.fd = self._parent._directory(self.path.parent, private=True)
            self._parent._watch(self.fd, ("owned", ""))
            require(len(self._parent.watches) == 1, "parent-watch")
            self.wd = next(iter(self._parent.watches))
            self._parent_identity = tuple(attempt._identity(os.fstat(self.fd))[:5])
            self._absent()
            if role == "pair":
                self._dependency = attempt._Reader()
                path = profile.RUNTIME_ROOT / "runtime.json"
                item = self._dependency.file(path)
                require(
                    type(item) is dict
                    and self._dependency.raws[str(path)][0]
                    == r.state.canonical(profile.RUNTIME),
                    "runtime-profile",
                )
                self._scan_parent()
                self._dependency.check_memberships()
                self._dependency.close_named()
                self._dependency.check_events()
            self._anchor = (
                self.fd,
                self.wd,
                self._parent_identity,
                self._parent,
                self._dependency,
            )
            self._parent.check_memberships()
            self._parent.close_named()
            self._events()
            self._memory()
        except BaseException as error:
            try:
                self.release()
            except BaseException:
                error.add_note("secondary directory observer release failure")
            raise

    @property
    def receipt(self):
        return self._receipt

    @property
    def closed(self):
        return self._closed

    @property
    def completed(self):
        return self._completed

    def _memory(self):
        require(
            os.getpid() == self._process
            and os.geteuid() == os.getegid() == r.legacy.ROOT_UID,
            "owner-process",
        )
        require(
            self._selection is self._expected_selection
            and (self.role, self.path) == self._spec
            and _configuration() == self._config,
            "memory",
        )
        if self._anchor is not None:
            require(
                type(self.fd) is int
                and type(self.wd) is int
                and type(self._parent_identity) is tuple
                and (self.fd, self.wd, self._parent_identity) == self._anchor[:3]
                and self._parent is self._anchor[3]
                and self._dependency is self._anchor[4]
                and self._child is self._expected_child,
                "handle-memory",
            )
            if not self._closed:
                require(
                    self._parent.nodes[str(self.path.parent)]["fd"] == self.fd,
                    "parent-handle",
                )
        if not self._closed:
            self._selection.validate()
        self._receipt_memory()
        self._selection._memory()
        require(
            self._selection is self._expected_selection
            and (self.role, self.path) == self._spec
            and _configuration() == self._config,
            "memory",
        )
        if self._anchor is not None:
            require(
                (self.fd, self.wd, self._parent_identity) == self._anchor[:3]
                and self._parent is self._anchor[3]
                and self._dependency is self._anchor[4]
                and self._child is self._expected_child,
                "handle-memory",
            )
        self._receipt_memory()

    def _receipt_memory(self):
        value = self._receipt
        require(value is not None or not self._created, "receipt-memory")
        if value is None:
            return
        require(
            type(value) is DirectoryReceipt
            and value is self._created_receipt
            and value.path == str(self.path)
            and value.role == self.role
            and type(value.parent_identity) is tuple
            and len(value.parent_identity) == 5
            and type(value.identity) is tuple
            and len(value.identity) == 9
            and all(
                type(part) is int and part >= 0
                for part in (*value.parent_identity, *value.identity)
            )
            and r.state.canonical(r.asdict(value)) == self._receipt_raw,
            "receipt-memory",
        )

    def _absent(self):
        try:
            os.stat(self.path.name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError as error:
            require(error.errno == errno.ENOENT, "absence")
        else:
            require(False, "destination-exists")

    def _scan_parent(self):
        if self.role != "pair":
            return
        found = set()
        with os.scandir(self.fd) as entries:
            for count, item in enumerate(entries, 1):
                require(count <= attempt.NAME_LIMIT, "membership-budget")
                if item.name not in ("runtime.json", self.path.name):
                    info = attempt._identity(item.stat(follow_symlinks=False))
                    require(
                        re.fullmatch(r"[a-f0-9]{64}", item.name)
                        and info[2:5]
                        == [stat.S_IFDIR | 0o700, r.legacy.ROOT_UID, r.legacy.ROOT_UID],
                        "parent-membership",
                    )
                    continue
                found.add(item.name)
        require(
            found
            == (
                {"runtime.json", self.path.name} if self._created else {"runtime.json"}
            ),
            "parent-membership",
        )

    def _events(self, *, creation=False):
        consumed = 0
        for _ in range(attempt.EVENT_BATCH_LIMIT):
            require(attempt.EVENT_BYTES_LIMIT - consumed >= 16, "event-budget")
            try:
                data = os.read(
                    self._parent.event, min(65536, attempt.EVENT_BYTES_LIMIT - consumed)
                )
            except BlockingIOError:
                require(not creation or self._seen, "missing-create-event")
                return
            require(bool(data), "event-eof")
            consumed += len(data)
            offset = 0
            while offset < len(data):
                require(len(data) - offset >= 16, "event-frame")
                wd, mask, cookie, size = struct.unpack_from("iIII", data, offset)
                require(
                    size <= 4096
                    and offset + 16 + size <= len(data)
                    and wd == self.wd
                    and not mask & attempt._SELF,
                    "event-frame",
                )
                raw = data[offset + 16 : offset + 16 + size]
                offset += 16 + size
                name, separator, padding = raw.partition(b"\0")
                require(
                    separator
                    and not any(padding)
                    and 0 < len(name) <= 255
                    and not any(c in name for c in (0, 10, 13, 47)),
                    "event-name",
                )
                name = os.fsdecode(name)
                if name == self.path.name:
                    require(
                        creation
                        and not self._seen
                        and mask == 0x40000100
                        and cookie == 0,
                        "event",
                    )
                    self._seen = True
                elif self.role == "runtime-root":
                    # This parent is shared with other fixed CmdMesh namespaces.
                    continue
                else:
                    require(
                        re.fullmatch(r"[a-f0-9]{64}", name)
                        and mask in (0x40000100, 0x40000200),
                        "event",
                    )
        require(False, "event-budget")

    @publication._poison_on_failure
    def create(self):
        require(
            not self._closed and not self._poisoned and not self._attempted,
            "single-use",
        )
        self._attempted = True
        self._memory()
        self._absent()
        self._scan_parent()
        if self._dependency is not None:
            self._dependency.check_memberships()
            self._dependency.close_named()
            self._dependency.check_events()
        self._parent.check_memberships()
        self._parent.close_named()
        self._events()
        self._memory()
        os.mkdir(self.path.name, mode=0o700, dir_fd=self.fd)
        self._created = True
        self._child = attempt._Reader()
        self._expected_child = self._child
        child = self._child.directory(self.path)
        require(child not in (None, False), "created-directory")
        require(self._child.membership(self.path) == {}, "created-membership")
        os.fsync(child)
        os.fsync(self.fd)
        self._events(creation=True)
        receipt = DirectoryReceipt(
            str(self.path),
            self.role,
            self._parent_identity,
            tuple(attempt._identity(os.fstat(child))),
        )
        self._receipt = self._created_receipt = receipt
        self._receipt_raw = r.state.canonical(r.asdict(receipt))
        self.check_memberships()
        self.close_named()
        self.check_events()
        self._enumerated = False
        return receipt

    @publication._poison_on_failure
    def check_memberships(self):
        require(
            not self._closed and not self._poisoned and self._receipt is not None,
            "not-created",
        )
        self._scan_parent()
        self._parent.check_memberships()
        self._child.check_memberships()
        if self._dependency is not None:
            self._dependency.check_memberships()
        self._enumerated = True

    @publication._poison_on_failure
    def close_named(self):
        require(
            not self._closed and not self._poisoned and self._enumerated,
            "membership-stage",
        )
        self._parent.close_named()
        self._child.close_named()
        if self._dependency is not None:
            self._dependency.close_named()
        require(
            tuple(attempt._identity(os.fstat(self.fd))[:5]) == self._parent_identity,
            "parent-changed",
        )
        self._memory()

    @publication._poison_on_failure
    def check_events(self):
        require(
            not self._closed and not self._poisoned and self._receipt is not None,
            "not-created",
        )
        self._events()
        self._child.check_events()
        if self._dependency is not None:
            self._dependency.check_events()

    def release(self):
        if self._closed:
            return
        self._closed = True
        first = None
        for reader in (self._child, self._dependency, self._parent):
            if reader is not None:
                try:
                    reader.release()
                except BaseException as error:
                    if first is None:
                        first = error
        if first is not None:
            raise first


@contextmanager
def _observe(selection, role):
    operation = _Creation(selection, role)
    primary = None
    try:
        yield operation
        require(
            not operation._poisoned and operation.receipt is not None, "not-created"
        )
        if not operation._enumerated:
            operation.check_memberships()
        operation.close_named()
        operation.check_events()
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            operation.release()
        except BaseException:
            if primary is None:
                raise
            primary.add_note("secondary directory observer release failure")
    operation._memory()
    operation._completed = True


def observe_directory_creation_v2(
    *,
    binding,
    checkpoint,
    checkpoint_sha256,
    intent_raw,
    intent_sha256,
    contract_raw,
    contract_sha256,
    role,
):
    """Observe one fixed empty mkdir under caller-owned real exclusion.

    A later file witness must overlap this context before it closes. This API
    does not initialize the bootstrap mutex/profile or publish H0/H1/markers.
    """
    require(type(role) is str and role in ("runtime-root", "pair"), "role")
    selection = semantics.select(
        binding=binding,
        checkpoint=checkpoint,
        checkpoint_sha256=checkpoint_sha256,
        intent_raw=intent_raw,
        intent_sha256=intent_sha256,
        contract_raw=contract_raw,
        contract_sha256=contract_sha256,
    )
    return _observe(selection, role)
