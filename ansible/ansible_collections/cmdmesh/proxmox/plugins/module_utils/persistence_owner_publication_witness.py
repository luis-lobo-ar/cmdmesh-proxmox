"""One finite control publication with parent and named-file event coverage.

The caller retains real leases and immutable old-slot/reference/database
witnesses. This leaf is not current/fence admission or a continuation executor.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
import os
from pathlib import Path
import re
import stat
import struct

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_atomic as atomic,
    persistence_owner_attempt as attempt,
    persistence_owner_semantics as semantics,
)

r, profile = attempt.r, attempt.profile
EVENT_PROFILE = "linux-procfd-parent-modify-create-close-v1"


def require(value, code):
    r.require(value, "publication-witness-" + code)


def _poison_on_failure(method):
    @wraps(method)
    def checked(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except BaseException:
            self._poisoned = True
            raise

    return checked


def _configuration():
    return (
        r.state.canonical(profile.RUNTIME),
        profile.RUNTIME_ROOT,
        profile.PROTOCOL,
        profile.MARKER,
        r.RUNTIME_ROOT,
        r.legacy.RUNTIME_ROOT,
        r.legacy.ROOT_UID,
        EVENT_PROFILE,
        attempt._WALK_ROOT,
    )


@dataclass(frozen=True, slots=True)
class _Dependency:
    path: str
    raw: bytes
    identity: tuple[int, ...] | None


@dataclass(frozen=True, slots=True)
class _Spec:
    action: str
    path: str
    payload: bytes
    before_names: tuple[str, ...]
    shared: bool
    pair_key: str
    dependencies: tuple[_Dependency, ...]


def _signature(spec):
    return (
        spec.action,
        spec.path,
        spec.payload,
        spec.before_names,
        spec.shared,
        spec.pair_key,
        tuple((entry.path, entry.raw, entry.identity) for entry in spec.dependencies),
    )


def _spec(
    owner,
    intent,
    intent_raw,
    intent_sha,
    action,
    complete_raw,
    complete_sha,
    selection=None,
):
    pair = profile.RUNTIME_ROOT / owner.pair_key
    shared = False
    dependencies = ()
    if action == "record-completion":
        if selection is None:
            completion = r.validate_handoff(
                owner, intent_raw, intent_sha, complete_raw, complete_sha
            )
        else:
            completion = selection.completion(complete_raw, complete_sha)
        path, raw, names = pair / "complete.json", complete_raw, ("intent.json",)
        dependencies = (
            _Dependency(
                str(pair / "intent.json"),
                intent_raw,
                tuple(completion["intent_file"]["identity"]),
            ),
            _Dependency(
                completion["marker_file"]["path"],
                r.state.canonical(completion["marker"]),
                tuple(completion["marker_file"]["identity"]),
            ),
        )
    else:
        require(complete_raw is None and complete_sha is None, "unexpected-completion")
        if action == "finish-runtime":
            path, raw, names = (
                profile.RUNTIME_ROOT / "runtime.json",
                r.state.canonical(profile.RUNTIME),
                (),
            )
            shared = True
        elif action == "record-intent":
            path, raw, names = pair / "intent.json", intent_raw, ()
        else:
            require(action == "publish-marker", "action")
            path = r.legacy.RUNTIME_ROOT / owner.pair_key / profile.MARKER
            raw, names = r.state.canonical(r._marker(owner, intent_sha)), tuple(
                intent["basis"]["members"][""]
            )
            dependencies = (_Dependency(str(pair / "intent.json"), intent_raw, None),)
    return _Spec(
        action,
        str(path),
        raw,
        tuple(sorted(names)),
        shared,
        owner.pair_key,
        dependencies,
    )


class _Publication:
    def __init__(self, spec, binding, owner, binding_raw, selection=None):
        self.spec, self._expected_spec = spec, _signature(spec)
        self._binding, self._owner, self._binding_raw = binding, owner, binding_raw
        self._selection = self._expected_selection = selection
        if selection is not None:
            require(type(selection) is semantics.Selection, "selection")
            selection.validate()
        self._attempted = False
        self._successful = False
        self._poisoned = False
        self._configuration = _configuration()
        self._process = os.getpid()
        self._receipt = self._receipt_raw = None
        self._published_receipt = None
        self._final = None
        self._controls = None
        self._closed = False
        self._enumerated = False
        self._parent = attempt._Reader()
        try:
            path = Path(spec.path)
            self.fd = self._parent._directory(path.parent, private=True, full=True)
            self._parent._watch(
                self.fd, ("shared", spec.pair_key) if spec.shared else ("owned", "")
            )
            require(len(self._parent.watches) == 1, "parent-watch")
            self.wd = next(iter(self._parent.watches))
            self.parent_identity = tuple(attempt._identity(os.fstat(self.fd)))
            require(self._scan(after=False) == spec.before_names, "initial-membership")
            self._parent.check_memberships()
            self._parent.close_named()
            self._parent.check_events()
            if spec.dependencies:
                self._controls = attempt._Reader()
                for dependency in spec.dependencies:
                    item = self._controls.file(Path(dependency.path))
                    require(
                        type(item) is dict
                        and self._controls.raws[dependency.path][0] == dependency.raw
                        and (
                            dependency.identity is None
                            or tuple(item["identity"]) == dependency.identity
                        ),
                        "dependency",
                    )
                self._controls.check_memberships()
                self._controls.close_named()
                self._controls.check_events()
        except BaseException as error:
            try:
                self.release()
            except BaseException:
                error.add_note(
                    "secondary publication observer initialization release failure"
                )
            raise

    @property
    def receipt(self):
        return self._receipt

    @property
    def closed(self):
        return self._closed

    @property
    def seal(self):
        return self

    def _scan(self, *, after):
        names = []
        with os.scandir(self.fd) as entries:
            for count, entry in enumerate(entries, 1):
                require(count <= attempt.NAME_LIMIT, "membership-budget")
                if (
                    after
                    and self.spec.shared
                    and entry.name != self.spec.pair_key
                    and re.fullmatch("[a-f0-9]{64}", entry.name)
                ):
                    info = entry.stat(follow_symlinks=False)
                    if (
                        info.st_mode == stat.S_IFDIR | 0o700
                        and info.st_uid == info.st_gid == r.legacy.ROOT_UID
                    ):
                        continue
                names.append(entry.name)
        return tuple(sorted(names))

    def _memory(self):
        require(os.getpid() == self._process, "process-changed")
        require(self._selection is self._expected_selection, "selection-changed")
        if self._selection is not None:
            self._selection.validate()
        r._close_binding(self._binding, self._owner, self._binding_raw)
        require(
            type(self.spec) is _Spec
            and _signature(self.spec) == self._expected_spec
            and _configuration() == self._configuration,
            "memory",
        )
        if self._receipt is not None:
            require(
                self._receipt is self._published_receipt
                and r.state.canonical(r.asdict(self._receipt)) == self._receipt_raw,
                "receipt-memory",
            )
        if self._selection is not None:
            self._selection._memory()
        require(self._selection is self._expected_selection, "selection-changed")

    def _atomic_events(self, receipt):
        modified = linked = closed = False
        consumed = 0
        for _ in range(attempt.EVENT_BATCH_LIMIT):
            require(attempt.EVENT_BYTES_LIMIT - consumed >= 16, "event-budget")
            try:
                data = os.read(
                    self._parent.event, min(65536, attempt.EVENT_BYTES_LIMIT - consumed)
                )
            except BlockingIOError:
                require(modified and linked and closed, "missing-publication-events")
                return
            require(bool(data), "event-eof")
            consumed += len(data)
            offset = 0
            while offset < len(data):
                require(len(data) - offset >= 16, "event-frame")
                wd, mask, _, size = struct.unpack_from("iIII", data, offset)
                require(size <= 4096 and offset + 16 + size <= len(data), "event-frame")
                name = os.fsdecode(
                    data[offset + 16 : offset + 16 + size].split(b"\0", 1)[0]
                )
                offset += 16 + size
                require(wd == self.wd and not mask & attempt._SELF, "event")
                if (
                    name == receipt.anonymous_name
                    and mask == 2
                    and not linked
                    and not closed
                ):
                    modified = True
                elif (
                    name == Path(self.spec.path).name
                    and mask == 256
                    and modified
                    and not linked
                ):
                    linked = True
                elif (
                    name == receipt.anonymous_name
                    and mask == 8
                    and linked
                    and not closed
                ):
                    closed = True
                elif (
                    self.spec.shared
                    and name != self.spec.pair_key
                    and re.fullmatch("[a-f0-9]{64}", name)
                    and mask in (0x40000100, 0x40000200)
                ):
                    continue
                else:
                    require(False, "event")
        require(False, "event-budget")

    @_poison_on_failure
    def publish(self):
        require(not self.closed and not self._attempted, "single-use")
        require(not self._poisoned, "poisoned")
        self._attempted = True
        self._memory()
        require(self._scan(after=False) == self.spec.before_names, "initial-membership")
        self._parent.check_memberships()
        self._parent.close_named()
        self._parent.check_events()
        if self._controls is not None:
            self._controls.check_memberships()
            self._controls.close_named()
            self._controls.check_events()
        self._memory()
        receipt = atomic.publish_observed(
            self.spec.path, self.spec.payload, protocol=profile.PROTOCOL
        )
        require(
            type(receipt) is atomic.PublicationReceipt
            and receipt.path == self.spec.path
            and receipt.protocol == profile.PROTOCOL
            and receipt.payload_sha256 == r.state.sha256(self.spec.payload)
            and receipt.payload_bytes == len(self.spec.payload)
            and receipt.parent_identity == self.parent_identity[:5],
            "receipt-binding",
        )
        require(
            type(receipt.anonymous_name) is str
            and 0 < len(os.fsencode(receipt.anonymous_name)) <= 255
            and receipt.anonymous_name not in (".", "..", Path(self.spec.path).name)
            and not any(c in receipt.anonymous_name for c in ("/", "\0", "\r", "\n")),
            "anonymous-name",
        )
        for identity, links in (
            (receipt.before_identity, 0),
            (receipt.final_identity, 1),
        ):
            require(
                type(identity) is tuple
                and len(identity) == 9
                and all(type(part) is int and part >= 0 for part in identity),
                "receipt-identity",
            )
            atomic._private_identity(identity, links, len(self.spec.payload))
        require(
            receipt.before_identity[:5] == receipt.final_identity[:5], "receipt-inode"
        )
        self._final = attempt._Reader()
        item = self._final.file(Path(self.spec.path))
        require(
            type(item) is dict
            and tuple(item["identity"]) == receipt.final_identity
            and item["sha256"] == receipt.payload_sha256
            and self._final.raws[self.spec.path][0] == self.spec.payload,
            "final-file",
        )
        self._atomic_events(receipt)
        require(
            self._scan(after=True)
            == tuple(sorted((*self.spec.before_names, Path(self.spec.path).name))),
            "final-membership",
        )
        current = attempt._identity(os.fstat(self.fd))
        require(tuple(current[:5]) == self.parent_identity[:5], "parent-changed")
        node = self._parent.nodes[str(Path(self.spec.path).parent)]
        node["identity"], node["prefix"] = current, 5 if self.spec.shared else 9
        self._receipt = self._published_receipt = receipt
        self._receipt_raw = r.state.canonical(r.asdict(receipt))
        self.check_memberships()
        self.close_named()
        self.check_events()
        self._memory()
        self._enumerated = False
        self._successful = True
        return receipt

    @_poison_on_failure
    def check_memberships(self):
        require(not self._poisoned, "poisoned")
        require(not self.closed and self._receipt is not None, "not-published")
        expected = tuple(sorted((*self.spec.before_names, Path(self.spec.path).name)))
        require(self._scan(after=True) == expected, "final-membership")
        self._parent.check_memberships()
        if self._controls is not None:
            self._controls.check_memberships()
        self._final.check_memberships()
        self._enumerated = True

    @_poison_on_failure
    def close_named(self):
        require(not self._poisoned, "poisoned")
        require(not self.closed and self._enumerated, "membership-stage")
        self._parent.close_named()
        if self._controls is not None:
            self._controls.close_named()
        self._final.close_named()
        self._memory()

    @_poison_on_failure
    def check_events(self):
        require(not self._poisoned, "poisoned")
        require(not self.closed and self._receipt is not None, "not-published")
        self._parent.check_events()
        if self._controls is not None:
            self._controls.check_events()
        self._final.check_events()

    def release(self):
        if self._closed:
            return
        self._closed = True
        first = None
        for reader in (self._final, self._controls, self._parent):
            if reader is not None:
                try:
                    reader.release()
                except BaseException as error:
                    if first is None:
                        first = error
        if first is not None:
            raise first


@contextmanager
def _observe_control_publication(
    binding,
    intent_raw,
    intent_sha256,
    action,
    *,
    event_profile,
    complete_raw=None,
    complete_sha256=None,
    _selection=None,
):
    """Watch one derived destination; caller owns immutable old/data/current proofs."""
    require(
        type(event_profile) is str and event_profile == EVENT_PROFILE, "event-profile"
    )
    require(
        type(action) is str
        and action
        in ("finish-runtime", "record-intent", "publish-marker", "record-completion"),
        "action",
    )
    configuration = _configuration()
    if _selection is not None:
        require(type(_selection) is semantics.Selection, "selection")
        _selection._match(binding, intent_raw, intent_sha256)
    owner, binding_raw = r._binding(binding)
    intent = r._intent(owner, intent_raw, intent_sha256)
    spec = _spec(
        owner,
        intent,
        intent_raw,
        intent_sha256,
        action,
        complete_raw,
        complete_sha256,
        _selection,
    )
    publication = _Publication(spec, binding, owner, binding_raw, _selection)
    primary = None
    try:
        yield publication
        require(not publication._poisoned, "poisoned")
        require(
            publication._successful and publication.receipt is not None, "not-published"
        )
        if not publication._enumerated:
            publication.check_memberships()
        publication.close_named()
        r._close_binding(binding, owner, binding_raw)
        require(
            r.state.canonical(intent) == intent_raw
            and _configuration() == configuration,
            "input-memory",
        )
        publication.check_events()
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            publication.release()
        except BaseException:
            if primary is None:
                raise
            primary.add_note("secondary publication observer release failure")
    publication._memory()
    r._close_binding(binding, owner, binding_raw)
    require(
        r.state.canonical(intent) == intent_raw and _configuration() == configuration,
        "input-memory",
    )


def observe_control_publication(
    binding,
    intent_raw,
    intent_sha256,
    action,
    *,
    event_profile,
    complete_raw=None,
    complete_sha256=None,
):
    """Legacy semantic1 leaf; no checkpoint or fresh-current qualification."""
    return _observe_control_publication(
        binding,
        intent_raw,
        intent_sha256,
        action,
        event_profile=event_profile,
        complete_raw=complete_raw,
        complete_sha256=complete_sha256,
    )


def observe_control_publication_v2(
    *,
    binding,
    checkpoint,
    checkpoint_sha256,
    intent_raw,
    intent_sha256,
    contract_raw,
    contract_sha256,
    action,
    event_profile,
    complete_raw=None,
    complete_sha256=None,
):
    """Require selected semantic2 inputs before all four finite publications.

    The caller still supplies real leases, current/source/actor qualification,
    immutable-old/reference/database witnesses and successful outer closure.
    """
    selection = semantics.select(
        binding=binding,
        checkpoint=checkpoint,
        checkpoint_sha256=checkpoint_sha256,
        intent_raw=intent_raw,
        intent_sha256=intent_sha256,
        contract_raw=contract_raw,
        contract_sha256=contract_sha256,
    )
    return _observe_control_publication(
        binding,
        intent_raw,
        intent_sha256,
        action,
        event_profile=event_profile,
        complete_raw=complete_raw,
        complete_sha256=complete_sha256,
        _selection=selection,
    )
