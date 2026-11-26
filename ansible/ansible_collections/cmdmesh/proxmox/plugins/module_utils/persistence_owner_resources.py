"""Fixed owner IO resources, borrowing already held real executor leases.

This leaf performs Linux FD/inotify operations, not SQL, native commands, lock
acquisition or publication. It does not authenticate source execution/current.
For publish-marker, the caller MUST overlap the fresh attempt inspector and
the semantic2 planned marker witness before C1 and retain that witness through
E2. Projected root membership here alone cannot detect transient unknown root
children or authenticate the intentional marker. Original files/slots never
relax. Other actions retain an immutable exact old-root observation.
"""

from contextlib import contextmanager
import os
from pathlib import Path
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_attempt as attempt,
    persistence_owner_current as current,
    persistence_owner_semantics as semantics,
)

r, runtime = semantics.r, current.runtime
ACTIONS = frozenset(
    {
        "begin",
        "finish-runtime",
        "record-intent",
        "publish-marker",
        "record-completion",
        "requalify-complete",
        "inspect",
    }
)


def require(value, code):
    r.require(value, "resources-" + code)


def _expected(value):
    if value is None:
        return None
    require(
        type(value) is list
        and len(value) in (5, 9)
        and all(type(item) is int and item >= 0 for item in value),
        "expected-identity",
    )
    return value.copy()


def _application_ids(policy):
    return tuple(
        policy["mapping"]["offset"] + policy["mapping"][key] for key in ("uid", "gid")
    )


class _Seal(attempt._Reader):
    """Use the existing immutable FD observer, with fixed role projections."""

    def __init__(self, pair_key):
        super().__init__()
        self.pair_key = pair_key
        self.projected = {}
        self._held = None
        self._poisoned = False

    @property
    def poisoned(self):
        return self._poisoned

    def _check(self, method):
        try:
            require(not self._poisoned, "seal-poisoned")
            return method()
        except BaseException:
            self._poisoned = True
            raise

    def exact_directory(self, path, names, *, private, expected=None):
        path = Path(path)
        require(
            type(names) in (list, tuple, set) and 0 < len(names) <= attempt.NAME_LIMIT,
            "members",
        )
        require(
            all(
                type(name) is str and name not in {"", ".", ".."} and "/" not in name
                for name in names
            ),
            "members",
        )
        fd = self._directory(path, private=private, full=True)
        first = self.nodes[str(path)]["identity"]
        expected = _expected(expected)
        if expected is not None:
            require(first[: len(expected)] == expected, "directory-baseline")
        self._watch(fd, ("owned", ""))
        self.membership(path)
        require(self.members[str(path)][1] == tuple(sorted(names)), "membership")

    def control_file(self, path, expected):
        r.state.digest(expected["sha256"])
        identity = _expected(expected["identity"])
        require(len(identity) == 9, "file-identity")
        item = self.file(Path(path))
        require(
            type(item) is dict
            and item["identity"] == identity
            and item["sha256"] == expected["sha256"],
            "file-baseline",
        )

    def check_memberships(self):
        def check():
            super(_Seal, self).check_memberships()
            for path, names in self.projected.items():
                found = tuple(sorted(self._scan(Path(path), False)))
                require(found in names, "projected-membership")

        self._check(check)

    def close_named(self):
        self._check(super().close_named)

    def check_events(self):
        self._check(super().check_events)

    def freeze_fds(self):
        self._held = tuple(
            dict.fromkeys([*(node["fd"] for node in self.nodes.values()), self.event])
        )

    def release(self):
        if self.closed:
            return
        self.closed = True
        held = (
            self._held
            if self._held is not None
            else tuple(
                dict.fromkeys(
                    [*(node["fd"] for node in self.nodes.values()), self.event]
                )
            )
        )
        failed = None
        for fd in held:
            try:
                os.close(fd)
            except BaseException as error:
                if failed is None:
                    failed = error
        self.nodes.clear()
        if failed is not None:
            self._poisoned = True
            raise failed


def _entry(checkpoint, value):
    r.state.keys(
        value, {"phase", "host", "guest", "reference", "root", "ownership", "stopped"}
    )
    phase = value["phase"]
    require(type(phase) is str and phase in {"os_quiesced", "stopped"}, "phase")
    request, image, expected = current._authority(checkpoint)
    guard, _, _ = runtime.load_profile(request, image)
    current._host(request, value["host"])
    r.observe.validate_guest(request["policy"], value["guest"])
    require(
        value["guest"]["status"]
        == ("running" if phase == "os_quiesced" else "stopped"),
        "guest-state",
    )
    current.same(value["guest"]["config"], image["config"], "guest-config")
    current.same(
        value["root"],
        {key: image["rootfs"][key] for key in ("path", "identity", "uuid")},
        "root",
    )
    guard.validate_ownership(request["policy"], value["ownership"])
    current.same(
        guard.ownership_seal(value["ownership"]),
        guard.ownership_seal(expected["retained"]["ownership"]),
        "ownership",
    )
    validator = (
        runtime.validate_reference
        if phase == "os_quiesced"
        else runtime.validate_stopped_reference
    )
    validator(request, value["reference"])
    current.same(
        value["reference"]["files"], expected["reference"]["files"], "reference-files"
    )
    if phase == "os_quiesced":
        require(value["stopped"] is None, "unexpected-stopped")
    else:
        r.state.keys(value["stopped"], {"lxc_state", "cgroup", "prior_fence"})
        require(
            value["stopped"]["lxc_state"] == "STOPPED"
            and type(value["stopped"]["prior_fence"]) is str
            and value["stopped"]["prior_fence"]
            in {"prior-init-absent", "prior-init-reused", "manager-epoch-changed"},
            "stopped",
        )
        semantics.codec.admission._cgroup(value["stopped"]["cgroup"])
    return request, guard


def _reference(reader, request, entry, guard):
    for path, expected in entry["reference"]["files"].items():
        reader.control_file(Path(path), expected)
    for item in entry["reference"]["units"].values():
        reader.exact_directory(
            Path(item["DropInPaths"][0]).parent,
            item["directory_membership"],
            private=False,
        )
    ownership = entry["ownership"]
    owner = Path(guard.owner_path(request["policy"]))
    reader.control_file(owner, ownership["file"])
    reader.exact_directory(
        owner.parent,
        {"owner.json"},
        private=True,
        expected=ownership["directory"]["identity"],
    )
    for name, unit in ownership["retired"]["units"].items():
        preserved, denial = (
            Path(path) for path in guard.retired_paths(request["policy"], name)
        )
        reader.exact_directory(
            preserved.parent, unit["directory_membership"], private=False
        )
        reader.control_file(preserved, unit["preserved_file"])
        reader.control_file(denial, unit["denial_file"])


def _database(reader, request, checkpoint):
    policy = request["policy"]
    expected = checkpoint["completion"]["runtime"]["retained"]["application"][
        "database"
    ]
    r.state.keys(
        expected, {"uid", "gid", "mode", "inode", "bytes", "regular", "sqlite_header"}
    )
    require(
        all(
            type(expected[key]) is int and expected[key] >= 0
            for key in ("uid", "gid", "mode", "inode", "bytes")
        )
        and expected["regular"] is True
        and expected["sqlite_header"] is True
        and expected["mode"] == 0o600
        and expected["inode"] > 0
        and 0 < expected["bytes"] <= 16777216,
        "database-metadata",
    )
    uid, gid = _application_ids(policy)
    require((expected["uid"], expected["gid"]) == (uid, gid), "database-owner")
    directory = Path(policy["datasets"]["data"]["mountpoint"])
    parent = reader._directory(directory.parent)
    fd = os.open(
        directory.name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=parent,
    )
    try:
        first = attempt._identity(os.fstat(fd))
        require(
            first[2] == stat.S_IFDIR | 0o700
            and first[3:5] == [uid, gid]
            and first == attempt._identity(directory.lstat()),
            "database-directory",
        )
        require(str(directory) not in reader.nodes, "duplicate-database-directory")
        reader.nodes[str(directory)] = dict(
            fd=fd, identity=first, prefix=9, kind="directory"
        )
    except BaseException:
        os.close(fd)
        raise
    reader._watch(fd, ("owned", ""))
    path = directory / "ledger.sqlite3"
    first = reader.entry(path)
    require(
        first is not None
        and first[2] == stat.S_IFREG | 0o600
        and first[3:6] == [uid, gid, 1]
        and first[1] == expected["inode"]
        and first[6] == expected["bytes"],
        "database-file",
    )
    fd = os.open(
        path.name,
        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=reader.nodes[str(directory)]["fd"],
    )
    try:
        require(attempt._identity(os.fstat(fd)) == first, "database-race")
        reader._watch(fd, ("file", ""))
        reader.nodes[str(path)] = dict(fd=fd, identity=first, prefix=9, kind="file")
    except BaseException:
        os.close(fd)
        raise
    # This selected data role supports precisely one DB, never sidecar adoption.
    reader.membership(directory)
    require(
        reader.members[str(directory)][1] == ("ledger.sqlite3",), "database-membership"
    )


def _old(reader, selection, intent, action):
    owner = selection._private_binding
    root = Path(r.legacy.RUNTIME_ROOT / owner.pair_key)
    for path, expected in intent["shared_directories"].items():
        reader._directory(Path(path), private=True)
        require(
            reader.nodes[str(Path(path))]["identity"][:5] == _expected(expected),
            "legacy-parent",
        )
    shared = Path(r.legacy.RUNTIME_ROOT)
    reader._watch(reader.nodes[str(shared)]["fd"], ("shared", owner.pair_key))
    reader.membership(shared, shared=True)
    require(
        reader.members[str(shared)][1]
        == tuple(sorted(("runtime.json", owner.pair_key))),
        "legacy-shared-membership",
    )
    reader.control_file(
        Path(r.legacy.RUNTIME_ROOT / "runtime.json"), intent["shared_runtime"]
    )
    raw_map = {}
    for relative, expected in intent["basis"]["directories"].items():
        path = root / relative
        if relative == "" and action == "publish-marker":
            reader._directory(path, private=True)
            require(
                reader.nodes[str(path)]["identity"][:5] == _expected(expected),
                "legacy-directory",
            )
            names = tuple(sorted(intent["basis"]["members"][relative]))
            require(
                tuple(sorted(reader._scan(path, False))) == names, "legacy-membership"
            )
            reader.projected[str(path)] = (
                names,
                tuple(sorted((*names, attempt.profile.MARKER))),
            )
        else:
            names = list(intent["basis"]["members"][relative])
            if not relative:
                present = reader.entry(path / attempt.profile.MARKER)
                if action in {"record-completion", "requalify-complete"}:
                    require(present is not None, "marker-missing")
                elif action != "inspect":
                    require(present is None, "marker-unexpected")
                if present is not None:
                    marker = r.state.canonical(
                        r._marker(owner, selection._intent_sha256)
                    )
                    item = reader.file(path / attempt.profile.MARKER, r.MARKER_LIMIT)
                    require(
                        type(item) is dict
                        and reader.raws[str(path / attempt.profile.MARKER)][0]
                        == marker,
                        "marker",
                    )
                    names.append(attempt.profile.MARKER)
            reader.exact_directory(path, names, private=True, expected=expected)
    for relative, expected in intent["basis"]["files"].items():
        path = root / relative
        reader.control_file(path, expected)
        raw_map[relative] = reader.raws[str(path)][0]
    r._validate_legacy(
        owner, intent["basis"], raw_map, intent["anchor"], intent["caller_evidence"]
    )


def _seal_view(seal, *, released=False):
    nodes = {}
    for path, node in (() if released else seal.nodes.items()):
        require(
            type(node["identity"]) is list
            and all(type(item) is int for item in node["identity"])
            and type(node["fd"]) is int,
            "seal-type",
        )
        nodes[path] = (node["fd"], node["kind"], node["prefix"], node["identity"])
    raw = {}
    for path, value in seal.raws.items():
        require(
            type(value) is tuple
            and len(value) == 2
            and type(value[0]) is bytes
            and type(value[1]) is str,
            "raw-type",
        )
        raw[path] = (r.state.sha256(value[0]), value[1])
    return r.state.canonical(
        dict(
            nodes=nodes,
            observed=seal.observed,
            absent=seal.absent,
            members=seal.members,
            projected=seal.projected,
            watches=seal.watches,
            raw=raw,
            event=seal.event,
            held=seal._held,
        )
    )


def _poison(method):
    def checked(self, *args, **kwargs):
        try:
            require(not self._poisoned, "poisoned")
            return method(self, *args, **kwargs)
        except BaseException:
            self._poisoned = True
            raise

    return checked


class _Resources:
    def __init__(self, selection, entry, action):
        self._selection = self._expected_selection = selection
        self._entry = entry
        self._entry_raw = r.state.canonical(entry)
        self._private_entry = r.observe.decode(self._entry_raw)
        self._references = (entry, self._private_entry)
        self._action = action
        self._fixed_action = action
        self._process = os.getpid()
        self._input_snapshot = (
            selection,
            entry,
            self._private_entry,
            self._entry_raw,
            action,
            self._process,
        )
        self._poisoned = self.closed = self._enumerated = False
        self._seals = ()
        self._views = None
        self._seal_snapshot = None
        request, guard = _entry(selection._private_checkpoint, self._private_entry)
        intent = r._intent(
            selection._private_binding, selection._intent_raw, selection._intent_sha256
        )
        try:
            self.old = _Seal(selection._private_binding.pair_key)
            self._seals += (self.old,)
            self.reference = _Seal(selection._private_binding.pair_key)
            self._seals += (self.reference,)
            self.database = _Seal(selection._private_binding.pair_key)
            self._seals += (self.database,)
            _database(self.database, request, selection._private_checkpoint)
            _reference(self.reference, request, self._private_entry, guard)
            _old(self.old, selection, intent, action)
            require(
                sum(seal.budget for seal in self._seals) <= 33554432, "aggregate-budget"
            )
            for seal in self._seals:
                seal.freeze_fds()
            self._views = tuple(_seal_view(seal) for seal in self._seals)
            self._seal_snapshot = (
                self._seals,
                self._views,
                tuple(_seal_view(seal, released=True) for seal in self._seals),
            )
            self.check_memberships()
            self.close_named()
            self.check_events()
            self._enumerated = False
        except BaseException as error:
            try:
                self.release()
            except BaseException:
                error.add_note("secondary owner resource setup release failure")
            raise

    def _fast_memory(self, *, released=False):
        require(
            self._selection is self._input_snapshot[0]
            and self._entry is self._input_snapshot[1]
            and self._private_entry is self._input_snapshot[2]
            and type(self._entry_raw) is bytes
            and self._entry_raw == self._input_snapshot[3]
            and self._action == self._input_snapshot[4]
            and self._process == self._input_snapshot[5],
            "input-snapshot",
        )
        require(
            os.getpid() == self._process
            and self._selection is self._expected_selection
            and self._action == self._fixed_action
            and (self._entry, self._private_entry) == self._references
            and self._entry is self._references[0]
            and self._private_entry is self._references[1],
            "input-reference",
        )
        for value in self._input_snapshot[1:3]:
            semantics.codec.admission._json(value)
            require(r.state.canonical(value) == self._entry_raw, "entry-memory")
        require(
            self._seals is self._seal_snapshot[0]
            and self._views is self._seal_snapshot[1]
            and all(
                value is fixed
                for value, fixed in zip(
                    (self.old, self.reference, self.database), self._seal_snapshot[0]
                )
            ),
            "seal-reference",
        )
        require(
            not any(seal.poisoned for seal in self._seal_snapshot[0]), "seal-poisoned"
        )
        if not released:
            require(
                self._views
                == tuple(_seal_view(seal) for seal in self._seal_snapshot[0]),
                "seal-memory",
            )
        else:
            require(
                all(seal.closed for seal in self._seal_snapshot[0]), "seal-not-released"
            )
            require(
                self._seal_snapshot[2]
                == tuple(
                    _seal_view(seal, released=True) for seal in self._seal_snapshot[0]
                ),
                "released-seal-memory",
            )

    def _memory(self, *, released=False):
        self._fast_memory(released=released)
        # Full semantic reconstruction is pre-event only. Resource-exit closure
        # is immutable memory closure, never another public validation callback.
        if not released:
            self._selection.validate()
        self._selection._memory()
        self._fast_memory(released=released)

    @_poison
    def check_memberships(self):
        require(not self.closed, "released")
        self._memory()
        # Do every scan before any named metadata or event closure.
        for seal in self._seals:
            seal.check_memberships()
        self._enumerated = True
        self._memory()

    @_poison
    def close_named(self):
        require(not self.closed and self._enumerated, "membership-stage")
        self._memory()
        joined = {}
        for seal in self._seals:
            for path, node in seal.nodes.items():
                if path in joined:
                    prior = joined[path]
                    prefix = min(prior["prefix"], node["prefix"])
                    require(
                        prior["kind"] == node["kind"]
                        and prior["identity"][:prefix] == node["identity"][:prefix],
                        "seal-conflict",
                    )
                else:
                    joined[path] = node
        for seal in self._seals:
            seal.close_named()
        self._memory()

    @_poison
    def check_events(self):
        require(not self.closed and self._enumerated, "membership-stage")
        self._memory()
        for seal in self._seals:
            seal.check_events()
        self._fast_memory()

    def release(self):
        if self.closed:
            return
        self.closed = True
        first = None
        owned = self._seals if self._seal_snapshot is None else self._seal_snapshot[0]
        for seal in reversed(owned):
            try:
                seal.release()
            except BaseException as error:
                self._poisoned = True
                if first is None:
                    first = error
        if first is not None:
            raise first


@contextmanager
def hold_owner_resources(*, selection, entry, action):
    """Arm fixed resources BEFORE C1; caller owns true pair/native/app leases.

    No success, permission or full root-event coverage follows from this leaf.
    Caller runs all joined membership scans before named checks/events, and
    keeps the fixed planned marker witness overlapping through E2 if needed.
    """
    require(type(selection) is semantics.Selection, "selection")
    require(type(action) is str and action in ACTIONS, "action")
    selection.validate()
    semantics.codec.admission._json(entry)
    held = _Resources(selection, entry, action)
    primary = None
    try:
        yield held
        require(not held.closed and not held._poisoned, "poisoned-or-released")
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
            primary.add_note("secondary owner resource release failure")
    held._memory(released=True)
    require(not held._poisoned, "poisoned")
