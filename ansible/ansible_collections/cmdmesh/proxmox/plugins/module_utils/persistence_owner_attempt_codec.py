"""Pure semantic replay of selected attempt bytes; no observer authenticity claim."""

import base64
from pathlib import Path
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_attempt as attempt,
)

r, profile = attempt.r, attempt.profile
_FIELDS = {
    "document_type",
    "schema_version",
    "binding",
    "accepted_intent_sha256",
    "expected_publication_protocol",
    "status",
    "runtime_profile",
    "blocked_reasons",
    "files",
    "directories",
    "directory_closure_fields",
    "ancestors",
    "absent",
    "memberships",
    "membership_policy",
    "unsafe_entries",
    "unknown_entries",
    "readonly",
    "forensic_only",
    "candidate_only",
    "publication_authorized",
    "original_request_fenced",
    "native_action_dispatched",
    "metadata_resolution_recorded",
    "successor_native_admission_authorized",
}
_FIELDS_V2 = _FIELDS | {
    "checkpoint_sha256",
    "publication_contract_sha256",
    "completion_schema_version",
    "completion_disposition",
}


def require(value, code):
    r.require(value, "attempt-codec-" + code)


def _path(value):
    require(type(value) is str and 0 < len(value) <= 4096 and "\0" not in value, "path")
    path = Path(value)
    require(
        path.is_absolute() and str(path) == value and ".." not in path.parts, "path"
    )
    require(attempt._WALK_ROOT in (path, *path.parents), "anchor")
    return path


def _identity(value, *, ancestor=False, directory=False):
    require(type(value) is list and len(value) == (5 if ancestor else 9), "identity")
    require(all(type(part) is int and part >= 0 for part in value), "identity")
    require(value[0] > 0 and value[1] > 0, "identity")
    if ancestor:
        require(
            stat.S_ISDIR(value[2])
            and not value[2] & 0o22
            and value[3:5] == [r.legacy.ROOT_UID, r.legacy.ROOT_UID],
            "ancestor",
        )
    elif directory:
        r._identity(value[:5], directory=True)
        require(value[5] >= 1, "directory-links")
    else:
        r._identity(value)


class _MemoryReader:
    """Rebuild only facts actually requested by the source-defined layout."""

    def __init__(self, body, owner, intent):
        old = r.legacy.RUNTIME_ROOT / owner.pair_key
        pair = profile.RUNTIME_ROOT / owner.pair_key
        self.file_paths = {str(old / rel) for rel in intent["basis"]["files"]}
        self.file_paths.update(
            map(
                str,
                (
                    r.legacy.RUNTIME_ROOT / "runtime.json",
                    old / profile.MARKER,
                    profile.RUNTIME_ROOT / "runtime.json",
                    pair / "intent.json",
                    pair / "complete.json",
                ),
            )
        )
        self.directory_paths = {
            str(old / rel) for rel in intent["basis"]["directories"]
        }
        self.directory_paths.update(intent["shared_directories"])
        self.directory_paths.update(
            map(str, (r.legacy.RUNTIME_ROOT, profile.RUNTIME_ROOT, pair))
        )
        ancestors = set()
        for name in self.file_paths | self.directory_paths:
            ancestors.update(
                str(p)
                for p in _path(name).parents
                if attempt._WALK_ROOT in (p, *p.parents)
            )
        self.body = body
        self.nodes, self.members, self.absent, self.raws, self.observed = (
            {},
            {},
            {},
            {},
            {},
        )
        self.payloads = {}
        self.children = {}
        for section, allowed in (
            ("files", self.file_paths),
            ("directories", self.directory_paths),
            ("ancestors", ancestors),
            ("memberships", self.directory_paths),
            ("directory_closure_fields", self.directory_paths),
            ("membership_policy", self.directory_paths),
        ):
            value = body[section]
            require(type(value) is dict and len(value) <= len(allowed), "table-budget")
            require(
                set(value) <= allowed and all(_path(p) for p in value), "table-path"
            )
        require(not set(body["ancestors"]) & set(body["directories"]), "directory-role")
        for child in set(body["files"]) | set(body["directories"]):
            path = Path(child)
            self.children.setdefault(str(path.parent), set()).add(path.name)
        for value in body["ancestors"].values():
            _identity(value, ancestor=True)
        for value in body["directories"].values():
            _identity(value, directory=True)
        absent = body["absent"]
        require(
            type(absent) is list
            and len(absent) <= len(self.file_paths | self.directory_paths),
            "absence-budget",
        )
        require(
            all(type(p) is str for p in absent)
            and absent == sorted(set(absent))
            and set(absent) <= self.file_paths | self.directory_paths,
            "absence",
        )
        require(
            not set(absent) & (set(body["files"]) | set(body["directories"])),
            "presence-conflict",
        )
        for path, names in body["memberships"].items():
            require(
                type(names) is list and len(names) <= attempt.NAME_LIMIT, "name-budget"
            )
            require(
                all(
                    type(n) is str
                    and 0 < len(n) <= 255
                    and n not in (".", "..")
                    and "/" not in n
                    and "\0" not in n
                    for n in names
                ),
                "member-name",
            )
            require(names == sorted(set(names)), "member-order")
        for value in body["directory_closure_fields"].values():
            require(type(value) is int and value in (5, 9), "directory-policy")
        for value in body["membership_policy"].values():
            require(
                type(value) is str and value in ("exact", "selected-pair-and-unknowns"),
                "membership-policy",
            )
        total = 0
        for path, item in body["files"].items():
            r.state.keys(item, {"identity", "sha256", "raw_base64"})
            _identity(item["identity"])
            r.state.digest(item["sha256"])
            limit = min(
                (
                    r.MARKER_LIMIT
                    if path == str(old / profile.MARKER)
                    else attempt.FILE_LIMIT
                ),
                attempt.AGGREGATE_LIMIT - total,
            )
            encoded = item["raw_base64"]
            size = item["identity"][6]
            require(
                type(encoded) is str
                and size <= limit
                and len(encoded) == ((size + 2) // 3) * 4,
                "read-budget",
            )
            try:
                raw = base64.b64decode(encoded, validate=True)
            except (ValueError, UnicodeError) as error:
                raise ValueError(
                    "persistence-owner-retirement-attempt-codec-base64"
                ) from error
            require(
                len(raw) == size
                and len(raw) <= limit
                and base64.b64encode(raw).decode() == encoded
                and r.state.sha256(raw) == item["sha256"],
                "file-bytes",
            )
            total += size
            self.payloads[path] = raw

    def _directory(self, path, *, private=False, full=False):
        path = _path(str(path))
        key = str(path)
        if key not in self.nodes:
            if path != attempt._WALK_ROOT:
                self._directory(path.parent)
            identity = self.body["directories"].get(
                key, self.body["ancestors"].get(key)
            )
            require(identity is not None, "directory-fact")
            self.nodes[key] = dict(identity=identity, prefix=5, kind="directory")
        node = self.nodes[key]
        require(node["kind"] == "directory", "node-role")
        require(
            not private or stat.S_IMODE(node["identity"][2]) == 0o700,
            "private-directory",
        )
        if private or full:
            require(
                key in self.body["directories"] and len(node["identity"]) == 9,
                "private-fact",
            )
        if full:
            node["prefix"] = 9
        return key

    def directory_identity(self, path, *, private=False):
        return self.nodes[self._directory(path, private=private)]["identity"]

    def _entry(self, path):
        key = str(path)
        self._directory(path.parent)
        if key in self.body["absent"]:
            self.absent[key] = True
            return None
        require(
            key in self.body["files"] or key in self.body["directories"], "entry-fact"
        )
        return key

    def directory(self, path, *, shared=False):
        key = self._entry(path)
        if key is None:
            return None
        require(key in self.body["directories"], "directory-role")
        return self._directory(path, private=True, full=not shared)

    def file(self, path, limit=attempt.FILE_LIMIT):
        key = self._entry(path)
        if key is None:
            return None
        require(key in self.payloads and key not in self.nodes, "file-role")
        raw = self.payloads[key]
        require(len(raw) <= limit, "file-limit")
        item = self.body["files"][key]
        self.nodes[key] = dict(identity=item["identity"], prefix=9, kind="file")
        self.raws[key] = raw, item["sha256"]
        return item

    def membership(self, path, *, shared=False):
        key = str(path)
        require(
            key in self.body["memberships"] and key in self.nodes, "membership-fact"
        )
        names = self.body["memberships"][key]
        require(set(names) == self.children.get(key, set()), "membership-facts")
        found = {}
        for name in names:
            child = str(path / name)
            if child in self.body["files"]:
                found[name] = self.body["files"][child]["identity"]
            else:
                require(child in self.body["directories"], "member-fact")
                found[name] = self.body["directories"][child]
        previous = self.members.setdefault(key, (shared, tuple(names)))
        require(previous == (shared, tuple(names)), "membership-conflict")
        return found


def _validate_capture(
    binding,
    intent_raw,
    intent_sha256,
    capture_raw,
    capture_sha256,
    optional_selection=None,
):
    """Check selected JSON consistency; prove no exporter provenance or live truth."""
    require(
        optional_selection is None
        or type(optional_selection) is attempt.semantics.Selection,
        "semantic-selection",
    )
    if optional_selection is not None:
        optional_selection._match(binding, intent_raw, intent_sha256)
    expected_profile = r.state.canonical(profile.RUNTIME)
    expected_paths = (
        profile.RUNTIME_ROOT,
        profile.MARKER,
        profile.PROTOCOL,
        r.RUNTIME_ROOT,
        r.legacy.RUNTIME_ROOT,
        attempt._WALK_ROOT,
    )
    require(
        profile.RUNTIME_ROOT == r.RUNTIME_ROOT and profile.MARKER == r.MARKER,
        "profile-path",
    )
    owner, binding_raw = r._binding(binding)
    intent = r._intent(owner, intent_raw, intent_sha256)
    body = r._decode(capture_raw, capture_sha256, attempt.OUTPUT_LIMIT)
    r.state.keys(body, _FIELDS if optional_selection is None else _FIELDS_V2)
    require(
        body["blocked_reasons"] == []
        and body["unsafe_entries"] == {}
        and body["unknown_entries"] == {}
        and body["status"] != "blocked",
        "blocked",
    )
    reader = _MemoryReader(body, owner, intent)
    reconstructed = (
        attempt._collect(reader, owner, intent, intent_raw, intent_sha256)
        if optional_selection is None
        else attempt._collect(
            reader, owner, intent, intent_raw, intent_sha256, optional_selection
        )
    )
    require(r.state.canonical(reconstructed) == capture_raw, "reconstruction")
    r._close_binding(binding, owner, binding_raw)
    require(
        r.state.canonical(intent) == intent_raw
        and r.state.canonical(body) == capture_raw,
        "decoded-memory-changed",
    )
    require(
        r.state.canonical(profile.RUNTIME) == expected_profile
        and expected_paths
        == (
            profile.RUNTIME_ROOT,
            profile.MARKER,
            profile.PROTOCOL,
            r.RUNTIME_ROOT,
            r.legacy.RUNTIME_ROOT,
            attempt._WALK_ROOT,
        ),
        "profile-changed",
    )
    require(
        r.state.sha256(intent_raw) == intent_sha256
        and r.state.sha256(capture_raw) == capture_sha256,
        "input-changed",
    )
    if optional_selection is not None:
        optional_selection.validate()
        require(
            r.state.canonical(reconstructed) == capture_raw
            and r.state.canonical(body) == capture_raw,
            "semantic-memory-changed",
        )
    return reconstructed


def validate_capture(binding, intent_raw, intent_sha256, capture_raw, capture_sha256):
    """Replay the unchanged schema1 forensic contract."""
    return _validate_capture(
        binding, intent_raw, intent_sha256, capture_raw, capture_sha256
    )


def validate_capture_v2(
    *,
    binding,
    checkpoint,
    checkpoint_sha256,
    intent_raw,
    intent_sha256,
    contract_raw,
    contract_sha256,
    capture_raw,
    capture_sha256,
):
    """Replay explicit semantic2 selection; never authenticate exporter or leases."""
    selected = attempt.semantics.select(
        binding=binding,
        checkpoint=checkpoint,
        checkpoint_sha256=checkpoint_sha256,
        intent_raw=intent_raw,
        intent_sha256=intent_sha256,
        contract_raw=contract_raw,
        contract_sha256=contract_sha256,
    )
    return _validate_capture(
        binding, intent_raw, intent_sha256, capture_raw, capture_sha256, selected
    )
