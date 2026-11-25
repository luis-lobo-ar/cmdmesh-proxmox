"""Authenticated reference-ledger requests through an admitted local peer.

The caller owns guest, program, bind and process admission and lifecycle claims.
No application EX, host SQLite, credential replacement or automatic retry occurs.
"""

import hashlib
import json
import os
import re
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_state as state,
    unix_peer,
)


class LedgerApiError(ValueError):
    """Static protocol or credential failure, with no secret or response text."""


def require(value, code):
    if not value:
        raise LedgerApiError("persistence-ledger-api-" + code)


def fields(value, expected):
    require(type(value) is dict and set(value) == set(expected), "fields")


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate-key")
        result[key] = value
    return result


def _constant(unused):
    raise LedgerApiError("persistence-ledger-api-invalid-json")


def _decode(raw):
    try:
        return json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
    except (ValueError, RecursionError, UnicodeError):
        raise LedgerApiError("persistence-ledger-api-invalid-json") from None


def _identity(value):
    fields(value, {"instance_id", "config_sha256", "application_uid"})
    require(
        state.matches(r"[a-f0-9]{32}", value["instance_id"])
        and state.matches(r"[a-f0-9]{64}", value["config_sha256"])
        and type(value["application_uid"]) is int
        and 0 <= value["application_uid"] < 65536,
        "identity",
    )


def _metadata(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _credential(directory, binding, identity):
    parent = os.fstat(directory)
    require(
        stat.S_ISDIR(parent.st_mode)
        and stat.S_IMODE(parent.st_mode) == 0o700
        and (parent.st_uid, parent.st_gid) == (binding.uid, binding.gid),
        "configuration-directory",
    )
    descriptor = os.open(
        "application.json",
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=directory,
    )
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        require(
            stat.S_ISREG(before.st_mode)
            and stat.S_IMODE(before.st_mode) == 0o600
            and (before.st_uid, before.st_gid) == (binding.uid, binding.gid)
            and before.st_nlink == 1
            and 0 < before.st_size <= 4096,
            "configuration-file",
        )
        raw = source.read(4097)
        require(
            hashlib.sha256(raw).hexdigest() == identity["config_sha256"]
            and _metadata(os.fstat(source.fileno()))
            == _metadata(before)
            == _metadata(
                os.stat("application.json", dir_fd=directory, follow_symlinks=False)
            )
            and _metadata(os.fstat(directory)) == _metadata(parent),
            "configuration-changed",
        )
    value = _decode(raw)
    fields(value, {"schema_version", "instance_id", "uid", "token"})
    require(
        type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and type(value["uid"]) is int
        and value["uid"] == identity["application_uid"]
        and value["instance_id"] == identity["instance_id"]
        and state.matches(r"[a-f0-9]{64}", value["token"]),
        "configuration-identity",
    )
    return value["token"], (_metadata(parent), _metadata(before))


def _call(parent, binding, config, identity, command):
    _identity(identity)
    require(type(binding) is unix_peer.ProcessIdentity, "binding")
    original = []

    def payload():
        token, seal = _credential(config, binding, identity)
        require(not original, "duplicate-dispatch")
        original.append(seal)
        return state.canonical({**command, "token": token}) + b"\n"

    try:
        raw = unix_peer.exchange(parent, "api.sock", binding, payload)
        require(len(original) == 1, "credential-not-read")
        token, seal = _credential(config, binding, identity)
        require(seal == original[0], "configuration-changed")
        result = _decode(raw)
        require(
            token.encode() not in state.canonical(result),
            "response-contains-credential",
        )
        return result
    except (OSError, unix_peer.PeerError, UnicodeError):
        raise LedgerApiError("persistence-ledger-api-unavailable") from None


def validate_read(value, instance_id):
    fields(value, {"outcome", "instance_id", "entries"})
    require(
        value["outcome"] == "read" and value["instance_id"] == instance_id,
        "response-identity",
    )
    entries = value["entries"]
    require(type(entries) is list and 1 <= len(entries) <= 4096, "records")
    sequence = 0
    operations = set()
    rows = []
    for item in entries:
        fields(item, {"sequence", "operation_id", "value"})
        require(
            type(item["sequence"]) is int
            and sequence < item["sequence"] < 2**63
            and state.matches(r"[a-f0-9]{32}", item["operation_id"])
            and item["operation_id"] not in operations
            and type(item["value"]) is str,
            "records",
        )
        try:
            require(len(item["value"].encode()) <= 65536, "records")
        except UnicodeError:
            raise LedgerApiError("persistence-ledger-api-records") from None
        sequence = item["sequence"]
        operations.add(item["operation_id"])
        rows.append([sequence, item["operation_id"], item["value"]])
    require(any(row[2] for row in rows), "records")
    encoded = state.canonical(rows)
    require(len(encoded) <= 1048576, "records-limit")
    return {
        "instance_id": instance_id,
        "entries": entries,
        "records_sha256": state.sha256(encoded),
        "record_count": len(rows),
    }


def read(parent, binding, config, identity):
    """Read through the original credential, never through host-side SQLite."""
    result = _call(parent, binding, config, identity, {"action": "read"})
    return validate_read(result, identity["instance_id"])


def append(parent, binding, config, identity, operation_id, value):
    """Attempt one idempotent append; errors must not be automatically retried."""
    require(
        state.matches(r"[a-f0-9]{32}", operation_id) and type(value) is str,
        "append-input",
    )
    try:
        require(len(value.encode()) <= 65536, "append-input")
    except UnicodeError:
        raise LedgerApiError("persistence-ledger-api-append-input") from None
    result = _call(
        parent,
        binding,
        config,
        identity,
        {"action": "append", "operation_id": operation_id, "value": value},
    )
    fields(result, {"outcome", "sequence"})
    require(
        result["outcome"] in ("committed", "unchanged")
        and type(result["sequence"]) is int
        and 0 < result["sequence"] < 2**63,
        "append-not-confirmed",
    )
    return result
