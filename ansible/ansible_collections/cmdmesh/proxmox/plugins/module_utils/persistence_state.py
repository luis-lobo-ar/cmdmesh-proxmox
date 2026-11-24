"""Fixed reference-persistence data contracts; no collection or mutation.

A structurally valid manifest is not trusted. load_manifest requires a digest
retained separately in the trusted controller's completed backup receipt.
"""

import hashlib
import json
import re

ROLES = {"data", "config"}
DOCUMENT = "cmdmesh.proxmox.persistence.backup-manifest"
MAX_MANIFEST_BYTES = 1048576
MAPPING = {"offset": 100000, "length": 65536, "uid": 1100, "gid": 1100}


class PersistenceError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(value, code="persistence-invalid-manifest"):
    if not value:
        raise PersistenceError(code)


def keys(value, fields):
    require(type(value) is dict and set(value) == set(fields))


def matches(pattern, value):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def integer(value, minimum, maximum):
    require(type(value) is int and minimum <= value <= maximum)


def digest(value, size=64):
    require(matches(r"[a-f0-9]{" + str(size) + "}", value))


def decimal(value):
    require(matches(r"[1-9][0-9]{0,19}", value) and int(value) < 2**64)


def canonical(value):
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    except (TypeError, ValueError, RecursionError):
        raise PersistenceError("persistence-invalid-json") from None


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def source_identity(value):
    keys(value, {"selector", "host_profile", "owner_tag", "generation_tag"})
    selector = value["selector"]
    keys(selector, {"origin", "node", "kind", "vmid"})
    require(
        all(
            matches(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", selector[k])
            for k in ("origin", "node")
        )
    )
    require(selector["kind"] == "proxmox.lxc")
    integer(selector["vmid"], 100, 999999999)
    keys(
        value["host_profile"],
        {"machine_id_sha256", "ca_certificate_sha256", "leaf_certificate_sha256"},
    )
    for fingerprint in value["host_profile"].values():
        digest(fingerprint)
    require(matches(r"cmdmesh-own-[a-f0-9]{32}", value["owner_tag"]))
    require(matches(r"cmdmesh-gen-[a-f0-9]{32}", value["generation_tag"]))


def pair_key(datasets):
    """One lock identity for the retained pair, independent of any CT VMID."""
    keys(datasets, ROLES)
    guids = []
    for item in datasets.values():
        require(type(item) is dict and "guid" in item)
        decimal(item["guid"])
        guids.append(item["guid"])
    require(len(set(guids)) == 2, "persistence-shared-dataset")
    return sha256(canonical(sorted(guids)))


def validate_manifest(value):
    keys(
        value,
        {
            "document_type",
            "schema_version",
            "profile_version",
            "operation_id",
            "source",
            "datasets",
            "application",
            "recipient",
            "artifacts",
        },
    )
    require(value["document_type"] == DOCUMENT)
    for version in (value["schema_version"], value["profile_version"]):
        require(
            type(version) is int and version == 1, "persistence-version-unsupported"
        )
    operation = value["operation_id"]
    digest(operation)
    source_identity(value["source"])
    datasets = value["datasets"]
    pair_key(datasets)
    parents, snapshots, transactions = set(), set(), set()
    for role, item in datasets.items():
        keys(item, {"name", "guid", "snapshot", "snapshot_guid", "createtxg"})
        name = item["name"]
        require(matches(r"[A-Za-z][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_.-]+)+", name))
        require(
            not ({".", ".."} & set(name.split("/"))) and name.rsplit("/", 1)[1] == role
        )
        require(
            item["snapshot"] == name + "@cmdmesh-" + operation,
            "persistence-snapshot-generation-mismatch",
        )
        decimal(item["snapshot_guid"])
        decimal(item["createtxg"])
        parents.add(name.rsplit("/", 1)[0])
        snapshots.add(item["snapshot_guid"])
        transactions.add(item["createtxg"])
    require(
        len(parents) == 1 and len(transactions) == 1 and len(snapshots) == 2,
        "persistence-snapshot-pair-mismatch",
    )
    require(not (snapshots & {item["guid"] for item in datasets.values()}))
    app = value["application"]
    keys(
        app,
        {
            "instance_id",
            "config_sha256",
            "database_sha256",
            "records_sha256",
            "record_count",
            "mapping",
        },
    )
    digest(app["instance_id"], 32)
    for name in ("config_sha256", "database_sha256", "records_sha256"):
        digest(app[name])
    integer(app["record_count"], 1, 2**63 - 1)
    keys(app["mapping"], MAPPING)
    require(
        all(type(v) is int for v in app["mapping"].values())
        and app["mapping"] == MAPPING,
        "persistence-mapping-unsupported",
    )
    # Standard X25519 age recipients only. The standard age implementation must
    # separately validate its checksum before this can become an actual backup.
    require(matches(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}", value["recipient"]))
    keys(value["artifacts"], ROLES)
    for role, artifact in value["artifacts"].items():
        keys(artifact, {"name", "bytes", "sha256"})
        require(artifact["name"] == role + ".zfs.age")
        integer(artifact["bytes"], 1, 2**63 - 1)
        digest(artifact["sha256"])
    return value


def load_manifest(raw, trusted_sha256):
    """Check externally retained trust before decoding any backup description."""
    digest(trusted_sha256)
    require(type(raw) is bytes and 0 < len(raw) <= MAX_MANIFEST_BYTES)
    require(sha256(raw) == trusted_sha256, "persistence-manifest-changed")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "persistence-duplicate-field")
            result[key] = value
        return result

    def invalid(unused):
        raise PersistenceError("persistence-invalid-json")

    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    except PersistenceError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise PersistenceError("persistence-invalid-json") from None
    return validate_manifest(value)
