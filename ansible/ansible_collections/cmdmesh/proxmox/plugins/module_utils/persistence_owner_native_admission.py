"""Pure native execution assertions, never fresh or installed-source authority.

The existing metadata Admission validates historical/source/metadata-FS claims.
This wrapper adds exact H1 review and distinct native-protocol qualification.
The source-authenticated coordinator must still hold/recheck actual historical
bytes, source controls, filesystem facts, real leases and each current phase.
"""

import base64
from dataclasses import dataclass, field
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_execution_admission as base,
    persistence_owner_native_handoff as handoffs,
    persistence_owner_native_storage as storage,
)

r = base.r
REVIEW_DOCUMENT = "cmdmesh.proxmox.owner-native-handoff-review"
FILESYSTEM_DOCUMENT = "cmdmesh.proxmox.owner-native-filesystem-qualification"
DOCUMENT = "cmdmesh.proxmox.owner-native-admission-selection"
SDK_PATHS = frozenset(
    "plugins/module_utils/persistence_" + name + ".py"
    for name in (
        "backup",
        "observe",
        "state",
        "pair_lock",
        "config_lock",
        "guest_api",
        "owner_atomic",
        "owner_attempt",
        "owner_ack",
        "owner_current",
        "owner_phase_admission",
        "owner_resources",
        "owner_metadata_executor",
        "owner_filesystem",
        "owner_request_journal",
        "owner_native_handoff",
        "owner_native_executor",
        "owner_native_storage",
        "owner_native_admission",
    )
)
PRIMITIVES = frozenset(
    "plugins/module_utils/persistence_" + name + ".py"
    for name in (
        "backup",
        "observe",
        "state",
        "owner_atomic",
        "owner_attempt",
        "owner_filesystem",
        "owner_request_journal",
        "owner_native_storage",
    )
)
NAMES = ("handoff_review", "filesystem_qualification")
LIMIT = 1048576


def require(value, code):
    r.state.require(value, "persistence-owner-native-admission-" + code)


def _same(left, right, code):
    require(r.state.canonical(left) == r.state.canonical(right), code)


def _configuration():
    return r.state.canonical(
        dict(
            review=REVIEW_DOCUMENT,
            filesystem=FILESYSTEM_DOCUMENT,
            sources=sorted(SDK_PATHS),
            primitives=sorted(PRIMITIVES),
            limit=LIMIT,
            native_storage_sha256=r.state.sha256(storage._configuration()),
        )
    )


def _review(value, handoff):
    base._document(
        value,
        REVIEW_DOCUMENT,
        {
            "checkpoint_sha256",
            "intent_sha256",
            "complete_sha256",
            "original_contract_sha256",
            "capture_sha256",
            "completion_acceptance_sha256",
            "requalification_acceptance_sha256",
            "original_native_operation_qualified",
            "ack_recovered",
        },
    )
    expected = dict(
        checkpoint_sha256=handoff.selection.checkpoint_sha256,
        intent_sha256=handoff.selection._intent_sha256,
        complete_sha256=handoff.complete_sha256,
        original_contract_sha256=handoff.original_contract_sha256,
        capture_sha256=handoff.capture_sha256,
    )
    require(
        all(value[key] == item for key, item in expected.items()), "handoff-review-join"
    )
    for key in ("completion_acceptance_sha256", "requalification_acceptance_sha256"):
        r.state.digest(value[key])
    require(
        value["original_native_operation_qualified"] is False
        and value["ack_recovered"] is False,
        "historical-uncertainty",
    )


def _probe(descriptor, filesystem):
    base._keys(descriptor, {"raw_base64", "bytes", "sha256"})
    require(
        type(descriptor["raw_base64"]) is str
        and 0 < len(descriptor["raw_base64"]) <= 87384,
        "probe-encoding",
    )
    raw = base64.b64decode(descriptor["raw_base64"], validate=True)
    require(
        type(descriptor["bytes"]) is int and descriptor["bytes"] == len(raw) <= 65536,
        "probe-size",
    )
    value = base._decode(raw, descriptor["sha256"], 65536)
    base._document(
        value,
        "cmdmesh.proxmox.owner-native-storage-probe",
        {
            "protocol",
            "configuration_sha256",
            "host_epoch",
            "kernel_release",
            "parent",
            "mount",
            "scratch_identity",
            "initial_file",
            "replaced_file",
            "initial_sha256",
            "replacement_sha256",
            "exclusive_errno",
            "scratch_removed",
            "filesystem_qualified",
            "native_action_dispatched",
        },
    )
    require(
        value["protocol"] == storage.PROTOCOL
        and value["configuration_sha256"] == r.state.sha256(storage._configuration())
        and type(value["exclusive_errno"]) is int
        and value["exclusive_errno"] == 17
        and value["scratch_removed"] is True
        and value["filesystem_qualified"] is False
        and value["native_action_dispatched"] is False,
        "probe-profile",
    )
    _same(value["host_epoch"], filesystem["subject"]["host_epoch"], "probe-epoch")
    require(
        value["kernel_release"] == filesystem["subject"]["kernel_release"],
        "probe-kernel",
    )
    parent = filesystem["roles"]["bootstrap-lock"]
    require(
        parent["ancestor_path"]
        == parent["parent"]
        == str(storage.journal.RUNTIME_ROOT.parent)
        and parent["missing_suffix"] == [],
        "common-parent",
    )
    base._keys(value["parent"], {"path", "identity"})
    _same(
        value["parent"],
        dict(path=parent["parent"], identity=parent["ancestor_identity"]),
        "probe-parent",
    )
    base._mount(value["mount"])
    _same(value["mount"], filesystem["mounts"][parent["mount_index"]], "probe-mount")
    scratch = value["scratch_identity"]
    base._stable(scratch)
    owner = storage.journal.ROOT_UID
    require(
        scratch[0] == parent["ancestor_identity"][0]
        and scratch[1] != parent["ancestor_identity"][1]
        and scratch[2:] == [stat.S_IFDIR | 0o700, owner, owner],
        "probe-directory",
    )
    identities = []
    for generation, key, checksum in (
        (1, "initial_file", "initial_sha256"),
        (2, "replaced_file", "replacement_sha256"),
    ):
        info = value[key]
        require(type(info) is list and len(info) == 9, "probe-file")
        for item in info:
            base._int(item)
        payload = r.state.canonical(
            dict(
                document_type="cmdmesh.proxmox.owner-native-storage-probe.payload",
                schema_version=1,
                generation=generation,
            )
        )
        require(
            info[0] == scratch[0]
            and info[1] > 0
            and info[2:7] == [stat.S_IFREG | 0o600, owner, owner, 1, len(payload)]
            and value[checksum] == r.state.sha256(payload),
            "probe-file",
        )
        identities.append(info[1])
    require(len(set([scratch[1], *identities])) == 3, "probe-inodes")


def _validate(metadata_admission, handoff, pairs):
    require(
        type(metadata_admission) is base.Admission
        and type(handoff) is handoffs.NativeHandoff,
        "inputs",
    )
    metadata_admission.validate()
    handoff.validate()
    require(
        metadata_admission.action == "requalify-complete"
        and metadata_admission.selection is handoff.selection,
        "selected-subject",
    )
    manifest = base._decode(
        metadata_admission.producer_manifest_raw,
        metadata_admission.producer_manifest_sha256,
        LIMIT,
    )
    sdk = manifest["components"]["sdk"]
    require(SDK_PATHS <= set(sdk), "native-source-roles")
    review, qualification = (base._decode(raw, sha, LIMIT) for raw, sha in pairs)
    _review(review, handoff)
    base._document(
        qualification,
        FILESYSTEM_DOCUMENT,
        {
            "subject",
            "metadata_filesystem_sha256",
            "producer_manifest_sha256",
            "configuration_sha256",
            "primitives",
            "diagnostic_acceptance_sha256",
            "logic_qualification_sha256",
            "probe",
        },
    )
    filesystem = base._decode(
        metadata_admission.filesystem_qualification_raw,
        metadata_admission.filesystem_qualification_sha256,
        LIMIT,
    )
    _same(qualification["subject"], filesystem["subject"], "filesystem-subject")
    require(
        qualification["metadata_filesystem_sha256"]
        == metadata_admission.filesystem_qualification_sha256
        and qualification["producer_manifest_sha256"]
        == metadata_admission.producer_manifest_sha256
        and qualification["configuration_sha256"]
        == r.state.sha256(storage._configuration()),
        "filesystem-join",
    )
    base._keys(qualification["primitives"], PRIMITIVES)
    require(
        all(
            qualification["primitives"][path] == sdk[path]["sha256"]
            for path in PRIMITIVES
        ),
        "primitive-source",
    )
    for key in ("diagnostic_acceptance_sha256", "logic_qualification_sha256"):
        r.state.digest(qualification[key])
    _probe(qualification["probe"], filesystem)
    metadata_admission.validate()
    handoff.validate()


@dataclass(frozen=True, slots=True)
class NativeAdmission:
    metadata_admission: base.Admission = field(repr=False)
    handoff: handoffs.NativeHandoff = field(repr=False)
    handoff_review_raw: bytes = field(repr=False)
    handoff_review_sha256: str
    filesystem_qualification_raw: bytes = field(repr=False)
    filesystem_qualification_sha256: str
    _fixed: tuple = field(repr=False)
    _configuration_raw: bytes = field(repr=False)

    @property
    def selection(self):
        return self.handoff.selection

    def _values(self):
        return tuple(
            getattr(self, name + suffix)
            for name in NAMES
            for suffix in ("_raw", "_sha256")
        )

    def _memory(self):
        require(
            type(self) is NativeAdmission
            and type(self._fixed) is tuple
            and len(self._fixed) == 6
            and self.metadata_admission is self._fixed[0]
            and self.handoff is self._fixed[1]
            and self._values() == self._fixed[2:]
            and type(self._configuration_raw) is bytes
            and _configuration() == self._configuration_raw,
            "snapshot",
        )
        for raw, sha in zip(self._values()[::2], self._values()[1::2]):
            require(type(raw) is bytes, "snapshot-bytes")
            r.state.digest(sha)

    def validate(self):
        self._memory()
        _validate(
            self.metadata_admission,
            self.handoff,
            tuple(zip(self._values()[::2], self._values()[1::2])),
        )
        self._memory()

    def describe(self):
        self.validate()
        return r.state.canonical(
            dict(
                document_type=DOCUMENT,
                schema_version=1,
                checkpoint_sha256=self.selection.checkpoint_sha256,
                complete_sha256=self.handoff.complete_sha256,
                executing_contract_sha256=self.selection.contract_sha256,
                handoff_review_sha256=self.handoff_review_sha256,
                filesystem_qualification_sha256=self.filesystem_qualification_sha256,
                producer_authenticated=False,
                filesystem_verified_live=False,
                current_lease_verified=False,
                native_action_dispatched=False,
                original_native_operation_qualified=False,
                ack_recovered=False,
            )
        )


def load_native_admission(
    *,
    metadata_admission,
    handoff,
    handoff_review_raw,
    handoff_review_sha256,
    filesystem_qualification_raw,
    filesystem_qualification_sha256
):
    """Validate externally selected assertions; no IO, producer or native grant."""
    values = (
        handoff_review_raw,
        handoff_review_sha256,
        filesystem_qualification_raw,
        filesystem_qualification_sha256,
    )
    configuration = _configuration()
    _validate(metadata_admission, handoff, tuple(zip(values[::2], values[1::2])))
    result = NativeAdmission(
        metadata_admission,
        handoff,
        *values,
        (metadata_admission, handoff, *values),
        configuration
    )
    result.validate()
    return result
