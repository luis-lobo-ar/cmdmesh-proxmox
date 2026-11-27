"""Pure historical selection for a future explicitly admitted v4 executor.

This module authenticates no producer, observes no filesystem, holds no lease
and permits no native action or journal initialization. The executor must join
externally qualified source/storage assertions with fresh intrinsic observations.
The original completion and contract are never rewritten for a new producer.
"""

import base64
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_attempt_codec as codec,
    persistence_owner_request_journal as journal,
    persistence_owner_semantics as semantics,
)

r = semantics.r
DOCUMENT = "cmdmesh.proxmox.owner-native-handoff-selection"
PROFILE = "owner-native-v4-historical-selection-v1"
NAMES = ("original_contract", "complete", "capture")


def require(value, code):
    r.require(value, "native-handoff-" + code)


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
        and ".." not in PurePosixPath(root).parts,
        "journal-profile",
    )
    return r.state.canonical(
        dict(profile=PROFILE, journal=journal.RUNTIME, root=root, stages=journal.STAGES)
    )


def _validate(selection, historical, pairs):
    require(
        type(selection) is semantics.Selection
        and type(historical) is semantics.Selection,
        "selection",
    )
    selection.validate()
    historical.validate()
    original, complete, capture = (r._decode(raw, checksum) for raw, checksum in pairs)
    require(
        type(original.get("schema_version")) is int
        and original["schema_version"] == 2
        and type(complete.get("schema_version")) is int
        and complete["schema_version"] == 2
        and historical._contract_raw == pairs[0][0]
        and historical.contract_sha256 == pairs[0][1],
        "historical-schema",
    )
    current_args, original_args = selection._arguments(), historical._arguments()
    require(
        all(
            r.state.canonical(current_args[key])
            == r.state.canonical(original_args[key])
            for key in ("checkpoint", "checkpoint_sha256")
        )
        and current_args["binding"] == original_args["binding"]
        and current_args["intent_raw"] == original_args["intent_raw"]
        and current_args["intent_sha256"] == original_args["intent_sha256"],
        "historical-subject",
    )
    historical.completion(*pairs[1])
    codec.validate_capture_v2(
        **historical._arguments(), capture_raw=pairs[2][0], capture_sha256=pairs[2][1]
    )
    require(
        capture["status"] == "complete-candidate"
        and type(capture["completion_schema_version"]) is int
        and capture["completion_schema_version"] == 2
        and capture["completion_disposition"] == "semantic2-candidate",
        "complete-capture",
    )
    path = str(
        semantics.storage.RUNTIME_ROOT
        / selection._private_binding.pair_key
        / "complete.json"
    )
    fact = capture["files"][path]
    require(
        fact["sha256"] == pairs[1][1]
        and base64.b64decode(fact["raw_base64"], validate=True) == pairs[1][0],
        "selected-completion",
    )
    selection.validate()
    historical.validate()


@dataclass(frozen=True, slots=True)
class NativeHandoff:
    selection: semantics.Selection = field(repr=False)
    historical: semantics.Selection = field(repr=False)
    original_contract_raw: bytes = field(repr=False)
    original_contract_sha256: str
    complete_raw: bytes = field(repr=False)
    complete_sha256: str
    capture_raw: bytes = field(repr=False)
    capture_sha256: str
    _fixed: tuple = field(repr=False)
    _configuration_raw: bytes = field(repr=False)

    def _values(self):
        return tuple(
            getattr(self, name + suffix)
            for name in NAMES
            for suffix in ("_raw", "_sha256")
        )

    def _memory(self):
        require(
            type(self) is NativeHandoff
            and type(self._fixed) is tuple
            and len(self._fixed) == 8
            and self.selection is self._fixed[0]
            and self.historical is self._fixed[1]
            and self._values() == self._fixed[2:]
            and type(self._configuration_raw) is bytes
            and _configuration() == self._configuration_raw,
            "snapshot",
        )
        for raw, checksum in zip(self._values()[::2], self._values()[1::2]):
            require(type(raw) is bytes, "snapshot-bytes")
            r.state.digest(checksum)

    def validate(self):
        self._memory()
        _validate(
            self.selection,
            self.historical,
            tuple(zip(self._values()[::2], self._values()[1::2])),
        )
        self._memory()

    @property
    def journal_binding(self):
        """Identify a new v4 lineage; this binding grants no managed authority."""
        self.validate()
        owner = self.selection._private_binding
        authority = r.digest(
            dict(
                document_type="cmdmesh.proxmox.owner-native-v4-lineage",
                schema_version=1,
                profile_sha256=r.state.sha256(self._configuration_raw),
                checkpoint_sha256=self.selection.checkpoint_sha256,
                intent_sha256=self.selection._intent_sha256,
                original_contract_sha256=self.original_contract_sha256,
                complete_sha256=self.complete_sha256,
            )
        )
        return journal.Binding(owner.pair_key, authority, owner.guest)

    def describe(self):
        self.validate()
        return r.state.canonical(
            dict(
                document_type=DOCUMENT,
                schema_version=1,
                checkpoint_sha256=self.selection.checkpoint_sha256,
                intent_sha256=self.selection._intent_sha256,
                executing_contract_sha256=self.selection.contract_sha256,
                original_contract_sha256=self.original_contract_sha256,
                complete_sha256=self.complete_sha256,
                capture_sha256=self.capture_sha256,
                journal_authority_sha256=self.journal_binding.authority_sha256,
                producer_authenticated=False,
                current_lease_verified=False,
                filesystem_qualified=False,
                native_admission_authorized=False,
                native_action_dispatched=False,
                original_native_operation_qualified=False,
                ack_recovered=False,
            )
        )


def select_native_handoff(*, selection, **inputs):
    configuration = _configuration()
    require(type(selection) is semantics.Selection, "selection")
    require(
        set(inputs)
        == {name + suffix for name in NAMES for suffix in ("_raw", "_sha256")},
        "input-fields",
    )
    values = tuple(
        inputs[name + suffix] for name in NAMES for suffix in ("_raw", "_sha256")
    )
    for raw, checksum in zip(values[::2], values[1::2]):
        require(type(raw) is bytes, "selected-bytes")
        r._decode(raw, checksum)
    selection.validate()
    args = selection._arguments()
    args.update(contract_raw=values[0], contract_sha256=values[1])
    historical = semantics.select(**args)
    fixed = (selection, historical, *values)
    result = NativeHandoff(selection, historical, *values, fixed, configuration)
    result.validate()
    return result
