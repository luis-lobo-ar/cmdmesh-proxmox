"""Fixed semantic2 selection; no observation, publication or permission.

External callers select checkpoint/contract hashes. Neither this object nor a
completion record authenticates source execution, real leases or native facts.
"""

from dataclasses import dataclass, field

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_completion as codec,
)

r, storage = codec.r, codec.storage


def require(value, code):
    r.require(value, "semantic-selection-" + code)


def _profile():
    return r.state.canonical(
        {
            "runtime": storage.RUNTIME,
            "root": str(storage.RUNTIME_ROOT),
            "retirement_root": str(r.RUNTIME_ROOT),
            "legacy_root": str(r.legacy.RUNTIME_ROOT),
            "marker": storage.MARKER,
            "legacy_marker": r.MARKER,
            "protocol": storage.PROTOCOL,
            "uid": r.legacy.ROOT_UID,
            "phase_policy": codec.PHASE_POLICY,
            "required_gates": list(codec.REQUIRED_GATES),
        }
    )


@dataclass(frozen=True, slots=True)
class Selection:
    checkpoint_sha256: str
    contract_sha256: str
    _original_binding: object = field(repr=False)
    _private_binding: object = field(repr=False)
    _original_checkpoint: dict = field(repr=False)
    _private_checkpoint: dict = field(repr=False)
    _checkpoint_raw: bytes = field(repr=False)
    _binding_raw: bytes = field(repr=False)
    _intent_raw: bytes = field(repr=False)
    _intent_sha256: str = field(repr=False)
    _contract_raw: bytes = field(repr=False)
    _profile_raw: bytes = field(repr=False)
    _fixed: tuple = field(repr=False)
    _references: tuple = field(repr=False)

    def _memory(self):
        require(type(self) is Selection, "type")
        require(
            type(self._fixed) is tuple
            and len(self._fixed) == 8
            and all(
                type(value) is bytes
                for value in (
                    self._checkpoint_raw,
                    self._binding_raw,
                    self._intent_raw,
                    self._contract_raw,
                    self._profile_raw,
                    *(self._fixed[index] for index in (2, 3, 4, 6, 7)),
                )
            ),
            "snapshot-type",
        )
        require(
            type(self._references) is tuple
            and len(self._references) == 4
            and all(
                value is expected
                for value, expected in zip(
                    (
                        self._original_binding,
                        self._private_binding,
                        self._original_checkpoint,
                        self._private_checkpoint,
                    ),
                    self._references,
                )
            ),
            "snapshot-reference",
        )
        r.state.digest(self.checkpoint_sha256)
        r.state.digest(self.contract_sha256)
        require(
            (
                self.checkpoint_sha256,
                self.contract_sha256,
                self._checkpoint_raw,
                self._binding_raw,
                self._intent_raw,
                self._intent_sha256,
                self._contract_raw,
                self._profile_raw,
            )
            == self._fixed,
            "selection-changed",
        )
        require(_profile() == self._profile_raw, "profile-changed")
        require(
            storage.RUNTIME_ROOT == r.RUNTIME_ROOT and storage.MARKER == r.MARKER,
            "profile-path",
        )
        r._close_binding(
            self._original_binding, self._private_binding, self._binding_raw
        )
        for checkpoint in (self._original_checkpoint, self._private_checkpoint):
            codec.admission._json(checkpoint)
            require(
                r.state.canonical(checkpoint) == self._checkpoint_raw
                and r.state.sha256(self._checkpoint_raw) == self.checkpoint_sha256,
                "checkpoint-changed",
            )

    def _arguments(self):
        return dict(
            binding=self._private_binding,
            checkpoint=self._private_checkpoint,
            checkpoint_sha256=self.checkpoint_sha256,
            intent_raw=self._intent_raw,
            intent_sha256=self._intent_sha256,
            contract_raw=self._contract_raw,
            contract_sha256=self.contract_sha256,
        )

    def validate(self):
        """Reclose original/private inputs; a valid selection grants no rights."""
        self._memory()
        contract = codec.load_publication_contract(**self._arguments())
        self._memory()
        require(r.state.canonical(contract) == self._contract_raw, "contract-changed")
        self._memory()

    def _match(self, binding, intent_raw, intent_sha256):
        self.validate()
        _, binding_raw = r._binding(binding)
        require(
            binding_raw == self._binding_raw
            and type(intent_raw) is bytes
            and intent_raw == self._intent_raw
            and intent_sha256 == self._intent_sha256,
            "context-mismatch",
        )
        self._memory()

    def completion(self, raw, sha, *, allow_historical=False):
        """Dispatch only fixed codecs; legacy1 requires explicit forensic use."""
        require(type(allow_historical) is bool, "historical-mode")
        self.validate()
        header = r._decode(raw, sha)
        version = header.get("schema_version")
        require(type(version) is int and version in (1, 2), "completion-schema")
        if version == 2:
            body = codec.validate_completion(
                **self._arguments(), complete_raw=raw, complete_sha256=sha
            )
        else:
            require(allow_historical, "historical-only")
            body = r.validate_handoff(
                self._private_binding, self._intent_raw, self._intent_sha256, raw, sha
            )
        self.validate()
        self._memory()
        require(
            r.state.canonical(header) == raw and r.state.canonical(body) == raw,
            "completion-changed",
        )
        return body


def select(
    *,
    binding,
    checkpoint,
    checkpoint_sha256,
    intent_raw,
    intent_sha256,
    contract_raw,
    contract_sha256,
):
    """Select exact inputs, without discovering authority or touching the target."""
    require(type(checkpoint) is dict, "checkpoint")
    owner, binding_raw = r._binding(binding)
    codec.admission._json(checkpoint)
    checkpoint_raw = r.state.canonical(checkpoint)
    r.state.digest(checkpoint_sha256)
    require(r.state.sha256(checkpoint_raw) == checkpoint_sha256, "checkpoint-hash")
    private = r.observe.decode(checkpoint_raw)
    profile_raw = _profile()
    fixed = (
        checkpoint_sha256,
        contract_sha256,
        checkpoint_raw,
        binding_raw,
        intent_raw,
        intent_sha256,
        contract_raw,
        profile_raw,
    )
    selected = Selection(
        checkpoint_sha256,
        contract_sha256,
        binding,
        owner,
        checkpoint,
        private,
        checkpoint_raw,
        binding_raw,
        intent_raw,
        intent_sha256,
        contract_raw,
        profile_raw,
        fixed,
        (binding, owner, checkpoint, private),
    )
    selected.validate()
    return selected
