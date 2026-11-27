"""Self-leased initialization and developing native-v4 lifecycle machinery.

The caller authenticates its installed producer. NativeAdmission selects the
historical/source/storage assertions; actual observers and locks close before
returning a candidate. Read-only preparation is available; native dispatch and
status remain unfinished.
Legacy journal state is never used for v4 failure reporting.
"""

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
import os
from pathlib import Path

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_current as current,
    persistence_owner_metadata_executor as metadata,
    persistence_owner_native_admission as admission_codec,
    persistence_owner_native_handoff as handoffs,
    persistence_owner_native_storage as storage,
    persistence_owner_phase_admission as phases,
    persistence_owner_request_journal as journal,
)

runtime, state, observe = current.runtime, current.state, current.observe


def require(value, code):
    state.require(value, "persistence-owner-native-executor-" + code)


def genesis_sha256(admission):
    """Derive the proposed unused head without observing or creating metadata."""
    require(type(admission) is admission_codec.NativeAdmission, "admission")
    admission.validate()
    return journal._digest(journal._genesis(admission.handoff.journal_binding))


@contextmanager
def _filesystem(admission):
    """Match actual fixed-role facts without reinterpreting a metadata write grant."""
    base = admission.metadata_admission
    qualified = metadata._decode(
        base.filesystem_qualification_raw, base.filesystem_qualification_sha256
    )
    with metadata.filesystem.observe_subject(admission.selection) as observed:
        metadata.filesystem._match_subject(observed.raw, qualified)
        native = metadata._decode(
            admission.filesystem_qualification_raw,
            admission.filesystem_qualification_sha256,
        )
        admission_codec._probe(native["probe"], qualified)
        admission.validate()
        yield observed
        admission.validate()


def _initialization(admission, expected_head_sha256, check_mode, allow_mutation):
    require(type(admission) is admission_codec.NativeAdmission, "admission")
    require(type(check_mode) is bool, "check-mode")
    write = allow_mutation is not None
    if write:
        require(
            type(allow_mutation) is bool and allow_mutation and not check_mode,
            "mutation-mode",
        )
    state.digest(expected_head_sha256)
    require(expected_head_sha256 == genesis_sha256(admission), "genesis")
    handoff, selection = admission.handoff, admission.selection
    base = admission.metadata_admission
    cp = selection._private_checkpoint
    values = (*admission._values(), expected_head_sha256, check_mode, allow_mutation)
    inputs = metadata._Inputs(base, "os_quiesced", None, values)
    expected = metadata._requalification_capture(
        handoff.historical, handoff.capture_raw, handoff.capture_sha256
    )
    with _leased(handoff, "shutdown", None) as scope:
        with metadata._Stack() as stack:
            # Retain the entire original publication before resource setup/SQL.
            original = stack.enter_context(
                metadata._complete_forensics(
                    handoff.historical, handoff.complete_raw, handoff.complete_sha256
                )
            )
            require(
                metadata.previous._projection(
                    metadata._decode(original.raw, original.sha256)
                )
                == metadata.previous._projection(expected),
                "historical-projection",
            )
            held = stack.enter_context(
                metadata.resources.hold_owner_resources(
                    selection=selection, entry=scope.entry, action="requalify-complete"
                )
            )
            actors = stack.enter_context(metadata._hold_actor_controls(base))
            filesystem = stack.enter_context(_filesystem(admission))
            facts = metadata._decode(filesystem.raw, filesystem.sha256)
            role = facts["roles"]["bootstrap-lock"]
            mount = facts["mounts"][role["mount_index"]]
            native_parents = stack.enter_context(
                _observe_native_namespace(handoff.journal_binding, mount, fixed=False)
            )
            require(
                facts["subject"]["host_epoch"]
                == {
                    key: scope.entry["host"][key]
                    for key in ("boot_id", "mount_namespace")
                },
                "filesystem-host-epoch",
            )
            before = storage._inspect_initialization(handoff.journal_binding)
            with _phase_current(scope):
                pass
            e1 = scope.latest.evidence
            storage._close_initialization(before)
            holders = [held, actors, original.seal, filesystem, native_parents]
            admission.validate()
            metadata._post_worker(cp, scope, e1, None, holders, inputs)
            changed = False
            if write:
                # Both SQL/current workers are closed throughout the short mutex.
                initialized = storage._initialize_journal(handoff.journal_binding)
                require(
                    type(initialized) is dict
                    and set(initialized) == {"changed", "head_sha256"}
                    and type(initialized["changed"]) is bool
                    and initialized["changed"] is before.would_change
                    and initialized["head_sha256"] == expected_head_sha256,
                    "initializer-result",
                )
                changed = initialized["changed"]
            after = storage._inspect_initialization(handoff.journal_binding)
            require(not write or not after.would_change, "initialization-incomplete")
            native = stack.enter_context(
                _observe_native_namespace(handoff.journal_binding, mount, fixed=True)
            )
            holders.append(native)
            with _phase_current(scope):
                pass
            e2 = scope.latest.evidence
            storage._close_initialization(after)
            admission.validate()
            raw = state.canonical(
                dict(
                    document_type="cmdmesh.proxmox.owner-native-initialization-candidate",
                    schema_version=1,
                    operation="initialize" if write else "inspect-initialization",
                    checkpoint_sha256=selection.checkpoint_sha256,
                    complete_sha256=handoff.complete_sha256,
                    original_contract_sha256=handoff.original_contract_sha256,
                    executing_contract_sha256=selection.contract_sha256,
                    producer_manifest_sha256=base.producer_manifest_sha256,
                    handoff_review_sha256=admission.handoff_review_sha256,
                    filesystem_qualification_sha256=admission.filesystem_qualification_sha256,
                    head_sha256=expected_head_sha256,
                    initialized=not after.would_change,
                    would_change=before.would_change,
                    changed=changed,
                    v4_metadata_write_attempted=write,
                    initial_closing_current=e1,
                    final_closing_current=e2,
                    candidate_only=True,
                    native_action_dispatched=False,
                    original_native_operation_qualified=False,
                    ack_recovered=False,
                    successor_native_admission_authorized=False,
                )
            )
            result = metadata.Candidate(raw, state.sha256(raw))
            metadata._post_worker(cp, scope, e2, None, holders, inputs)
        require(scope.pending is None, "initialization-pending")
    admission.validate()
    inputs.fast()
    require(
        scope.pending is None
        and type(result.raw) is bytes
        and result.raw == raw
        and result.sha256 == state.sha256(raw),
        "initialization-exit-memory",
    )
    return result


def inspect_initialization(*, admission, expected_head_sha256, check_mode=False):
    """Read-only absent/unused inspection; no mutex, namespace, native or adoption."""
    return _initialization(admission, expected_head_sha256, check_mode, None)


def initialize(
    *, admission, expected_head_sha256, allow_mutation=False, check_mode=False
):
    """Explicit unused-v4 metadata only; every resource exit precedes the return."""
    require(type(allow_mutation) is bool, "mutation-mode")
    return _initialization(admission, expected_head_sha256, check_mode, allow_mutation)


PREPARED = "cmdmesh.proxmox.owner-native-v4-transition.prepared"
PREPARED_LIMIT = 8388608
PREPARED_FALSE = (
    "native_action_dispatched",
    "original_native_operation_qualified",
    "ack_recovered",
    "successor_native_admission_authorized",
)


def _references(admission):
    admission.validate()
    return dict(
        checkpoint_sha256=admission.selection.checkpoint_sha256,
        native_admission_sha256=state.sha256(admission.describe()),
        producer_manifest_sha256=admission.metadata_admission.producer_manifest_sha256,
    )


def _preparation_inputs(admission, kind, head, prior_raw, prior_sha, check_mode):
    require(type(admission) is admission_codec.NativeAdmission, "admission")
    require(type(kind) is str and kind in {"shutdown", "resume"}, "kind")
    require(type(check_mode) is bool, "check-mode")
    if kind == "resume":
        require(type(prior_raw) is bytes and type(prior_sha) is str, "resume-prior")
    else:
        require(prior_raw is prior_sha is None, "shutdown-prior")
    state.digest(head)
    phase = "os_quiesced" if kind == "shutdown" else "stopped"
    admission.validate()
    _, prior = metadata._preflight(
        admission.metadata_admission, phase, prior_raw, prior_sha, check_mode
    )
    return phase, prior


@contextmanager
def _retained_readonly(admission, scope):
    """Keep original history and current resources; supply no operation grant."""
    require(type(scope) is _Scope and scope.handoff is admission.handoff, "scope")
    scope.check()
    handoff, selection = admission.handoff, admission.selection
    expected = metadata._requalification_capture(
        handoff.historical, handoff.capture_raw, handoff.capture_sha256
    )
    with metadata._Stack() as stack:
        original = stack.enter_context(
            metadata._complete_forensics(
                handoff.historical, handoff.complete_raw, handoff.complete_sha256
            )
        )
        require(
            metadata.previous._projection(
                metadata._decode(original.raw, original.sha256)
            )
            == metadata.previous._projection(expected),
            "historical-projection",
        )
        held = stack.enter_context(
            metadata.resources.hold_owner_resources(
                selection=selection, entry=scope.entry, action="requalify-complete"
            )
        )
        actors = stack.enter_context(
            metadata._hold_actor_controls(admission.metadata_admission)
        )
        filesystem = stack.enter_context(_filesystem(admission))
        facts = metadata._decode(filesystem.raw, filesystem.sha256)
        require(
            facts["subject"]["host_epoch"]
            == {
                key: scope.entry["host"][key] for key in ("boot_id", "mount_namespace")
            },
            "filesystem-host-epoch",
        )
        mount = facts["mounts"][facts["roles"]["bootstrap-lock"]["mount_index"]]
        parents = stack.enter_context(
            _observe_native_namespace(handoff.journal_binding, mount, fixed=False)
        )
        yield [held, actors, original.seal, filesystem, parents], mount


def prepare(
    *,
    admission,
    kind,
    accepted_head_sha256,
    prior_runtime_raw=None,
    prior_runtime_sha256=None,
    check_mode=False
):
    """Observe a ready predecessor without claiming a slot or sending a request."""
    phase, prior = _preparation_inputs(
        admission,
        kind,
        accepted_head_sha256,
        prior_runtime_raw,
        prior_runtime_sha256,
        check_mode,
    )
    references = _references(admission)
    inputs = metadata._Inputs(
        admission.metadata_admission,
        phase,
        prior,
        (
            *admission._values(),
            kind,
            accepted_head_sha256,
            prior_runtime_raw,
            prior_runtime_sha256,
            check_mode,
            state.canonical(references),
        ),
    )
    cp = admission.selection._private_checkpoint
    with _leased(admission.handoff, kind, prior) as scope:
        with _retained_readonly(admission, scope) as (holders, mount):
            with _observe_ready_journal(
                admission.handoff.journal_binding,
                mount,
                accepted_head_sha256=accepted_head_sha256,
            ) as native:
                all_holders = [*holders, native]
                store_raw = state.canonical(
                    observe.mount_facts(scope.request["backup_store"])
                )
                with _phase_current(scope):
                    pass
                metadata._post_worker(
                    cp, scope, scope.latest.evidence, prior, all_holders, inputs
                )
                with _phase_current(scope):
                    pass
                before = scope.latest.evidence
                require(
                    state.canonical(observe.mount_facts(scope.request["backup_store"]))
                    == store_raw,
                    "backup-mount",
                )
                body = dict(
                    document_type=PREPARED,
                    schema_version=1,
                    **references,
                    predecessor_sha256=accepted_head_sha256,
                    kind=kind,
                    entry=metadata.transition._entry_identity(scope.entry),
                    init_identity=metadata.transition._init_identity(before),
                    uptime_floor=before["observation"]["guest"]["runtime"]["uptime"],
                    backup_store=observe.decode(store_raw),
                    prior_runtime=prior,
                    before_current=before,
                    candidate_only=True,
                    **dict.fromkeys(PREPARED_FALSE, False)
                )
                raw = state.canonical(body)
                require(0 < len(raw) <= PREPARED_LIMIT, "prepared-limit")
                result = metadata.Candidate(raw, state.sha256(raw))
                admission.validate()
                metadata._post_worker(cp, scope, before, prior, all_holders, inputs)
        require(scope.pending is None, "preparation-pending")
    inputs.fast()
    admission.validate()
    require(
        result.raw == raw and result.sha256 == state.sha256(raw),
        "preparation-exit-memory",
    )
    return result


def _decode_prepared(admission, raw, checksum):
    require(type(admission) is admission_codec.NativeAdmission, "admission")
    require(type(raw) is bytes and 0 < len(raw) <= PREPARED_LIMIT, "prepared-limit")
    body = metadata._decode(raw, checksum)
    state.keys(
        body,
        {
            "document_type",
            "schema_version",
            "checkpoint_sha256",
            "native_admission_sha256",
            "producer_manifest_sha256",
            "predecessor_sha256",
            "kind",
            "entry",
            "init_identity",
            "uptime_floor",
            "backup_store",
            "prior_runtime",
            "before_current",
            "candidate_only",
            *PREPARED_FALSE,
        },
    )
    require(
        body["document_type"] == PREPARED
        and type(body["schema_version"]) is int
        and body["schema_version"] == 1
        and body["candidate_only"] is True
        and all(body[key] is False for key in PREPARED_FALSE),
        "prepared-schema",
    )
    require(
        type(body["kind"]) is str and body["kind"] in {"shutdown", "resume"}, "kind"
    )
    state.digest(body["predecessor_sha256"])
    state.integer(body["uptime_floor"], 0, 2**63 - 1)
    phases._json(body)
    references = _references(admission)
    require(
        all(body[key] == value for key, value in references.items()),
        "prepared-admission",
    )
    phase = "os_quiesced" if body["kind"] == "shutdown" else "stopped"
    current.validate_current(
        admission.selection._private_checkpoint, phase, body["before_current"]
    )
    require(
        body["uptime_floor"]
        == body["before_current"]["observation"]["guest"]["runtime"]["uptime"]
        and state.canonical(body["init_identity"])
        == state.canonical(metadata.transition._init_identity(body["before_current"])),
        "prepared-current",
    )
    require(
        type(body["entry"]) is dict and type(body["backup_store"]) is dict,
        "prepared-basis",
    )
    return body


def _compatible_preparation(saved, fresh):
    ignored = {"before_current", "uptime_floor"}
    require(
        state.canonical({k: v for k, v in saved.items() if k not in ignored})
        == state.canonical({k: v for k, v in fresh.items() if k not in ignored}),
        "prepared-basis-changed",
    )
    require(fresh["uptime_floor"] >= saved["uptime_floor"], "prepared-uptime-decreased")


def inspect_transition(*, admission, prepared_raw, prepared_sha256, check_mode=False):
    """Reobserve one selected preparation; never replace it or advance the head."""
    saved = _decode_prepared(admission, prepared_raw, prepared_sha256)
    prior = saved["prior_runtime"]
    prior_raw = None if prior is None else state.canonical(prior)
    fresh = prepare(
        admission=admission,
        kind=saved["kind"],
        accepted_head_sha256=saved["predecessor_sha256"],
        prior_runtime_raw=prior_raw,
        prior_runtime_sha256=None if prior_raw is None else state.sha256(prior_raw),
        check_mode=check_mode,
    )
    current_body = _decode_prepared(admission, fresh.raw, fresh.sha256)
    _compatible_preparation(saved, current_body)
    raw = state.canonical(
        dict(
            document_type="cmdmesh.proxmox.owner-native-v4-transition.inspection",
            schema_version=1,
            prepared_sha256=prepared_sha256,
            fresh_preparation_sha256=fresh.sha256,
            preconditions_observed=True,
            before_current=current_body["before_current"],
            candidate_only=True,
            **dict.fromkeys(PREPARED_FALSE, False)
        )
    )
    return metadata.Candidate(raw, state.sha256(raw))


@dataclass(frozen=True, slots=True)
class _Phase:
    entry: dict
    evidence: dict
    prior: dict | None


@dataclass(slots=True)
class _Scope:
    handoff: handoffs.NativeHandoff
    kind: str
    request: dict
    entry: dict
    raw: bytes
    prior: dict | None
    target: ExitStack
    latest: _Phase | None = None
    pending: journal.Pending | None = None
    outcome: str = "not-dispatched"
    worker_active: bool = False
    window_active: bool = False
    window_used: bool = False
    target_held: bool = True
    poisoned: bool = False
    closed: bool = False
    _fixed: tuple = field(init=False, repr=False)
    _latest_raw: bytes = field(default=b"null\n", init=False, repr=False)

    def __post_init__(self):
        self._fixed = (
            self.handoff,
            self.kind,
            self.target,
            os.getpid(),
            state.canonical([self.request, self.entry, self.prior]),
            self.raw,
        )
        self._latest_raw = state.canonical(None)

    def check(self):
        require(not self.closed and not self.poisoned, "closed-or-poisoned")
        require(
            self.handoff is self._fixed[0]
            and self.kind == self._fixed[1]
            and self.target is self._fixed[2]
            and os.getpid() == self._fixed[3]
            and state.canonical([self.request, self.entry, self.prior])
            == self._fixed[4]
            and type(self.raw) is bytes
            and self.raw == self._fixed[5],
            "scope-memory",
        )
        require(
            state.canonical(
                None
                if self.latest is None
                else [self.latest.entry, self.latest.evidence, self.latest.prior]
            )
            == self._latest_raw,
            "phase-memory",
        )
        self.handoff.validate()


@contextmanager
def _leased(handoff, kind, prior_runtime):
    """Own pair EX, retired/target SH and application EX; no borrowed scope."""
    require(type(handoff) is handoffs.NativeHandoff, "handoff")
    require(type(kind) is str and kind in {"shutdown", "resume"}, "kind")
    handoff.validate()
    cp = handoff.selection._private_checkpoint
    phase = "os_quiesced" if kind == "shutdown" else "stopped"
    phases._json(prior_runtime)
    require(phase != "stopped" or prior_runtime is not None, "stopped-prior")
    if prior_runtime is not None:
        current.validate_current(
            cp,
            "os_quiesced",
            dict(
                phase="os_quiesced",
                observation=prior_runtime,
                guest_image_verified=True,
            ),
        )
    request, _, _ = current._authority(cp)
    policy = request["policy"]
    scope = None
    with metadata._Stack() as pair_lease:
        pair_lease.enter_context(runtime.pair_lock.locked_pair(policy["datasets"]))
        try:
            with metadata._Stack() as locks:
                locks.enter_context(
                    runtime.config_lock.read_guest(policy["retired_guest"]["vmid"])
                )
                target = locks.enter_context(ExitStack())
                target.enter_context(runtime.config_lock.read_guest(policy["vmid"]))
                entry = current._entry_leased(cp, phase, prior_runtime)
                uid, gid = (
                    policy["mapping"]["offset"] + policy["mapping"][key]
                    for key in ("uid", "gid")
                )
                raw = locks.enter_context(
                    observe.locked_config(
                        Path(policy["datasets"]["config"]["mountpoint"])
                        / "application.json",
                        uid,
                        gid,
                    )
                )
                scope = _Scope(
                    handoff, kind, request, entry, raw, prior_runtime, target
                )
                scope.check()
                yield scope
                scope.check()
                require(
                    not scope.worker_active
                    and not scope.window_active
                    and scope.target_held,
                    "active-context",
                )
                require(
                    not scope.window_used or scope.latest.evidence["phase"] != phase,
                    "final-phase-required",
                )
        except BaseException as error:
            # All native/application leases have exited; the real pair EX is
            # still owned. Never route a v4 pending operation into v3 cleanup.
            if scope is not None and scope.pending is not None:
                try:
                    require(type(scope.pending) is journal.Pending, "pending-type")
                    journal._fail(
                        scope.pending, "native-transition-unqualified", scope.outcome
                    )
                except BaseException:
                    error.add_note("secondary native-v4 failure-record error")
            raise
        finally:
            if scope is not None:
                scope.closed = True


@contextmanager
def _phase_current(scope, *, final=False):
    """Close each phase worker before allowing a native lock window."""
    require(type(scope) is _Scope and type(final) is bool, "scope-phase")
    scope.check()
    require(
        not scope.worker_active and not scope.window_active and scope.target_held,
        "active-context",
    )
    require((scope.window_used if final else not scope.window_used), "phase-order")
    phase = "os_quiesced" if scope.kind == "shutdown" else "stopped"
    prior = scope.prior
    if final:
        require(scope.latest is not None, "before-required")
        phase = "stopped" if scope.kind == "shutdown" else "os_quiesced"
        prior = scope.latest.evidence["observation"] if phase == "stopped" else None
    cp = scope.handoff.selection._private_checkpoint
    scope.worker_active = True
    try:
        entry = current._entry_leased(cp, phase, prior) if final else scope.entry
        entry_raw, prior_raw = state.canonical(entry), state.canonical(prior)
        with current._current_frames_leased(cp, entry, scope.raw, prior) as frames:
            yield frames
        evidence = metadata._evidence(frames, cp, phase)
        phases.validate_phase_admission(cp, phase, evidence, entry, prior)
        require(
            state.canonical(entry) == entry_raw and state.canonical(prior) == prior_raw,
            "phase-input-memory",
        )
        scope.check()
        scope.latest = _Phase(entry, evidence, prior)
        scope._latest_raw = state.canonical([entry, evidence, prior])
    except BaseException:
        scope.poisoned = True
        raise
    finally:
        scope.worker_active = False


@contextmanager
def _native_window(scope):
    """Release only target SH, once, with no phase-current context alive.

    The future admitted coordinator owns dispatch/journaling/polling inside this
    interval. This helper performs no native action and supplies no permission.
    """
    require(type(scope) is _Scope, "scope")
    scope.check()
    require(
        scope.latest is not None
        and not scope.worker_active
        and not scope.window_active
        and not scope.window_used
        and scope.target_held,
        "window-order",
    )
    scope.window_used = True
    scope.window_active = True
    primary = None
    try:
        scope.target.close()
        scope.target_held = False
        runtime.config_lock.require_write_available(scope.request["policy"]["vmid"])
        scope.check()
        yield
    except BaseException as error:
        scope.poisoned = True
        primary = error
        raise
    finally:
        try:
            if not scope.target_held:
                scope.target.enter_context(
                    runtime.config_lock.read_guest(scope.request["policy"]["vmid"])
                )
                scope.target_held = True
        except BaseException:
            scope.poisoned = True
            if primary is None:
                raise
            primary.add_note("secondary target-lock reacquisition failure")
        finally:
            scope.window_active = False


class _NativeSeal(metadata.resources._Seal):
    """Retain actual native parents/mounts, optionally immutable unused state."""

    def __init__(self, binding, mount, *, fixed):
        require(type(binding) is journal.Binding and type(fixed) is bool, "native-seal")
        metadata.admission_codec._mount(mount)
        super().__init__(binding.pair_key)
        paths = []
        self._native_mount = metadata._decode(
            state.canonical(mount), state.sha256(state.canonical(mount))
        )
        try:
            root, pair = journal.RUNTIME_ROOT, journal.RUNTIME_ROOT / binding.pair_key
            self._directory(root.parent, private=True)
            paths.append(root.parent)
            if fixed:
                root_fd = self.directory(root, shared=True)
                require(root_fd is not False, "native-root")
                if root_fd is not None:
                    paths.append(root)
                    self._file(root / "runtime.json", journal.RUNTIME, paths)
                    pair_fd = self.directory(pair)
                    require(pair_fd is not False, "native-pair")
                    self.membership(root, shared=True)
                    wanted = (
                        ("runtime.json",)
                        if pair_fd is None
                        else tuple(sorted(("runtime.json", binding.pair_key)))
                    )
                    require(self.members[str(root)][1] == wanted, "native-root-members")
                    if pair_fd is not None:
                        paths.append(pair)
                        self.membership(pair)
                        require(
                            self.members[str(pair)][1]
                            == ("HEAD.json", "genesis.json", "profile.json"),
                            "native-pair-members",
                        )
                        for name, value in (
                            ("profile.json", journal._profile(binding)),
                            ("genesis.json", journal._genesis(binding)),
                            ("HEAD.json", journal._genesis(binding)),
                        ):
                            self._file(pair / name, value, paths)
            else:
                for path in (root, pair):
                    try:
                        self._directory(path, private=True)
                    except FileNotFoundError:
                        break
                    paths.append(path)
            lock = root.parent / storage.LOCK_NAME
            if fixed or os.path.lexists(lock):
                entry = self.entry(lock)
                if entry is not None:
                    self._file(
                        lock,
                        dict(
                            document_type="cmdmesh.proxmox.owner-native-bootstrap-lock",
                            schema_version=1,
                            configuration_sha256=state.sha256(storage._configuration()),
                        ),
                        paths,
                    )
            self._native_paths = tuple(paths)
            self._native_fixed = (
                binding,
                self._native_paths,
                state.canonical(self._native_mount),
                storage._configuration(),
                os.getpid(),
            )
            self.freeze_fds()
            self.check_memberships()
            self.close_named()
            self.check_events()
            self.enumerated = False
        except BaseException as error:
            try:
                self.release()
            except BaseException:
                error.add_note("secondary native namespace observer release failure")
            raise

    def _file(self, path, value, paths):
        raw = state.canonical(value)
        item = self.file(path)
        require(type(item) is dict and self.raws[str(path)][0] == raw, "native-file")
        paths.append(path)

    def _mount(self, fd):
        facts = metadata.filesystem.statfs(fd)
        value = self._native_mount
        device = os.fstat(fd).st_dev
        require(
            metadata.filesystem.fd_mount_id(fd) == value["mount_id"]
            and [os.major(device), os.minor(device)] == value["device"]
            and all(facts[key] == value[key] for key in ("statfs_type", "statfs_fsid")),
            "native-destination-mount",
        )

    def close_named(self):
        def close():
            binding, paths, mount, configuration, pid = self._native_fixed
            require(
                binding.pair_key == self.pair_key
                and paths == self._native_paths
                and mount == state.canonical(self._native_mount)
                and configuration == storage._configuration()
                and pid == os.getpid(),
                "native-observer-memory",
            )
            super(_NativeSeal, self).close_named()
            for path in self._native_paths:
                self._mount(self.nodes[str(path)]["fd"])
                flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
                if self.nodes[str(path)]["kind"] == "directory":
                    flags |= os.O_DIRECTORY
                fd = (
                    os.open(path, flags)
                    if path == metadata.attempt._WALK_ROOT
                    else os.open(
                        path.name, flags, dir_fd=self.nodes[str(path.parent)]["fd"]
                    )
                )
                primary = None
                try:
                    self._mount(fd)
                except BaseException as error:
                    primary = error
                    raise
                finally:
                    try:
                        os.close(fd)
                    except BaseException:
                        if primary is None:
                            raise
                        primary.add_note(
                            "secondary native named descriptor close failure"
                        )

        self._check(close)


@contextmanager
def _observe_native_namespace(binding, mount, *, fixed):
    held = _NativeSeal(binding, mount, fixed=fixed)
    primary = None
    try:
        yield held
        if not held.enumerated:
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
            primary.add_note("secondary native namespace release failure")


class _NativeJournalSeal(_NativeSeal):
    """Exact quiet-boundary chain, including used slots; no journal writes."""

    def __init__(self, binding, mount, view):
        require(type(view) is journal.View, "journal-view")
        super().__init__(binding, mount, fixed=False)
        # New FDs must be releasable even if extended construction fails.
        self._held = None
        try:
            paths = list(self._native_paths)
            root = journal.RUNTIME_ROOT
            for name, identity in view.seal.directories.items():
                path = Path(name)
                require(
                    path == root.parent or path.is_relative_to(root), "native-view-path"
                )
                self._directory(path, private=True)
                require(
                    tuple(self.nodes[name]["identity"][:5]) == tuple(identity),
                    "native-view-directory",
                )
                paths.append(path)
            self.directory(root, shared=True)
            self.membership(root, shared=True)
            require(
                self.members[str(root)][1]
                == tuple(sorted(("runtime.json", binding.pair_key))),
                "native-root-members",
            )
            for name, names in view.seal.members.items():
                path = Path(name)
                require(
                    path.is_relative_to(root / binding.pair_key), "native-view-members"
                )
                self.exact_directory(
                    path,
                    names,
                    private=True,
                    expected=list(view.seal.directories[name]),
                )
            for name, identity in view.seal.files.items():
                path = Path(name)
                require(path.is_relative_to(root), "native-view-file")
                item = self.file(path)
                require(
                    type(item) is dict and tuple(item["identity"]) == tuple(identity),
                    "native-view-file-identity",
                )
                paths.append(path)
            self._native_paths = tuple(dict.fromkeys(paths))
            self._native_fixed = (
                binding,
                self._native_paths,
                state.canonical(self._native_mount),
                storage._configuration(),
                os.getpid(),
            )
            self.freeze_fds()
            self.check_memberships()
            self.close_named()
            self.check_events()
            self.enumerated = False
        except BaseException as error:
            try:
                self.release()
            except BaseException:
                error.add_note(
                    "secondary ready-journal observer construction cleanup failure"
                )
            raise


@contextmanager
def _observe_ready_journal(binding, mount, *, accepted_head_sha256):
    view = journal._inspect(binding, accepted_head_sha256)
    require(view.head["state"] == "ready", "ready-predecessor")
    held = _NativeJournalSeal(binding, mount, view)
    primary = None
    try:
        yield held
        if not held.enumerated:
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
            primary.add_note("secondary ready-journal observer release failure")


class _ImmutableNativeJournal(_NativeSeal):
    """Retain accepted history and each published phase across intended writes.

    HEAD and the new slot's membership are mutable only in the fixed primitive
    windows. Prior slots, all immutable files, and their event queues survive
    every window. This is a sole-writer adapter, not a syscall sandbox.
    """

    def __init__(self, binding, mount, view):
        require(
            type(view) is journal.View and view.head["state"] == "ready", "ready-view"
        )
        super().__init__(binding, mount, fixed=False)
        try:
            self.retain(view)
            root = journal.RUNTIME_ROOT
            self._held = None
            self.directory(root, shared=True)
            self.membership(root, shared=True)
            require(
                self.members[str(root)][1]
                == tuple(sorted(("runtime.json", binding.pair_key))),
                "native-root-members",
            )
            pair = root / binding.pair_key
            for name, names in view.seal.members.items():
                path = Path(name)
                if path != pair:
                    self.exact_directory(
                        path,
                        names,
                        private=True,
                        expected=list(view.seal.directories[name]),
                    )
            self.freeze_fds()
            self.check_memberships()
            self.close_named()
            self.check_events()
        except BaseException as error:
            try:
                self.release()
            except BaseException:
                error.add_note(
                    "secondary immutable journal construction cleanup failure"
                )
            raise

    def retain(self, view):
        """Add immutable files monotonically; never rebase an existing file."""
        require(type(view) is journal.View and not self.closed, "journal-view")
        self._held = None
        paths = list(self._native_paths)
        root = journal.RUNTIME_ROOT
        for name, identity in view.seal.directories.items():
            path = Path(name)
            require(
                path == root.parent or path.is_relative_to(root), "native-view-path"
            )
            self._directory(path, private=True)
            require(
                tuple(self.nodes[name]["identity"][:5]) == tuple(identity),
                "native-view-directory",
            )
            paths.append(path)
        for name, identity in view.seal.files.items():
            path = Path(name)
            require(path.is_relative_to(root), "native-view-file")
            if path == root / self.pair_key / "HEAD.json":
                continue
            if name not in self.raws:
                item = self.file(path)
                require(type(item) is dict, "native-view-file")
            require(
                tuple(self.nodes[name]["identity"]) == tuple(identity),
                "native-view-file-identity",
            )
            paths.append(path)
        self._native_paths = tuple(dict.fromkeys(paths))
        self._native_fixed = (
            self._native_fixed[0],
            self._native_paths,
            state.canonical(self._native_mount),
            storage._configuration(),
            os.getpid(),
        )
        self.freeze_fds()


class _NativeJournal:
    """One fixed native request, under the coordinator's real pair EX lease.

    A failed publication poisons the adapter. It never retries a primitive,
    adopts a new ambient HEAD, posts a request, or clears a failure barrier.
    The latest returned Pending is retained for the coordinator's failure path.
    """

    def __init__(self, binding, mount, accepted_head_sha256):
        self.binding = binding
        self.mount = observe.decode(state.canonical(mount))
        self.head = accepted_head_sha256
        self.pending = None
        self.candidate = None
        self.immutable = None
        self.quiet = None
        self.closed = False
        self.poisoned = False
        self._pid = os.getpid()
        try:
            view = journal._inspect(binding, accepted_head_sha256)
            self.immutable = _ImmutableNativeJournal(binding, self.mount, view)
            self.quiet = _NativeJournalSeal(binding, self.mount, view)
            self.check()
        except BaseException as error:
            try:
                self.release()
            except BaseException:
                error.add_note("secondary native journal constructor cleanup failure")
            raise

    def check(self):
        require(
            not self.closed and not self.poisoned and os.getpid() == self._pid,
            "journal-closed-or-poisoned",
        )
        try:
            require(
                self.immutable is not None and self.quiet is not None,
                "journal-boundary",
            )
            for held in (self.immutable, self.quiet):
                held.check_memberships()
            for held in (self.immutable, self.quiet):
                held.close_named()
            for held in (self.immutable, self.quiet):
                held.check_events()
        except BaseException:
            self.poisoned = True
            raise

    def _before(self, stage):
        require(not self.closed and not self.poisoned, "journal-closed-or-poisoned")
        count = -1 if self.pending is None else len(self.pending.phases.records)
        wanted = (
            -1
            if stage == "begin"
            else (
                len(journal.STAGES)
                if stage == "complete"
                else journal.STAGES.index(stage)
            )
        )
        require(count == wanted and self.candidate is None, "journal-stage")
        self.check()
        # From this point any exception is terminal for this adapter, including
        # a primitive that publishes successfully and then fails before return.
        self.poisoned = True
        self.quiet.release()
        self.quiet = None

    def _after(self, head):
        view = journal._inspect(self.binding, head)
        # Drain existing policies before arming guards for the new filenames.
        # Never clear or replace the immutable history observer/event queue.
        self.immutable.check_memberships()
        self.immutable.close_named()
        self.immutable.check_events()
        self.immutable.retain(view)
        self.quiet = _NativeJournalSeal(self.binding, self.mount, view)
        self.head = head
        self.poisoned = False
        self.check()

    def begin(self, *, kind, prepared_sha256):
        self._before("begin")
        self.pending = journal._begin(self.binding, self.head, kind, prepared_sha256)
        self._after(self.pending.pending_head_sha256)
        return self.pending

    def dispatch(self, payload):
        self._before("dispatch")
        self.pending = journal._append_phase(self.pending, "dispatch", payload)
        self._after(self.pending.pending_head_sha256)
        return self.pending

    def observed(self, payload):
        self._before("ack-observed")
        self.pending = journal._append_phase(self.pending, "ack-observed", payload)
        self._after(self.pending.pending_head_sha256)
        return self.pending

    def ack(self, payload):
        self._before("ack")
        self.pending = journal._append_phase(self.pending, "ack", payload)
        self._after(self.pending.pending_head_sha256)
        return self.pending

    def terminal(self, payload):
        self._before("terminal")
        self.pending = journal._append_phase(self.pending, "terminal", payload)
        self._after(self.pending.pending_head_sha256)
        return self.pending

    def complete(self, evidence):
        self._before("complete")
        self.candidate = journal._complete(self.pending, evidence)
        self._after(self.candidate.head_sha256)
        return self.candidate

    def release(self):
        if self.closed:
            return
        self.closed = True
        primary = None
        for held in (self.quiet, self.immutable):
            if held is not None:
                try:
                    held.release()
                except BaseException as error:
                    if primary is None:
                        primary = error
                    else:
                        primary.add_note(
                            "secondary native journal observer release failure"
                        )
        if primary is not None:
            raise primary


@contextmanager
def _native_journal(binding, mount, *, accepted_head_sha256):
    """Own local journal observers only; the coordinator owns all actual leases."""
    held = _NativeJournal(binding, mount, accepted_head_sha256)
    primary = None
    try:
        yield held
        held.check()
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            held.release()
        except BaseException:
            if primary is None:
                raise
            primary.add_note("secondary native journal release failure")
