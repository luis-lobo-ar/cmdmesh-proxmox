"""Self-leased initialization and developing native-v4 lifecycle machinery.

The caller authenticates its installed producer. NativeAdmission selects the
historical/source/storage assertions; actual observers and locks close before
returning a candidate. Preparation, native dispatch and status remain unfinished.
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
