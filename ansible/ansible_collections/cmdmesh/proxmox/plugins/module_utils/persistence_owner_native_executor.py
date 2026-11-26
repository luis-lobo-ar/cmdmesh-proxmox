"""Private lease machinery for the developing native-v4 coordinator.

There is no admitted initializer, preparation, dispatch or status API yet. These
helpers acquire real locks but do not authenticate installed producer/storage
qualifications or grant native permission. Legacy journal state is never used
for v4 failure reporting.
"""

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
import os
from pathlib import Path

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_current as current,
    persistence_owner_metadata_executor as metadata,
    persistence_owner_native_handoff as handoffs,
    persistence_owner_phase_admission as phases,
    persistence_owner_request_journal as journal,
)

runtime, state, observe = current.runtime, current.state, current.observe


def require(value, code):
    state.require(value, "persistence-owner-native-executor-" + code)


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
