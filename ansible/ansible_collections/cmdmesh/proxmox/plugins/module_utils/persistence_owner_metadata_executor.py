"""Self-leased, one-way metadata handoff execution, never an OS actuator.

Inputs authenticate selected assertions, not their exporter. A caller must
authenticate the portable installed producer and filesystem qualification.
Returns are closed candidates, never successor/native admission. Every error
leaves existing barriers intact; there is no compensation or automatic retry.
"""

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, asdict
import os
from pathlib import Path
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_attempt as attempt,
    persistence_owner_attempt_codec as codec,
    persistence_owner_begin as begin,
    persistence_owner_bootstrap as bootstrap,
    persistence_owner_completion as completion,
    persistence_owner_continuation as previous,
    persistence_owner_continuation_v2 as continuation,
    persistence_owner_current as current,
    persistence_owner_directory as directory,
    persistence_owner_execution_admission as admission_codec,
    persistence_owner_filesystem as filesystem,
    persistence_owner_phase_admission as phase_admission,
    persistence_owner_publication_witness as witness,
    persistence_owner_resources as resources,
    persistence_owner_semantics as semantics,
    persistence_owner_storage_profile as storage,
    persistence_owner_transition as transition,
)

r, runtime = semantics.r, current.runtime
WRITES = frozenset(
    {"begin", "finish-runtime", "record-intent", "publish-marker", "record-completion"}
)
VENDOR_PATHS = {
    "RESTEnvironment": "/usr/share/perl5/PVE/RESTEnvironment.pm",
    "UPID": "/usr/share/perl5/PVE/UPID.pm",
    "Cmd": "/usr/share/perl5/PVE/Cmd.pm",
    "LXC": "/usr/share/perl5/PVE/LXC.pm",
    "Storage": "/usr/share/perl5/PVE/Storage.pm",
    "StoragePlugin": "/usr/share/perl5/PVE/Storage/Plugin.pm",
    "DirPlugin": "/usr/share/perl5/PVE/Storage/DirPlugin.pm",
    "Tools": "/usr/share/perl5/PVE/Tools.pm",
    "LXCConfig": "/usr/share/perl5/PVE/LXC/Config.pm",
}


def require(value, code):
    r.require(value, "executor-" + code)


@dataclass(frozen=True, slots=True)
class Candidate:
    raw: bytes
    sha256: str


class _Stack(ExitStack):
    """Attempt every cleanup, retaining the first failure as the result."""

    def _push_exit_callback(self, callback, is_sync=True):
        def exit_callback(*details):
            try:
                return callback(*details)
            except BaseException as error:
                if self._primary is None:
                    self._primary = error
                elif error is not self._primary:
                    self._primary.add_note(
                        "secondary executor resource exit failure: "
                        + type(error).__name__
                    )
                raise self._primary

        super()._push_exit_callback(exit_callback, is_sync)

    def __exit__(self, kind, error, traceback):
        self._primary = error
        result = super().__exit__(kind, error, traceback)
        if error is None and self._primary is not None:
            raise self._primary
        return False if error is not None else result


def _decode(raw, sha):
    return admission_codec._decode(raw, sha, 33554432)


def _preflight(admission, phase, prior_raw, prior_sha, check_mode, allow_mutation=None):
    require(type(admission) is admission_codec.Admission, "admission")
    require(type(check_mode) is bool, "check-mode")
    if allow_mutation is not None:
        require(
            type(allow_mutation) is bool and allow_mutation and not check_mode,
            "mutation-mode",
        )
        require(admission.action in WRITES, "action")
    else:
        require(admission.action == "requalify-complete", "action")
    require(type(phase) is str and phase in {"os_quiesced", "stopped"}, "phase")
    admission.validate()
    prior = None
    if prior_raw is not None or prior_sha is not None:
        prior = _decode(prior_raw, prior_sha)
        current.validate_current(
            admission.selection._private_checkpoint,
            "os_quiesced",
            dict(phase="os_quiesced", observation=prior, guest_image_verified=True),
        )
    require(phase != "stopped" or prior is not None, "explicit-stopped-prior")
    return admission.selection, prior


class _Inputs:
    def __init__(self, admission, phase, prior, values):
        self.admission, self.selection = admission, admission.selection
        self.phase, self.prior = phase, prior
        self.values = tuple(values)
        self.snapshot = tuple(values)
        self.prior_raw = r.state.canonical(prior)
        self.pid = os.getpid()

    def close(self):
        self.admission.validate()
        self.fast()

    def fast(self):
        self.admission._memory()
        self.selection._memory()
        require(
            self.admission.selection is self.selection and os.getpid() == self.pid,
            "input-identity",
        )
        require(
            self.values == self.snapshot
            and all(type(a) is type(b) for a, b in zip(self.values, self.snapshot)),
            "input-memory",
        )
        require(r.state.canonical(self.prior) == self.prior_raw, "prior-memory")


def _control_file(reader, path, expected_sha, expected_identity=None, *, vendor=False):
    """Fixed selected control; only source-defined legacy/vendor 0644 exceptions."""
    path = Path(path)
    key = str(path)
    if key in reader.nodes:
        require(
            reader.raws[key][1] == expected_sha
            and (
                expected_identity is None
                or reader.nodes[key]["identity"] == expected_identity
            ),
            "duplicate-control",
        )
        return
    first = reader.entry(path)
    modes = {stat.S_IFREG | 0o600}
    if vendor or path.name == "legacy-guard.py":
        modes.add(stat.S_IFREG | 0o644)
    require(
        first is not None
        and first[2] in modes
        and first[3:6] == [r.legacy.ROOT_UID, r.legacy.ROOT_UID, 1],
        "control-policy",
    )
    require(expected_identity is None or first == expected_identity, "control-identity")
    limit = min(attempt.FILE_LIMIT, 33554432 - reader.budget)
    require(0 <= first[6] <= limit, "control-budget")
    fd = os.open(
        path.name,
        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=reader.nodes[str(path.parent)]["fd"],
    )
    try:
        require(attempt._identity(os.fstat(fd)) == first, "control-race")
        reader._watch(fd, ("file", ""))
        raw = bytearray()
        while chunk := os.read(fd, min(65536, limit + 1 - len(raw))):
            raw.extend(chunk)
            require(len(raw) <= limit, "control-budget")
        raw = bytes(raw)
        require(
            len(raw) == first[6]
            and attempt._identity(os.fstat(fd)) == first
            and r.state.sha256(raw) == expected_sha,
            "control-body",
        )
        reader.nodes[key] = dict(fd=fd, identity=first, prefix=9, kind="file")
        reader.raws[key] = raw, expected_sha
        reader.budget += len(raw)
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def _hold_actor_controls(admission):
    """Finite source/claim inventory already authenticated by Admission's codec."""
    selection = admission.selection
    actors = _decode(
        admission.historical_capture_raw, admission.historical_capture_sha256
    )["actors"]
    sources = _decode(
        admission.historical_authority_raw, admission.historical_authority_sha256
    )["source_profile"]["sources"]
    reader = resources._Seal(selection._private_binding.pair_key)
    primary = None
    try:
        for path, identity in actors["runtime_directories"].items():
            reader._directory(Path(path), private=True)
            require(
                reader.nodes[path]["identity"][:5] == identity,
                "actor-runtime-directory",
            )
        groups = list(actors["history_directories"].values()) + [
            actors[key] for key in ("writer", "blank_boot", "recipient", "attach")
        ]
        for group in groups:
            reader.exact_directory(
                Path(group["path"]),
                list(group["files"]),
                private=True,
                expected=group["identity"],
            )
            for name, item in group["files"].items():
                _control_file(
                    reader,
                    Path(group["path"]) / name,
                    r.state.sha256(item["raw"].encode("utf-8")),
                    item["identity"],
                )
        for group in (actors["history_files"], actors["runtime_files"]):
            for path, item in group.items():
                _control_file(
                    reader,
                    path,
                    r.state.sha256(item["raw"].encode("utf-8")),
                    item["identity"],
                )
        for role, path in VENDOR_PATHS.items():
            _control_file(reader, path, sources[role], vendor=True)
        reader.freeze_fds()
        view = resources._seal_view(reader)
        released = resources._seal_view(reader, released=True)
        reader.check_memberships()
        reader.close_named()
        reader.check_events()
        reader.enumerated = False
        yield reader
        if not reader.enumerated:
            reader.check_memberships()
        reader.close_named()
        require(resources._seal_view(reader) == view, "actor-memory")
        reader.check_events()
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            reader.release()
        except BaseException:
            if primary is None:
                raise
            primary.add_note("secondary actor observer release failure")
    require(
        not reader.poisoned and resources._seal_view(reader, released=True) == released,
        "actor-release-memory",
    )


def _descriptor(observation, path):
    body = r.observe.decode(observation.raw)
    item = body["files"][str(path)]
    return dict(path=str(path), sha256=item["sha256"], identity=item["identity"].copy())


def _frames(cp, scope, prior):
    return current._current_frames_leased(cp, scope.entry, scope.raw, prior)


def _evidence(frames, cp, phase):
    require(
        type(frames) is current._CurrentFrames
        and frames.completed
        and type(frames.closing_raw) is bytes,
        "closing-frame",
    )
    captured_raw = frames.closing_raw
    evidence = _decode(captured_raw, r.state.sha256(captured_raw))
    current.validate_current(cp, phase, evidence)
    require(
        type(frames.closing_raw) is bytes
        and frames.closing_raw == captured_raw
        and r.state.canonical(evidence) == captured_raw,
        "closing-frame-memory",
    )
    return evidence


def _fixed_close(cp, entry, evidence, prior):
    request, profile, _ = current._authority(cp)
    current.same(
        current.boot.root_identity(profile),
        profile["rootfs"]["identity"],
        "root-changed",
    )
    if entry["phase"] == "os_quiesced":
        init = evidence["observation"]["kernel"]["init"]
        require(
            runtime.kernel.reader.memory.init_state(init["pid"])
            == (init["pstart"], init["pid_namespace_inode"]),
            "init-changed",
        )
    else:
        current.same(
            current._empty_cgroup(request["policy"]["vmid"]),
            entry["stopped"]["cgroup"],
            "cgroup-changed",
        )
        require(
            current._prior_fence(entry["host"], prior)
            == entry["stopped"]["prior_fence"],
            "prior-fence-changed",
        )


def _post_worker(cp, scope, evidence, prior, holders, inputs):
    request, profile, _ = current._authority(cp)
    guard, _, _ = runtime.load_profile(request, profile)
    frame = evidence["observation"]
    retained = frame["retained" if scope.entry["phase"] == "os_quiesced" else "guarded"]
    path = Path(request["policy"]["datasets"]["data"]["mountpoint"]) / "ledger.sqlite3"
    runtime.seal_database(
        path,
        frame["application"]["database_sha256"],
        retained["application"]["database"],
    )
    # This SDK check contains enumeration. It MUST precede the joined stage.
    current._fast_close(request, profile, scope.entry, evidence, guard)
    inputs.close()
    for held in holders:
        held.check_memberships()
    joined = {}
    for held in holders:
        readers = held._seals if type(held) is resources._Resources else (held,)
        for reader in readers:
            for path, node in getattr(reader, "nodes", {}).items():
                if path in joined:
                    before = joined[path]
                    n = min(node["prefix"], before["prefix"])
                    require(
                        node["kind"] == before["kind"]
                        and node["identity"][:n] == before["identity"][:n],
                        "observer-conflict",
                    )
                else:
                    joined[path] = node
    for held in holders:
        held.close_named()
    _fixed_close(cp, scope.entry, evidence, prior)
    require(scope.pending is None, "legacy-pending")
    inputs.fast()
    for held in holders:
        held.check_events()


def _publication(stack, selection, action, complete=None):
    kwargs = selection._arguments()
    if complete is not None:
        kwargs.update(complete_raw=complete.raw, complete_sha256=complete.sha256)
    return stack.enter_context(
        witness.observe_control_publication_v2(
            **kwargs, action=action, event_profile=witness.EVENT_PROFILE
        )
    )


def _publish(admission, fs, publication, role):
    filesystem.assert_destination_parent(
        admission=admission, subject=fs, role=role, fd=publication.fd
    )
    publication.publish()


def _create(admission, fs, birth, role):
    filesystem.assert_destination_parent(
        admission=admission, subject=fs, role=role, fd=birth.fd
    )
    birth.create()


def _candidate(
    admission,
    phase,
    e1,
    e2,
    post,
    receipts,
    *,
    requalification=False,
    complete_sha=None,
):
    value = dict(
        document_type="cmdmesh.proxmox.owner-metadata-execution-candidate",
        schema_version=1,
        action=admission.action,
        admission_sha256=admission.admission_sha256,
        checkpoint_sha256=admission.selection.checkpoint_sha256,
        intent_sha256=admission.selection._intent_sha256,
        publication_contract_sha256=admission.selection.contract_sha256,
        phase=phase,
        initial_closing_current=e1,
        final_closing_current=e2,
        final_capture_sha256=post.sha256,
        final_capture=r.observe.decode(post.raw),
        publication_receipts=receipts,
        complete_sha256=complete_sha,
        readonly=requalification,
        metadata_publications_completed=not requalification,
        requalification_candidate=requalification,
        candidate_only=True,
        original_native_operation_qualified=False,
        ack_recovered=False,
        native_action_dispatched=False,
        successor_native_admission_authorized=False,
        metadata_acceptance_authorized=False,
    )
    raw = r.state.canonical(value)
    require(0 < len(raw) <= 33554432, "output-budget")
    return Candidate(raw, r.state.sha256(raw))


def _execute(
    *,
    admission,
    capture_raw,
    capture_sha256,
    plan_raw,
    plan_sha256,
    phase,
    prior_runtime_raw,
    prior_runtime_sha256,
    allow_mutation,
    check_mode,
    beginning,
):
    selection, prior = _preflight(
        admission,
        phase,
        prior_runtime_raw,
        prior_runtime_sha256,
        check_mode,
        allow_mutation,
    )
    require((admission.action == "begin") is beginning, "entry-action")
    args = selection._arguments()
    plan_args = dict(
        **args,
        capture_raw=capture_raw,
        capture_sha256=capture_sha256,
        plan_raw=plan_raw,
        plan_sha256=plan_sha256,
    )
    plan = (
        begin.load_begin(**plan_args)
        if beginning
        else continuation.load_continuation(**plan_args, action=admission.action)
    )
    inputs = _Inputs(
        admission,
        phase,
        prior,
        (
            capture_raw,
            capture_sha256,
            plan_raw,
            plan_sha256,
            phase,
            allow_mutation,
            check_mode,
        ),
    )
    cp = selection._private_checkpoint
    receipts = []
    complete = None
    with transition._leased(cp, phase, prior) as scope:
        require(scope.pending is None, "legacy-pending")
        entry_raw = r.state.canonical(scope.entry)
        scope_raw = scope.raw
        scope_request = r.state.canonical(scope.request)
        with _Stack() as permanent:
            # Full old/new absence and transient-entry coverage begins before
            # the projected-old/resource setup, not after its metadata reads.
            initial_inspector = _Stack()
            permanent.callback(initial_inspector.close)
            fresh = initial_inspector.enter_context(attempt.inspect_attempt_v2(**args))
            held = permanent.enter_context(
                resources.hold_owner_resources(
                    selection=selection, entry=scope.entry, action=admission.action
                )
            )
            actors = permanent.enter_context(_hold_actor_controls(admission))
            fs = permanent.enter_context(
                filesystem.hold_qualified_subject(
                    selection=selection, admission=admission
                )
            )
            fs_epoch = _decode(fs.raw, fs.sha256)["subject"]["host_epoch"]
            require(
                fs_epoch
                == {
                    key: scope.entry["host"][key]
                    for key in ("boot_id", "mount_namespace")
                },
                "filesystem-host-epoch",
            )
            with _Stack() as publications:
                with initial_inspector:
                    fresh_body = codec.validate_capture_v2(
                        **args, capture_raw=fresh.raw, capture_sha256=fresh.sha256
                    )
                    require(
                        r.digest(previous._projection(fresh_body))
                        == plan["expected_fresh_projection_sha256"],
                        "fresh-projection",
                    )
                    birth_stack = _Stack()
                    permanent.callback(birth_stack.close)
                    birth = None
                    pub = None
                    if beginning:
                        role = (
                            "runtime-root"
                            if plan["bootstrap_mutex"] is not None
                            else "pair"
                        )
                        birth = birth_stack.enter_context(
                            directory.observe_directory_creation_v2(**args, role=role)
                        )
                    elif admission.action != "record-completion":
                        pub = _publication(publications, selection, admission.action)
                    with _frames(cp, scope, prior) as first:
                        pass
                    e1 = _evidence(first, cp, phase)
                    phase_admission.validate_phase_admission(
                        cp, phase, e1, scope.entry, prior
                    )
                    if admission.action == "record-completion":
                        pair = (
                            storage.RUNTIME_ROOT / selection._private_binding.pair_key
                        )
                        marker = (
                            r.legacy.RUNTIME_ROOT
                            / selection._private_binding.pair_key
                            / storage.MARKER
                        )
                        contract = _decode(
                            selection._contract_raw, selection.contract_sha256
                        )
                        complete = completion.prepare_completion(
                            **args,
                            intent_file=_descriptor(fresh, pair / "intent.json"),
                            marker_file=_descriptor(fresh, marker),
                            closing=dict(
                                phase=phase,
                                host_epoch={
                                    key: e1["observation"]["host"][key]
                                    for key in ("boot_id", "mount_namespace")
                                },
                                current=e1,
                                admission=dict(entry=scope.entry, prior_runtime=prior),
                                source_manifest_sha256=contract[
                                    "source_manifest_sha256"
                                ],
                            ),
                        )
                        pub = _publication(
                            publications, selection, admission.action, complete
                        )
                    # The exact inspector remains active until its replacement
                    # Birth/W2 is armed; it exits BEFORE our intentional writes.
                with _frames(cp, scope, prior) as second:
                    # The C2 first worker is still before any intentional
                    # publication. Refuse stale old/reference/DB/source facts
                    # here, including mutation events with identical bytes.
                    before_write = _decode(
                        second.initial_raw, r.state.sha256(second.initial_raw)
                    )
                    phase_admission.validate_phase_admission(
                        cp, phase, before_write, scope.entry, prior
                    )
                    _post_worker(
                        cp, scope, before_write, prior, [held, actors, fs], inputs
                    )
                    if beginning:
                        if plan["bootstrap_mutex"] is not None:
                            common = fs._subject._reader.nodes[
                                str(storage.RUNTIME_ROOT.parent)
                            ]["fd"]
                            filesystem.assert_destination_parent(
                                admission=admission,
                                subject=fs,
                                role="bootstrap-lock",
                                fd=common,
                            )
                            with bootstrap.locked_runtime_bootstrap(initialize=True):
                                _create(admission, fs, birth, "runtime-directory")
                                with _Stack() as runtime_stack:
                                    runtime_pub = _publication(
                                        runtime_stack, selection, "finish-runtime"
                                    )
                                    birth_stack.close()
                                    _publish(
                                        admission, fs, runtime_pub, "runtime-profile"
                                    )
                                    receipts.append(asdict(runtime_pub.receipt))
                                    birth = birth_stack.enter_context(
                                        directory.observe_directory_creation_v2(
                                            **args, role="pair"
                                        )
                                    )
                            # Global bootstrap ends before pair mkdir or SQL.
                        _create(admission, fs, birth, "pair-directory")
                        pub = _publication(publications, selection, "record-intent")
                        birth_stack.close()
                        _publish(admission, fs, pub, "intent")
                    else:
                        role = {
                            "finish-runtime": "runtime-profile",
                            "record-intent": "intent",
                            "publish-marker": "legacy-marker",
                            "record-completion": "completion",
                        }[admission.action]
                        if admission.action == "finish-runtime":
                            common = fs._subject._reader.nodes[
                                str(storage.RUNTIME_ROOT.parent)
                            ]["fd"]
                            filesystem.assert_destination_parent(
                                admission=admission,
                                subject=fs,
                                role="bootstrap-lock",
                                fd=common,
                            )
                            with bootstrap.locked_runtime_bootstrap(initialize=True):
                                _publish(admission, fs, pub, role)
                        else:
                            _publish(admission, fs, pub, role)
                    receipts.append(asdict(pub.receipt))
                    post = permanent.enter_context(attempt.inspect_attempt_v2(**args))
                e2 = _evidence(second, cp, phase)
                phase_admission.validate_phase_admission(
                    cp, phase, e2, scope.entry, prior
                )
                require(r.state.canonical(scope.entry) == entry_raw, "entry-memory")
                result = _candidate(
                    admission,
                    phase,
                    e1,
                    e2,
                    post,
                    receipts,
                    complete_sha=None if complete is None else complete.sha256,
                )
                result_snapshot = result.raw, result.sha256
                _post_worker(
                    cp, scope, e2, prior, [held, actors, fs, post.seal, pub], inputs
                )
            inputs.fast()
        require(
            scope.pending is None and r.state.canonical(scope.entry) == entry_raw,
            "scope-memory",
        )
    inputs.fast()
    require(
        scope.pending is None
        and type(scope.raw) is bytes
        and scope.raw == scope_raw
        and r.state.canonical(scope.request) == scope_request
        and r.state.canonical(scope.entry) == entry_raw,
        "lease-exit-memory",
    )
    require(
        type(result.raw) is bytes and (result.raw, result.sha256) == result_snapshot,
        "output-memory",
    )
    return result


def execute_begin(
    *,
    admission,
    capture_raw,
    capture_sha256,
    plan_raw,
    plan_sha256,
    phase,
    prior_runtime_raw=None,
    prior_runtime_sha256=None,
    allow_mutation=False,
    check_mode=False,
):
    return _execute(**locals(), beginning=True)


def execute_continuation(
    *,
    admission,
    capture_raw,
    capture_sha256,
    plan_raw,
    plan_sha256,
    phase,
    prior_runtime_raw=None,
    prior_runtime_sha256=None,
    allow_mutation=False,
    check_mode=False,
):
    return _execute(**locals(), beginning=False)


def requalify_complete(
    *,
    admission,
    capture_raw,
    capture_sha256,
    complete_raw,
    complete_sha256,
    phase,
    prior_runtime_raw=None,
    prior_runtime_sha256=None,
    original_contract_raw=None,
    original_contract_sha256=None,
    check_mode=False,
):
    """Fresh read-only candidate; never repairs/replaces a lost callback or ACK.

    Runtime1 is deliberately not normalized to runtime2. Its explicit immutable
    forensic path validates the old completion codec and exact retained files.
    """
    selection, prior = _preflight(
        admission, phase, prior_runtime_raw, prior_runtime_sha256, check_mode
    )
    selected = _decode(complete_raw, complete_sha256)
    historical = selection
    if selected.get("schema_version") == 2:
        require(
            original_contract_raw is not None and original_contract_sha256 is not None,
            "original-contract",
        )
        original_args = selection._arguments()
        original_args.update(
            contract_raw=original_contract_raw, contract_sha256=original_contract_sha256
        )
        historical = semantics.select(**original_args)
        historical.completion(complete_raw, complete_sha256)
    else:
        require(
            original_contract_raw is None and original_contract_sha256 is None,
            "historical-contract",
        )
        selection.completion(complete_raw, complete_sha256, allow_historical=True)
    # Do not feed a schema1/blocked capture into the normal capture2 planner.
    expected = _requalification_capture(historical, capture_raw, capture_sha256)
    inputs = _Inputs(
        admission,
        phase,
        prior,
        (
            capture_raw,
            capture_sha256,
            complete_raw,
            complete_sha256,
            original_contract_raw,
            original_contract_sha256,
        ),
    )
    cp = selection._private_checkpoint
    with transition._leased(cp, phase, prior) as scope:
        entry_raw = r.state.canonical(scope.entry)
        scope_raw = scope.raw
        scope_request = r.state.canonical(scope.request)
        with _Stack() as stack:
            observed = stack.enter_context(
                _complete_forensics(historical, complete_raw, complete_sha256)
            )
            held = stack.enter_context(
                resources.hold_owner_resources(
                    selection=selection, entry=scope.entry, action="requalify-complete"
                )
            )
            actors = stack.enter_context(_hold_actor_controls(admission))
            require(
                previous._projection(r.observe.decode(observed.raw))
                == previous._projection(expected),
                "requalification-projection",
            )
            with _frames(cp, scope, prior) as first:
                pass
            e1 = _evidence(first, cp, phase)
            with _frames(cp, scope, prior) as second:
                pass
            e2 = _evidence(second, cp, phase)
            phase_admission.validate_phase_admission(cp, phase, e2, scope.entry, prior)
            result = _candidate(
                admission,
                phase,
                e1,
                e2,
                observed,
                [],
                requalification=True,
                complete_sha=complete_sha256,
            )
            result_snapshot = result.raw, result.sha256
            _post_worker(cp, scope, e2, prior, [held, actors, observed.seal], inputs)
        require(scope.pending is None, "legacy-pending")
    inputs.fast()
    historical._memory()
    require(
        scope.pending is None
        and type(scope.raw) is bytes
        and scope.raw == scope_raw
        and r.state.canonical(scope.request) == scope_request
        and r.state.canonical(scope.entry) == entry_raw,
        "lease-exit-memory",
    )
    require(
        type(result.raw) is bytes and (result.raw, result.sha256) == result_snapshot,
        "output-memory",
    )
    return result


@contextmanager
def _complete_forensics(selection, complete_raw, complete_sha):
    """Strict v2 inspector, or a separately named historical runtime1 projection."""
    with attempt.inspect_attempt_v2(**selection._arguments()) as observed:
        body = _requalification_capture(selection, observed.raw, observed.sha256)
        path = (
            storage.RUNTIME_ROOT / selection._private_binding.pair_key / "complete.json"
        )
        item = body["files"][str(path)]
        require(
            item["sha256"] == complete_sha
            and observed.seal.raws[str(path)][0] == complete_raw,
            "selected-completion",
        )
        yield observed


def _requalification_capture(selection, raw, sha):
    """Replay one explicit historical exception without changing its status.

    The ordinary codec continues to reject all blocked/runtime1 captures. Here
    only a complete, sound H1v1 with exactly the legacy-profile blocked reason
    can be returned, still labelled blocked in the preserved forensic bytes.
    """
    body = _decode(raw, sha)
    if body.get("status") == "complete-candidate":
        return codec.validate_capture_v2(
            **selection._arguments(), capture_raw=raw, capture_sha256=sha
        )
    r.state.keys(body, codec._FIELDS_V2)
    require(
        body["status"] == "blocked"
        and body["runtime_profile"] == "legacy-v1"
        and body["blocked_reasons"] == ["legacy-runtime-profile"]
        and body["unsafe_entries"] == {}
        and body["unknown_entries"] == {}
        and type(body["completion_schema_version"]) is int
        and body["completion_schema_version"] == 1
        and body["completion_disposition"] == "historical-requalification-required",
        "historical-v1-complete-only",
    )
    owner = selection._private_binding
    intent = r._intent(owner, selection._intent_raw, selection._intent_sha256)
    reader = codec._MemoryReader(body, owner, intent)
    reconstructed = attempt._collect(
        reader,
        owner,
        intent,
        selection._intent_raw,
        selection._intent_sha256,
        selection,
    )
    require(r.state.canonical(reconstructed) == raw, "historical-reconstruction")
    selection.validate()
    require(
        r.state.canonical(body) == raw and r.state.canonical(reconstructed) == raw,
        "historical-memory",
    )
    return body
