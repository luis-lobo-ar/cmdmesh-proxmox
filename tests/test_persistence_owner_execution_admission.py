"""Real historical codecs; portable producer and FS assertions are synthetic.

No fixture authenticates an exporter or qualifies an installed filesystem. No
top-level admission, fence or Selection validator is replaced by these tests.
"""

import base64
import copy
import importlib
import os
from pathlib import Path
import stat
import struct
import sys
import unittest
from unittest import mock

import test_persistence_owner_fence as fixture
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_completion as completion,
    persistence_owner_retirement as r,
    persistence_owner_storage_profile as storage,
    persistence_owner_semantics as semantics,
)

PURE = False
PURE_ATTEMPTS = []


def audit(event, args):
    if PURE and (
        event == "open"
        or event.startswith(
            (
                "socket.",
                "subprocess.",
                "os.listdir",
                "os.scandir",
                "os.system",
                "os.posix_spawn",
            )
        )
    ):
        PURE_ATTEMPTS.append(event)
        raise RuntimeError("admission pure IO")


sys.addaudithook(audit)


def pure_call(function, *args, **kwargs):
    global PURE
    prior = PURE
    PURE = True
    try:
        return function(*args, **kwargs)
    finally:
        PURE = prior


def event(name, mask):
    raw = name.encode() + b"\0"
    raw += b"\0" * (-len(raw) % 16)
    return struct.pack("iIII", 1, mask, 0, len(raw)) + raw


def examples(model, codec):
    """Closed model inputs, never an accepted producer/FS qualification."""
    digest, canonical = model.digest, model.s.canonical
    source = lambda value: model.s.sha256(("modeled source " + value).encode())
    sdk = {
        "plugins/module_utils/persistence_owner_"
        + name
        + ".py": {
            "sha256": source(name),
            "bytes": 128,
        }
        for name in codec.SDK_ROLES
    }
    manifest = {
        "document_type": codec.MANIFEST_DOCUMENT,
        "schema_version": 1,
        "components": {
            "sdk": sdk,
            "node": {},
            "boundary": {"module.py": {"sha256": source("boundary"), "bytes": 128}},
            "recipe": {"playbook.yml": {"sha256": source("recipe"), "bytes": 128}},
            "controller": {
                "controller.py": {"sha256": source("controller"), "bytes": 128}
            },
            "verifier": {},
            "transport": {},
        },
    }
    epoch = copy.deepcopy(model.capture["before"]["current"]["observation"]["host"])
    epoch = {key: epoch[key] for key in ("boot_id", "mount_namespace")}
    decision, acceptance = source("external historical decision"), source(
        "H0 acceptance"
    )
    evidence = dict(
        phase="os_quiesced",
        host_epoch=epoch,
        current_sha256=digest(model.capture["before"]["current"]),
        worker_fence_sha256=decision,
        failure_provenance_sha256=model.authority["failure_provenance_sha256"],
        source_manifest_sha256=digest(model.authority["source_profile"]),
        accepted_prepared_sha256=model.authority["resume_prepared_sha256"],
    )
    with model.sdk.runtime.pair_lock.locked_pair(model.case.case.datasets):
        intent = r._prepare(
            model.owner,
            model.shutdown["operation_records"]["HEAD.json"].encode(),
            model.shutdown["head_sha256"],
            model.authority["legacy_basis_sha256"],
            canonical(evidence),
            digest(evidence),
        )
    intent_raw = canonical(intent)
    contract = completion.prepare_publication_contract(
        binding=model.owner,
        checkpoint=model.checkpoint,
        checkpoint_sha256=digest(model.checkpoint),
        intent_raw=intent_raw,
        intent_sha256=digest(intent),
        source_manifest_sha256=digest(manifest),
    )
    selection = semantics.select(
        binding=model.owner,
        checkpoint=model.checkpoint,
        checkpoint_sha256=digest(model.checkpoint),
        intent_raw=intent_raw,
        intent_sha256=digest(intent),
        contract_raw=contract.raw,
        contract_sha256=contract.sha256,
    )
    uid = r.legacy.ROOT_UID
    common = storage.RUNTIME_ROOT.parent
    identity = list(model.sdk.observe.stable(common.stat()))[:5]
    device = [os.major(identity[0]), os.minor(identity[0])]
    mount = dict(
        mount_id=100,
        parent_id=1,
        device=device,
        root="/",
        target="/",
        filesystem="ext4",
        source="/dev/example",
        options=["rw"],
        super_options=["rw"],
        statfs_type=0xEF53,
        statfs_fsid=[1, 2],
    )
    proc = dict(
        mount_id=101,
        parent_id=1,
        device=[0, 1],
        root="/",
        target="/proc",
        filesystem="proc",
        source="proc",
        options=["rw"],
        super_options=["rw"],
        statfs_type=0x9FA0,
        statfs_fsid=[0, 0],
    )
    parent = common / codec.PROBE_DIRECTORY / ("probe-" + "a" * 32)
    probe_id = [identity[0], 4242, stat.S_IFDIR | 0o700, uid, uid]
    before = [
        identity[0],
        4321,
        stat.S_IFREG | 0o600,
        uid,
        uid,
        0,
        len(codec.PROBE_PAYLOAD),
        1,
        1,
    ]
    final = [*before[:5], 1, len(codec.PROBE_PAYLOAD), 2, 2]

    def trace(raw):
        return dict(
            raw_base64=base64.b64encode(raw).decode(),
            bytes=len(raw),
            sha256=model.s.sha256(raw),
        )

    receipt = dict(
        path=str(parent / "atomic.json"),
        parent_identity=probe_id,
        anonymous_name="#4321",
        before_identity=before,
        final_identity=final,
        payload_sha256=model.s.sha256(codec.PROBE_PAYLOAD),
        payload_bytes=len(codec.PROBE_PAYLOAD),
        protocol=storage.PROTOCOL,
    )
    probe = dict(
        parent_path=str(parent),
        parent_identity=probe_id,
        mount_index=0,
        procedure="same-mount-disposable-atomic-event-v1",
        atomic_receipt=receipt,
        atomic_events=trace(
            event("#4321", 2) + event("atomic.json", 256) + event("#4321", 8)
        ),
        mkdir_events=trace(event("directory", 0x40000100)),
        named_samebyte_events=trace(event("atomic.json", 2) + event("atomic.json", 8)),
        transient_extra_events=trace(
            event("extra", 256) + event("extra", 8) + event("extra", 512)
        ),
        second_link_errno=17,
        closed_probe_provenance_sha256=source("closed probe"),
    )
    destinations = codec.destination_roles(selection)
    roles = {}
    for role, destination in destinations.items():
        parent_path = Path(destination).parent
        ancestor = (
            Path(r.legacy.RUNTIME_ROOT) / model.owner.pair_key
            if role == "legacy-marker"
            else common
        )
        roles[role] = dict(
            destination=destination,
            parent=str(parent_path),
            ancestor_path=str(ancestor),
            ancestor_identity=(
                intent["basis"]["directories"][""]
                if role == "legacy-marker"
                else identity
            ),
            missing_suffix=list(parent_path.relative_to(ancestor).parts),
            mount_index=0,
            probe_index=0,
        )
    filesystem = dict(
        document_type=codec.FILESYSTEM_DOCUMENT,
        schema_version=1,
        subject=dict(
            binding=r.asdict(model.owner),
            host_epoch=epoch,
            kernel_release="6.8.0-example",
            abi="linux64-procfd-v1",
        ),
        publication_protocol=storage.PROTOCOL,
        event_profile=codec.EVENT_PROFILE,
        runtime_profile_sha256=digest(storage.RUNTIME),
        primitives={
            name: sdk["plugins/module_utils/persistence_owner_" + name + ".py"][
                "sha256"
            ]
            for name in codec.PRIMITIVES
        },
        qualifier_producer_manifest_sha256=source("qualifier package"),
        qualifier_provenance_sha256=source("qualifier provenance"),
        logic_qualification_sha256=source("local logic proof"),
        procfs=dict(mount_index=1, type_magic=0x9FA0),
        mounts=[mount, proc],
        probes=[probe],
        roles=roles,
    )
    historical = dict(
        decision_sha256=decision,
        h0_acceptance_sha256=acceptance,
        authority_sha256=digest(model.authority),
        causal_capture_sha256=digest(model.capture),
        actor_capture_sha256=digest(model.capture["actors"]),
        closed_observation_sha256=source("closed observation"),
        review_sha256=source("review"),
        source_assessment_sha256=source("assessment"),
        historical_producer_cohort_sha256=source("historical producer"),
        source_profile_sha256=digest(model.profile),
        prepared_sha256=model.authority["resume_prepared_sha256"],
        failure_provenance_sha256=model.authority["failure_provenance_sha256"],
        basis_sha256=digest(intent["basis"]),
        predecessor_sha256=model.shutdown["head_sha256"],
        pending_head_sha256=model.basis["head_sha256"],
        host_epoch=epoch,
        candidate_upid=model.candidate,
        interval={
            key + "_current_sha256": digest(model.capture[key]["current"])
            for key in ("before", "closing")
        },
    )
    admission = dict(
        document_type=codec.ADMISSION_DOCUMENT,
        schema_version=1,
        subject=dict(
            binding=r.asdict(model.owner),
            checkpoint_sha256=digest(model.checkpoint),
            intent_sha256=digest(intent),
            publication_contract_sha256=contract.sha256,
        ),
        scope_profile=codec.SCOPE_PROFILE,
        conclusion=codec.CONCLUSION,
        historical_profile_id=codec.fence.PROFILE,
        historical=historical,
        execution=dict(
            producer_manifest_sha256=digest(manifest),
            filesystem_qualification_sha256=digest(filesystem),
            allowed_actions=sorted(codec.ACTIONS),
            completion_schema_version=2,
            runtime_profile_sha256=digest(storage.RUNTIME),
            publication_protocol=storage.PROTOCOL,
            event_profile=codec.EVENT_PROFILE,
            native_action_dispatched=False,
            successor_native_admission_authorized=False,
        ),
        arbitrary_root_or_cli_excluded=True,
        registry_archive_complete=False,
        original_native_operation_qualified=False,
        ack_recovered=False,
    )
    return selection, dict(
        admission=admission,
        historical_authority=model.authority,
        historical_capture=model.capture,
        producer_manifest=manifest,
        filesystem_qualification=filesystem,
    )


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class ExecutionAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.codec = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_execution_admission"
        )
        cls.model = fixture.OwnerFenceTests("runTest")
        cls.model.setUp()
        cls.addClassCleanup(cls.model.doCleanups)
        cls.patch_r = mock.patch.object(
            r, "RUNTIME_ROOT", r.legacy.RUNTIME_ROOT.parent / "handoff"
        )
        cls.patch_s = mock.patch.object(
            storage, "RUNTIME_ROOT", r.legacy.RUNTIME_ROOT.parent / "handoff"
        )
        cls.patch_r.start()
        cls.patch_s.start()
        cls.addClassCleanup(cls.patch_r.stop)
        cls.addClassCleanup(cls.patch_s.stop)
        cls.selection, cls.documents = examples(cls.model, cls.codec)

    def setUp(self):
        self.docs = copy.deepcopy(self.documents)

    def arguments(self, **changes):
        args = dict(selection=self.selection, action="begin")
        for name, value in self.docs.items():
            raw = self.model.s.canonical(value)
            args[name + "_raw"] = raw
            args[name + "_sha256"] = self.model.s.sha256(raw)
        args.update(changes)
        return args

    def load(self, **changes):
        return pure_call(
            self.codec.load_execution_admission, **self.arguments(**changes)
        )

    def test_complete_model_uses_real_causal_codec_without_io_or_permission(self):
        with mock.patch.object(
            self.codec.os, "open", side_effect=AssertionError("pure IO")
        ), mock.patch.object(
            self.codec.fence.observe, "native", side_effect=AssertionError("native")
        ):
            value = self.load()
            self.assertIsNone(pure_call(value.validate))
        self.assertEqual(value.action, "begin")
        self.assertEqual(value.admission_sha256, self.arguments()["admission_sha256"])
        with self.assertRaises((AttributeError, TypeError)):
            value.action = "inspect"
        self.assertEqual(PURE_ATTEMPTS, [])

    def test_overlay_option_656_bytes_and_4097_byte_refusal(self):
        fs = self.docs["filesystem_qualification"]
        fs["mounts"][0].update(
            filesystem="overlay",
            source="overlay",
            statfs_type=0x794C7630,
            super_options=["lowerdir=" + "x" * 647, "rw"],
        )
        self.docs["admission"]["execution"]["filesystem_qualification_sha256"] = (
            self.model.digest(fs)
        )
        self.load()
        fs["mounts"][0]["super_options"] = ["lowerdir=" + "x" * 4088, "rw"]
        self.docs["admission"]["execution"]["filesystem_qualification_sha256"] = (
            self.model.digest(fs)
        )
        with self.assertRaises(ValueError):
            self.load()

    def test_final_selection_memory_cannot_return_mutable_raw_alias(self):
        value = self.load()
        original = self.codec.semantics.Selection._memory
        calls = []

        def changed(selected):
            original(selected)
            if sys._getframe(1).f_locals.get("self") is value:
                calls.append(True)
                if len(calls) == 2:
                    object.__setattr__(
                        value, "admission_raw", bytearray(value.admission_raw)
                    )

        with mock.patch.object(
            self.codec.semantics.Selection, "_memory", changed
        ), self.assertRaises(ValueError):
            pure_call(value.validate)

    def test_all_fixed_actions_and_shared_probe_for_seven_destinations(self):
        for action in self.codec.ACTIONS:
            with self.subTest(action=action):
                self.assertEqual(self.load(action=action).action, action)

    def test_rehashed_historical_subject_and_scope_changes_refuse(self):
        for field in (
            "decision_sha256",
            "prepared_sha256",
            "source_profile_sha256",
            "actor_capture_sha256",
            "pending_head_sha256",
        ):
            self.docs = copy.deepcopy(self.documents)
            self.docs["admission"]["historical"][field] = "f" * 64
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load()
        self.docs = copy.deepcopy(self.documents)
        self.docs["admission"]["scope_profile"] = "arbitrary-root"
        with self.assertRaises(ValueError):
            self.load()

    def test_hash_canonical_bool_extra_and_missing_inputs_refuse(self):
        args = self.arguments()
        for change in (
            {"admission_sha256": "f" * 64},
            {"admission_raw": args["admission_raw"] + b" "},
            {"selection": object()},
            {"action": True},
        ):
            with self.subTest(change=tuple(change)), self.assertRaises(ValueError):
                self.load(**change)
        for fault in ("bool", "extra"):
            self.docs = copy.deepcopy(self.documents)
            if fault == "bool":
                self.docs["admission"]["schema_version"] = True
            else:
                self.docs["admission"]["permission"] = True
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.load()

    def test_manifest_absolute_paths_missing_roles_and_primitive_mismatch_refuse(self):
        for fault in ("absolute", "missing", "primitive"):
            self.docs = copy.deepcopy(self.documents)
            if fault == "absolute":
                self.docs["producer_manifest"]["components"]["sdk"][
                    "/workstation/source.py"
                ] = {"sha256": "f" * 64, "bytes": 1}
            elif fault == "missing":
                self.docs["producer_manifest"]["components"]["sdk"].pop(
                    next(iter(self.docs["producer_manifest"]["components"]["sdk"]))
                )
            else:
                self.docs["filesystem_qualification"]["primitives"]["atomic"] = "f" * 64
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.load()

    def test_changed_causal_actor_or_fresh_current_cannot_be_asserted_away(self):
        self.docs["historical_capture"]["closing"]["current"]["observation"][
            "application"
        ]["record_count"] += 1
        raw = self.model.s.canonical(self.docs["historical_capture"])
        self.docs["admission"]["historical"]["causal_capture_sha256"] = (
            self.model.s.sha256(raw)
        )
        with self.assertRaises(ValueError):
            self.load()

    def test_fs_role_path_mount_profile_and_probe_placement_refuse(self):
        for fault in ("path", "mount", "profile", "inside"):
            self.docs = copy.deepcopy(self.documents)
            fs = self.docs["filesystem_qualification"]
            if fault == "path":
                fs["roles"]["intent"]["destination"] += "-other"
            elif fault == "mount":
                fs["roles"]["legacy-marker"]["mount_index"] = 1
            elif fault == "profile":
                fs["publication_protocol"] = "fallback"
            else:
                fs["probes"][0]["parent_path"] = str(r.legacy.RUNTIME_ROOT / "probe")
            self.docs["admission"]["execution"]["filesystem_qualification_sha256"] = (
                self.model.digest(fs)
            )
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.load()

    def test_truncated_wrong_token_overflow_and_noncanonical_trace_refuse(self):
        for fault in ("truncated", "token", "overflow", "base64"):
            self.docs = copy.deepcopy(self.documents)
            fs = self.docs["filesystem_qualification"]
            trace = fs["probes"][0]["atomic_events"]
            raw = base64.b64decode(trace["raw_base64"])
            if fault == "truncated":
                raw = raw[:-1]
            elif fault == "token":
                raw = event("wrong", 2) + event("atomic.json", 256) + event("wrong", 8)
            elif fault == "overflow":
                raw = struct.pack("iIII", -1, 0x4000, 0, 0)
            trace.update(
                raw_base64=base64.b64encode(raw).decode(),
                bytes=len(raw),
                sha256=self.model.s.sha256(raw),
            )
            if fault == "base64":
                trace["raw_base64"] += "\n"
            self.docs["admission"]["execution"]["filesystem_qualification_sha256"] = (
                self.model.digest(fs)
            )
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.load()

    def test_action_not_selected_refuses(self):
        self.docs["admission"]["execution"]["allowed_actions"] = ["inspect"]
        with self.assertRaises(ValueError):
            self.load()
