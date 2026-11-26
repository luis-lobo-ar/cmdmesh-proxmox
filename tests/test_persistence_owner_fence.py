"""Complete semantic capture uses real temporary journals and existing codecs.

Native observations and the externally accepted source/scope profile are modeled.
Neither this fixture nor the pure return is a managed recovery certificate.
"""

import copy
import importlib
import json
import os
from pathlib import Path
import stat
import unittest
from unittest import mock

import test_persistence_owner_checkpoint as checkpoint_fixture
import test_persistence_owner_transition as transition_fixture
import test_persistence_owner_reaper as reaper_fixture
import test_persistence_recipient as recipient_fixture
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_blank_boot as blank,
    persistence_recipient as recipient,
    persistence_attach as attach,
    persistence_owner_retirement as retirement,
)

SOURCES = (
    "owner_transition",
    "owner_journal",
    "guest_api",
    "retained_boot",
    "blank_boot",
    "recipient",
    "writer_execution",
    "attach",
    "owner_publish",
    "owner_reconcile",
    "controller_boundary",
    "RESTEnvironment",
    "UPID",
    "Cmd",
    "LXC",
    "Storage",
    "StoragePlugin",
    "DirPlugin",
    "Tools",
    "LXCConfig",
)
PROFILE = "owner-v3-ack-clock-local-dir-v1"
SCOPE = "cooperating-owner-actors-only-throughout-interval"


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class OwnerFenceTests(unittest.TestCase):
    def setUp(self):
        self.cp_case = checkpoint_fixture.OwnerCheckpointTests("runTest")
        self.cp_case.setUp()
        self.addCleanup(self.cp_case.doCleanups)
        self.checkpoint = self.cp_case.load()
        self.case = transition_fixture.OwnerTransitionTests("runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.sdk = self.case.sdk
        self.s = self.sdk.state
        self.enterContext(
            mock.patch.object(
                self.sdk.observe,
                "locked_config_original",
                self.cp_case.base.fixture.locked_config,
            )
        )
        self.case.checkpoint = self.checkpoint
        model = self.case.model
        model.authority = self.checkpoint
        model.request = self.checkpoint["prepared"]["source_request"]
        model.profile = self.checkpoint["prepared"]["image_profile"]
        model.frame = copy.deepcopy(self.checkpoint["completion"]["runtime"])
        self.case.entry.update(
            host=copy.deepcopy(model.frame["host"]),
            guest=copy.deepcopy(model.frame["guest"]),
        )
        self.owner = self.sdk.binding(self.checkpoint)
        self.case.case.binding = self.owner
        self.case.case.datasets = model.request["policy"]["datasets"]
        self.enterContext(
            mock.patch.object(retirement.legacy, "ROOT_UID", os.geteuid())
        )
        with self.sdk.runtime.pair_lock.locked_pair(
            self.case.case.datasets, initialize=True
        ):
            pass
        genesis = self.case.initialize()
        self.shutdown_prepared = self.case.prepare(genesis)
        self.shutdown = self.case.operate(self.shutdown_prepared)
        if getattr(self, "resume_epoch_override", None) is not None:
            model.frame["host"]["boot_id"] = self.resume_epoch_override
            self.case.entry["host"]["boot_id"] = self.resume_epoch_override
        self.resume = self.case.prepare(self.shutdown["head_sha256"], "resume")
        original_post = self.case.post

        def delayed(binding, action):
            self.case.native_clock += 61
            value = original_post(binding, action)
            self.candidate = value["upid"]
            return value

        with mock.patch.object(self.sdk.api, "post_guest_action", side_effect=delayed):
            with self.assertRaisesRegex(ValueError, "ack-clock"):
                self.case.operate(self.resume)
        with self.sdk.runtime.pair_lock.locked_pair(self.case.case.datasets):
            self.basis, self.legacy_raw, shared, marker, _ = retirement._capture(
                self.owner
            )
        self.assertIsNone(marker)
        self.shared = shared
        self.raw = lambda value: self.s.canonical(value).decode()
        self.digest = lambda value: self.s.sha256(self.s.canonical(value))
        self.profile = {
            "id": PROFILE,
            "scope": SCOPE,
            "sources": {
                name: self.s.sha256(("modeled reviewed source " + name).encode())
                for name in SOURCES
            },
            "extra_claims": {},
        }
        self.actors = self.actor_capture()
        slot = retirement.legacy._slot(self.basis["maximum_sequence"])
        dispatch_sha = self.basis["files"][slot + "/dispatch.json"]["sha256"]
        self.provenance = {
            "document_type": "cmdmesh.proxmox.owner-post-return-failure",
            "schema_version": 1,
            "error_code": "persistence-owner-journal-ack-clock",
            "checkpoint_sha256": self.digest(self.checkpoint),
            "prepared_sha256": self.digest(self.resume),
            "dispatch_sha256": dispatch_sha,
            "source_profile_sha256": self.digest(self.profile),
            "receipt_sha256": "e" * 64,
            "mutation_attempted": True,
            "effects_may_exist": True,
            "command_outcome": "unknown",
            "os_transition_verified": False,
        }
        self.authority = {
            "document_type": "cmdmesh.proxmox.owner-causal-authority",
            "schema_version": 1,
            "checkpoint_sha256": self.digest(self.checkpoint),
            "writer_prepared_sha256": self.checkpoint["prepared_sha256"],
            "writer_completion_sha256": self.checkpoint["completion_sha256"],
            "shutdown_prepared_sha256": self.digest(self.shutdown_prepared),
            "shutdown_result_sha256": self.digest(self.shutdown),
            "shutdown_head_sha256": self.shutdown["head_sha256"],
            "resume_prepared_sha256": self.digest(self.resume),
            "failure_provenance_sha256": self.digest(self.provenance),
            "legacy_basis_sha256": self.digest(self.basis),
            "source_profile": self.profile,
        }
        current = self.case.model.evidence()
        init = current["observation"]["kernel"]["init"]
        init.update(
            pid=init["pid"] + 123,
            pstart=init["pstart"] + 100,
            pid_namespace_inode=init["pid_namespace_inode"] + 100,
        )
        current["observation"]["guest"]["runtime"]["pid"] = init["pid"]
        self.sdk.current.validate_current(self.checkpoint, "os_quiesced", current)
        reaper = reaper_fixture.OwnerReaperTests("runTest")
        reaper.setUp()
        reaper.binding, reaper.upid = self.owner.guest, self.candidate
        reaper.boot = current["observation"]["host"]["boot_id"]
        reaper.sources = self.digest(self.profile)
        normal = reaper.evidence(warnings=False)
        normal["events"][1]["_PID"] = str(
            self.sdk.api.parse_upid(self.owner.guest, self.candidate)["pid"]
        )
        normal["events"][1][
            "MESSAGE"
        ] = f"starting CT {self.owner.guest.vmid}: {self.candidate}"
        normal["events"][1]["_COMM"] = ("task UPID:" + self.owner.guest.node)[:15]
        self.capture = {
            "document_type": "cmdmesh.proxmox.owner-causal-capture",
            "schema_version": 1,
            "checkpoint": {
                "prepared": self.cp_case.base.raw.decode(),
                "completion": self.cp_case.raw.decode(),
                "records": {
                    name: raw.decode() for name, raw in self.cp_case.records.items()
                },
            },
            "shutdown": {
                "prepared": self.raw(self.shutdown_prepared),
                "result": self.raw(self.shutdown),
            },
            "failed_resume": {
                "prepared": self.raw(self.resume),
                "provenance": self.raw(self.provenance),
            },
            "legacy": {
                "basis": self.basis,
                "records": {
                    name: raw.decode() for name, raw in self.legacy_raw.items()
                },
                "runtime": self.file_capture(
                    Path(shared["path"]).read_bytes(),
                    shared["identity"],
                    shared["path"],
                ),
                "directories": {
                    str(path): list(self.sdk.observe.stable(path.lstat()))[:5]
                    for path in (
                        retirement.legacy.RUNTIME_ROOT.parent,
                        retirement.legacy.RUNTIME_ROOT,
                    )
                },
            },
            "actors": self.actors,
            "normal_return": self.raw(normal),
            "before": {"current": current, "projection": self.projection(current)},
            "closing": {
                "current": copy.deepcopy(current),
                "projection": self.projection(current),
            },
        }
        self.capture["closing"]["current"]["observation"]["guest"]["runtime"][
            "uptime"
        ] += 1

    def file_capture(self, raw, identity=None, path=None):
        result = {
            "raw": raw.decode(),
            "identity": (
                list(identity)
                if identity
                else [
                    1,
                    700,
                    stat.S_IFREG | 0o600,
                    os.geteuid(),
                    os.geteuid(),
                    1,
                    len(raw),
                    1,
                    1,
                ]
            ),
        }
        if path is not None:
            result["path"] = str(path)
        return result

    def directory_capture(self, files, identity=None, path=None):
        result = {
            "identity": (
                list(identity)[:5]
                if identity
                else [1, 800, stat.S_IFDIR | 0o700, os.geteuid(), os.geteuid()]
            ),
            "files": files,
        }
        if path is not None:
            result["path"] = str(path)
        return result

    def extra_claim(self, name, prepared, files):
        prepared_sha = self.digest(prepared)
        files["intent.json"] = self.s.canonical(
            {"prepared": prepared, "prepared_sha256": prepared_sha}
        )
        self.profile["extra_claims"][name] = {
            "prepared_sha256": prepared_sha,
            "files": {
                key: {"sha256": self.s.sha256(raw), "bytes": len(raw)}
                for key, raw in files.items()
            },
        }
        key = (
            self.owner.pair_key
            if name == "attach"
            else self.digest(
                [self.owner.guest.machine_id_sha256, self.owner.guest.vmid]
            )
        )
        root = {
            "attach": attach.RUNTIME_ROOT,
            "blank_boot": blank.RUNTIME_ROOT,
            "recipient": recipient.RUNTIME_ROOT,
        }[name]
        return self.directory_capture(
            {key: self.file_capture(raw) for key, raw in files.items()}, path=root / key
        )

    def actor_capture(self):
        prepared, completed = self.checkpoint["prepared"], self.checkpoint["completion"]
        history = prepared["history"]
        result = {
            "history_directories": {
                path: self.directory_capture(
                    {
                        name: self.file_capture(
                            Path(item["path"]).read_bytes(), item["identity"]
                        )
                        for name, item in group["files"].items()
                    },
                    group["identity"],
                    path,
                )
                for path, group in history["directories"].items()
            },
            "history_files": {
                path: self.file_capture(Path(path).read_bytes(), item["identity"], path)
                for path, item in history["files"].items()
            },
            "writer": self.directory_capture(
                {
                    name: self.file_capture(
                        raw,
                        (
                            completed["journal_files"][name]["identity"]
                            if name != "complete.json"
                            else None
                        ),
                    )
                    for name, raw in self.cp_case.records.items()
                },
                completed["claim_directory_identity"],
                self.sdk.writer.trial.claim_path(prepared["source_request"]),
            ),
        }
        request = recipient_fixture.example_request()
        request["source_request"]["source"] = copy.deepcopy(
            prepared["source_request"]["source"]
        )
        request["source_request"]["source"]["selector"]["vmid"] = prepared[
            "source_request"
        ]["policy"]["retired_guest"]["vmid"]
        request["target"]["vmid"] = self.owner.guest.vmid
        ack_base = f"UPID:{self.owner.guest.node}:00000200:00000001:6553F000:"
        blank_prepared = {
            "stage_prepared": {"recipient_prepared": {"request": request}},
            "policy": {"vmid": self.owner.guest.vmid},
        }
        result["blank_boot"] = self.extra_claim(
            "blank_boot",
            blank_prepared,
            {
                "write-possible.json": self.s.canonical(
                    {"vmid": self.owner.guest.vmid}
                ),
                "dispatch.json": self.s.canonical({"clock": 1699999744}),
                "acknowledgement.json": self.s.canonical(
                    {
                        "upid": ack_base + f"vzstart:{self.owner.guest.vmid}:root@pam:",
                        "tls_verified": True,
                    }
                ),
                "failed.json": self.s.canonical({"phase": "failed"}),
                "guard.py": blank.guard_source(),
                "policy.json": self.s.canonical(blank_prepared["policy"]),
            },
        )
        result["recipient"] = self.extra_claim(
            "recipient",
            {"request": request},
            {
                "write-possible.json": self.s.canonical(
                    {"operation_id": request["operation_id"]}
                ),
                "dispatch.json": self.s.canonical(
                    {
                        "clock": 1699999744,
                        "parameters": recipient.create_request(request),
                    }
                ),
                "acknowledgement.json": self.s.canonical(
                    {
                        "upid": ack_base
                        + f"vzcreate:{self.owner.guest.vmid}:root@pam:",
                        "tls_verified": True,
                    }
                ),
                "failed.json": self.s.canonical({"phase": "failed"}),
            },
        )
        attachment = prepared["boot_prepared"]["reconciliation_prepared"][
            "parent_prepared"
        ]["attachment_prepared"]
        result["attach"] = self.extra_claim(
            "attach",
            attachment,
            {
                "write-possible.json": self.s.canonical(
                    {"pair_key": self.owner.pair_key}
                )
            },
        )
        runtime = {
            blank.RUNTIME_ROOT: blank.PROFILE,
            recipient.RUNTIME_ROOT: recipient.PROFILE,
            attach.RUNTIME_ROOT: attach.PROFILE,
        }
        result["runtime_files"] = {
            str(root / "profile.json"): self.file_capture(
                self.s.canonical(value), path=root / "profile.json"
            )
            for root, value in runtime.items()
        }
        own = completed["runtime_profile"]
        result["runtime_files"][own["file"]["path"]] = self.file_capture(
            Path(own["file"]["path"]).read_bytes(),
            own["file"]["identity"],
            own["file"]["path"],
        )
        roots = {
            blank.RUNTIME_ROOT,
            recipient.RUNTIME_ROOT,
            attach.RUNTIME_ROOT,
            self.sdk.writer.trial.RUNTIME_ROOT,
            self.sdk.writer.boot.RUNTIME_ROOT,
            self.sdk.writer.boot.reconcile.RUNTIME_ROOT,
            self.sdk.writer.boot.reconcile.original.RUNTIME_ROOT,
        }
        result["runtime_directories"] = {
            str(path): [1, 800, stat.S_IFDIR | 0o700, os.geteuid(), os.geteuid()]
            for root in roots
            for path in (root.parent, root)
        }
        result["runtime_directories"][str(self.sdk.writer.trial.RUNTIME_ROOT)] = list(
            own["directory"]
        )
        result["runtime_directories"][str(self.sdk.writer.boot.RUNTIME_ROOT)] = list(
            prepared["boot_runtime"]["directory"]
        )
        return result

    def projection(self, current):
        frame = current["observation"]
        init = frame["kernel"]["init"]
        normal_unit = f"pve-container@{self.owner.guest.vmid}.service"
        monitor = frame["reference"]["units"][normal_unit]["MainPID"]
        epoch = {
            "boot_id": frame["host"]["boot_id"],
            "mount_namespace": frame["host"]["mount_namespace"],
            "pid_namespace": f"pid:[{init['host_pid_namespace_inode']}]",
        }

        def row(pid, birth, executable, argv, pidns):
            return {
                "pid": pid,
                "pstart": birth,
                "ppid": 1,
                "exe": executable,
                "argv": argv,
                "comm": Path(executable).name,
                "flags": 0,
                "mount_namespace": epoch["mount_namespace"],
                "pid_namespace": pidns,
            }

        return {
            "epoch": epoch,
            "units": {
                f"{kind}@{vmid}.service": {
                    "ActiveState": (
                        "active"
                        if vmid == self.owner.guest.vmid and kind == "pve-container"
                        else "inactive"
                    ),
                    "SubState": (
                        "running"
                        if vmid == self.owner.guest.vmid and kind == "pve-container"
                        else "dead"
                    ),
                    "MainPID": (
                        monitor
                        if vmid == self.owner.guest.vmid and kind == "pve-container"
                        else 0
                    ),
                    "Job": 0,
                }
                for vmid in (
                    self.owner.guest.vmid,
                    self.case.model.request["policy"]["retired_guest"]["vmid"],
                )
                for kind in ("pve-container", "pve-container-debug")
            },
            "processes": [
                row(
                    init["pid"],
                    init["pstart"],
                    "/usr/lib/systemd/systemd",
                    ["/sbin/init"],
                    f"pid:[{init['pid_namespace_inode']}]",
                ),
                row(
                    monitor,
                    600,
                    "/usr/bin/lxc-start",
                    ["/usr/bin/lxc-start", "-F", "-n", str(self.owner.guest.vmid)],
                    epoch["pid_namespace"],
                ),
            ],
        }

    def validate(self, capture=None, authority=None):
        fence = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_fence"
        )
        authority_raw = self.s.canonical(
            authority if authority is not None else self.authority
        )
        capture_raw = self.s.canonical(capture if capture is not None else self.capture)
        return fence.validate_causal_capture(
            authority_raw,
            self.s.sha256(authority_raw),
            capture_raw,
            self.s.sha256(capture_raw),
        )

    def test_fixture_has_real_decoded_checkpoint_and_failed_pending_resume(self):
        self.assertEqual(self.case.post_count, 2)
        self.assertEqual(
            self.checkpoint["completion"]["runtime"]["application"]["record_count"], 2
        )
        self.assertEqual(self.basis["head"]["state"], "pending")
        self.sdk.validate_result(
            self.checkpoint,
            self.s.canonical(self.shutdown_prepared),
            self.digest(self.shutdown_prepared),
            self.shutdown,
        )

    def test_complete_capture_verifies_semantics_but_confers_no_native_authority(self):
        before = copy.deepcopy((self.authority, self.capture))
        result = self.validate()
        self.assertIs(result["semantic_certificate_verified"], True)
        self.assertEqual(result["candidate_upid"], self.candidate)
        self.assertEqual(result["predecessor_sha256"], self.shutdown["head_sha256"])
        for flag in (
            "original_request_fenced",
            "original_native_operation_qualified",
            "ack_recovered",
            "native_action_dispatched",
            "metadata_resolution_recorded",
        ):
            self.assertIs(result[flag], False)
        self.assertEqual(before, (self.authority, self.capture))

    def test_changed_accepted_history_cannot_select_new_authority(self):
        for group, key in (
            ("shutdown", "result"),
            ("failed_resume", "prepared"),
            ("failed_resume", "provenance"),
            ("checkpoint", "completion"),
        ):
            capture = copy.deepcopy(self.capture)
            capture[group][key] += " "
            with self.subTest(group=group, key=key), self.assertRaises(ValueError):
                self.validate(capture)

    def test_missing_alternate_or_local_only_actor_claim_refuses(self):
        for name in ("blank_boot", "recipient", "attach", "writer"):
            capture = copy.deepcopy(self.capture)
            del capture["actors"][name]
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validate(capture)

    def test_rehashed_actor_inventory_cannot_omit_a_qualified_source_route(self):
        authority = copy.deepcopy(self.authority)
        del authority["source_profile"]["sources"]["blank_boot"]
        with self.assertRaises(ValueError):
            self.validate(authority=authority)

    def test_intent_without_ack_cannot_close_an_old_possible_future_post(self):
        capture = copy.deepcopy(self.capture)
        del capture["actors"]["blank_boot"]["files"]["acknowledgement.json"]
        with self.assertRaises(ValueError):
            self.validate(capture)

    def test_existing_claim_metadata_or_raw_drift_refuses(self):
        for change in ("raw", "mode", "size", "extra"):
            capture = copy.deepcopy(self.capture)
            group = capture["actors"]["blank_boot"]["files"]
            if change == "raw":
                group["dispatch.json"]["raw"] += " "
            if change == "mode":
                group["dispatch.json"]["identity"][2] |= 0o020
            if change == "size":
                group["dispatch.json"]["identity"][6] += 1
            if change == "extra":
                group["orphan.json"] = copy.deepcopy(group["failed.json"])
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(capture)

    def test_job_or_live_native_helper_refuses_healthy_current_frames(self):
        for change in ("job", "helper"):
            capture = copy.deepcopy(self.capture)
            projection = capture["closing"]["projection"]
            if change == "job":
                next(iter(projection["units"].values()))["Job"] = 123
            else:
                row = copy.deepcopy(projection["processes"][1])
                row.update(
                    pid=2000,
                    pstart=700,
                    exe="/usr/bin/systemctl",
                    comm="systemctl",
                    argv=[
                        "systemctl",
                        "restart",
                        f"pve-container@{self.owner.guest.vmid}.service",
                    ],
                )
                projection["processes"].append(row)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(capture)

    def test_current_frame_or_epoch_drift_refuses(self):
        for change in ("uptime", "app", "epoch", "init"):
            capture = copy.deepcopy(self.capture)
            frame = capture["closing"]["current"]["observation"]
            if change == "uptime":
                frame["guest"]["runtime"]["uptime"] = 0
            if change == "app":
                frame["application"]["record_count"] += 1
            if change == "epoch":
                capture["closing"]["projection"]["epoch"][
                    "pid_namespace"
                ] = "pid:[9999]"
            if change == "init":
                frame["kernel"]["init"]["pstart"] += 1
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(capture)

    def test_forged_task_log_without_independent_normal_return_refuses(self):
        capture = copy.deepcopy(self.capture)
        value = json.loads(capture["normal_return"])
        value["events"][0]["PRIORITY"] = "3"
        capture["normal_return"] = self.raw(value)
        with self.assertRaises(ValueError):
            self.validate(capture)

    def test_pure_validator_reads_no_files_native_commands_network_or_clocks(self):
        fence = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_fence"
        )
        with mock.patch(
            "builtins.open", side_effect=AssertionError("file IO")
        ), mock.patch.object(
            self.sdk.observe, "native", side_effect=AssertionError("native")
        ), mock.patch(
            "socket.socket", side_effect=AssertionError("network")
        ), mock.patch(
            "time.time", side_effect=AssertionError("clock")
        ):
            self.assertIs(self.validate()["semantic_certificate_verified"], True)

    def test_init_and_monitor_labels_cannot_exempt_native_mutator_processes(self):
        for role, command in (
            (
                "monitor",
                [
                    "/usr/bin/lxc-start",
                    "-F",
                    "-n",
                    str(self.case.model.request["policy"]["retired_guest"]["vmid"]),
                ],
            ),
            (
                "monitor",
                [
                    "/usr/bin/systemctl",
                    "start",
                    f"pve-container@{self.owner.guest.vmid}.service",
                ],
            ),
            (
                "init",
                [
                    "/usr/bin/pvesh",
                    "create",
                    f"/nodes/{self.owner.guest.node}/lxc/{self.owner.guest.vmid}/status/start",
                ],
            ),
        ):
            capture = copy.deepcopy(self.capture)
            for phase in ("before", "closing"):
                row = capture[phase]["projection"]["processes"][
                    0 if role == "init" else 1
                ]
                row.update(exe=command[0], argv=command, comm=Path(command[0]).name)
            with self.subTest(role=role, command=command), self.assertRaises(
                ValueError
            ):
                self.validate(capture)

    def test_exported_runtime_directory_baselines_are_not_just_permission_checks(self):
        capture = copy.deepcopy(self.capture)
        path = str(self.sdk.writer.trial.RUNTIME_ROOT)
        capture["actors"]["runtime_directories"][path][1] += 1
        with self.assertRaises(ValueError):
            self.validate(capture)

    def test_same_boot_capture_cannot_silently_use_another_host_pid_namespace(self):
        capture = copy.deepcopy(self.capture)
        for phase in ("before", "closing"):
            capture[phase]["current"]["observation"]["kernel"]["init"][
                "host_pid_namespace_inode"
            ] = 9999
            projection = capture[phase]["projection"]
            projection["epoch"]["pid_namespace"] = "pid:[9999]"
            projection["processes"][1]["pid_namespace"] = "pid:[9999]"
        with self.assertRaises(ValueError):
            self.validate(capture)

    def test_changing_only_namespace_does_not_make_old_init_a_new_process(self):
        capture = copy.deepcopy(self.capture)
        old = self.shutdown["before"]["observation"]["kernel"]["init"]
        for phase in ("before", "closing"):
            frame = capture[phase]["current"]["observation"]
            frame["kernel"]["init"].update(pid=old["pid"], pstart=old["pstart"])
            frame["guest"]["runtime"]["pid"] = old["pid"]
            capture[phase]["projection"]["processes"][0].update(
                pid=old["pid"], pstart=old["pstart"]
            )
        with self.assertRaises(ValueError):
            self.validate(capture)

    def test_helper_shorthand_and_equal_vmid_options_are_still_targeted_work(self):
        for command in (
            ["/usr/bin/systemctl", "restart", f"pve-container@{self.owner.guest.vmid}"],
            [
                "/usr/bin/pvesh",
                "create",
                f"/nodes/{self.owner.guest.node}/lxc",
                f"--vmid={self.owner.guest.vmid}",
            ],
        ):
            capture = copy.deepcopy(self.capture)
            row = copy.deepcopy(capture["closing"]["projection"]["processes"][1])
            row.update(
                pid=2000,
                pstart=700,
                exe=command[0],
                argv=command,
                comm=Path(command[0]).name,
            )
            capture["closing"]["projection"]["processes"].append(row)
            with self.subTest(command=command), self.assertRaises(ValueError):
                self.validate(capture)

    def test_pending_dispatch_entry_must_equal_the_accepted_resume_entry(self):
        capture, authority = copy.deepcopy(self.capture), copy.deepcopy(self.authority)
        relative = (
            retirement.legacy._slot(self.basis["maximum_sequence"]) + "/dispatch.json"
        )
        dispatch = json.loads(capture["legacy"]["records"][relative])
        dispatch["payload"]["entry_sha256"] = "f" * 64
        raw = self.s.canonical(dispatch)
        capture["legacy"]["records"][relative] = raw.decode()
        item = capture["legacy"]["basis"]["files"][relative]
        item["sha256"], item["identity"][6] = self.s.sha256(raw), len(raw)
        authority["legacy_basis_sha256"] = self.digest(capture["legacy"]["basis"])
        provenance = json.loads(capture["failed_resume"]["provenance"])
        provenance["dispatch_sha256"] = self.s.sha256(raw)
        capture["failed_resume"]["provenance"] = self.raw(provenance)
        authority["failure_provenance_sha256"] = self.digest(provenance)
        with self.assertRaises(ValueError):
            self.validate(capture, authority)

    def test_legacy_join_requires_shutdown_and_resume_in_the_same_epoch(self):
        fence = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_fence"
        )
        shutdown = copy.deepcopy(self.shutdown)
        shutdown["before"]["observation"]["host"][
            "boot_id"
        ] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        with self.assertRaises(ValueError):
            fence._legacy(
                self.authority,
                self.owner,
                self.capture["legacy"],
                shutdown,
                self.resume,
                self.provenance,
            )

    def test_source_helper_under_an_interpreter_is_still_targeted_work(self):
        capture = copy.deepcopy(self.capture)
        row = copy.deepcopy(capture["closing"]["projection"]["processes"][1])
        row.update(
            pid=2000,
            pstart=700,
            exe="/usr/bin/perl",
            comm="perl",
            argv=[
                "/usr/bin/perl",
                "/usr/share/lxc/hooks/lxc-pve-poststop-hook",
                str(self.owner.guest.vmid),
            ],
        )
        capture["closing"]["projection"]["processes"].append(row)
        with self.assertRaises(ValueError):
            self.validate(capture)

    def test_known_prior_start_and_before_floor_candidates_refuse(self):
        boot_path = str(
            self.sdk.writer.boot.claim_path(
                self.checkpoint["prepared"]["source_request"]
            )
        )
        prior = json.loads(
            self.capture["actors"]["history_directories"][boot_path]["files"][
                "acknowledgement.json"
            ]["raw"]
        )["upid"]
        earlier = self.candidate.split(":")
        earlier[3] = f"{int(earlier[3],16)-1:08X}"
        for upid in (prior, ":".join(earlier)):
            capture = copy.deepcopy(self.capture)
            original = capture["normal_return"]
            value = json.loads(original.replace(self.candidate, upid))
            identity = self.sdk.api.parse_upid(self.owner.guest, upid)
            value["task"].update(identity)
            value["events"][1]["_PID"] = str(identity["pid"])
            capture["normal_return"] = self.raw(value)
            with self.subTest(upid=upid), self.assertRaises(ValueError):
                self.validate(capture)

    def test_unrelated_process_churn_and_reused_candidate_pid_are_permitted(self):
        capture = copy.deepcopy(self.capture)
        row = copy.deepcopy(capture["closing"]["projection"]["processes"][1])
        candidate = self.sdk.api.parse_upid(self.owner.guest, self.candidate)
        row.update(
            pid=candidate["pid"],
            pstart=candidate["pstart"] + 1,
            exe="/usr/bin/sleep",
            argv=["sleep", "20"],
            comm="sleep",
        )
        capture["closing"]["projection"]["processes"].append(row)
        self.assertIs(self.validate(capture)["semantic_certificate_verified"], True)
        row["pstart"] = candidate["pstart"] - 1
        with self.assertRaises(ValueError):
            self.validate(capture)

    def test_controller_only_path_cannot_be_substituted_for_manager_claim(self):
        capture = copy.deepcopy(self.capture)
        capture["actors"]["blank_boot"]["path"] = "/srv/controller-only-claim"
        with self.assertRaises(ValueError):
            self.validate(capture)

    def test_external_hashes_and_exact_document_types_are_required(self):
        fence = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_fence"
        )
        authority_raw, capture_raw = self.s.canonical(self.authority), self.s.canonical(
            self.capture
        )
        for authority_sha, capture_sha in (
            ("0" * 64, self.s.sha256(capture_raw)),
            (self.s.sha256(authority_raw), "0" * 64),
        ):
            with self.assertRaises(ValueError):
                fence.validate_causal_capture(
                    authority_raw, authority_sha, capture_raw, capture_sha
                )
        for key, replacement in (
            ("schema_version", True),
            ("H0", "0" * 64),
            ("original_request_fenced", True),
        ):
            capture = copy.deepcopy(self.capture)
            capture[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(capture)

    def test_bad_unit_types_refuse_with_boundary_error(self):
        for key, value in (
            ("ActiveState", []),
            ("SubState", {}),
            ("Job", False),
            ("MainPID", True),
        ):
            capture = copy.deepcopy(self.capture)
            unit = next(iter(capture["closing"]["projection"]["units"].values()))
            unit[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(capture)

    def test_late_projection_memory_change_cannot_return_semantic_success(self):
        fence = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_fence"
        )
        original = fence._projection

        def late(*args):
            result = original(*args)
            next(iter(args[1]["projection"]["units"].values()))["Job"] = False
            return result

        with mock.patch.object(
            fence, "_projection", side_effect=late
        ), self.assertRaisesRegex(ValueError, "capture-memory-changed"):
            self.validate()

    def test_early_unrelated_kernel_thread_may_have_zero_tick_birth(self):
        capture = copy.deepcopy(self.capture)
        row = copy.deepcopy(capture["closing"]["projection"]["processes"][1])
        row.update(
            pid=2, pstart=0, ppid=0, exe=None, argv=[], comm="kthreadd", flags=0x200000
        )
        capture["closing"]["projection"]["processes"].append(row)
        self.assertIs(self.validate(capture)["semantic_certificate_verified"], True)

    def test_known_stop_wrapper_and_old_monitor_birth_refuse(self):
        for fault in ("stop-wrapper", "old-monitor", "zero-monitor"):
            capture = copy.deepcopy(self.capture)
            if fault == "stop-wrapper":
                row = copy.deepcopy(capture["closing"]["projection"]["processes"][1])
                row.update(
                    pid=2000,
                    pstart=700,
                    exe="/usr/bin/perl",
                    comm="pve-container-s",
                    argv=[
                        "/usr/bin/perl",
                        "/usr/share/lxc/pve-container-stop-wrapper",
                        str(self.owner.guest.vmid),
                    ],
                )
                capture["closing"]["projection"]["processes"].append(row)
            else:
                floor = self.sdk.api.parse_upid(self.owner.guest, self.candidate)[
                    "pstart"
                ]
                for phase in ("before", "closing"):
                    capture[phase]["projection"]["processes"][1]["pstart"] = (
                        0 if fault == "zero-monitor" else floor - 1
                    )
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.validate(capture)


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class OwnerFenceEpochTests(unittest.TestCase):
    def test_coherent_new_boot_resume_cannot_use_a_previous_boot_birth_floor(self):
        other = OwnerFenceTests("runTest")
        other.resume_epoch_override = "11111111-2222-3333-4444-555555555999"
        # Build a second real old-SDK journal with a manager epoch change, not a
        # mutation of the certificate verifier or an incoherent exported hash.
        self.addCleanup(other.doCleanups)
        other.setUp()
        self.assertNotEqual(
            other.shutdown["before"]["observation"]["host"]["boot_id"],
            other.capture["before"]["current"]["observation"]["host"]["boot_id"],
        )
        with self.assertRaises(ValueError):
            other.validate()


if __name__ == "__main__":
    unittest.main()
