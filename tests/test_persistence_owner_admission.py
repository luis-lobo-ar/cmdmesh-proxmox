"""Fresh modeled runtime must preserve the accepted portable application state.

Authority fixtures stand in for an already validated checkpoint. These tests
do not qualify a decoder, native guest lifecycle or real cgroup mount.
"""

import copy
from contextlib import contextmanager, ExitStack
import errno
import importlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import test_persistence_retained_runtime as fixtures


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class OwnerAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.current = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_current"
        )
        self.request, self.profile, self.frame = fixtures.model()
        self.frame["application"]["record_count"] = 2
        self.guard, _, self.binding = fixtures.runtime.load_profile(
            self.request, self.profile
        )
        prepared = {"source_request": self.request, "image_profile": self.profile}
        completion = {"runtime": self.frame}
        s = fixtures.runtime.state
        self.authority = {
            "document_type": "cmdmesh.proxmox.persistence.owner-checkpoint",
            "schema_version": 1,
            "prepared": prepared,
            "completion": completion,
            "prepared_sha256": s.sha256(s.canonical(prepared)),
            "completion_sha256": s.sha256(s.canonical(completion)),
        }

    def evidence(self, phase="os_quiesced"):
        observation = copy.deepcopy(self.frame)
        if phase == "stopped":
            observation = {
                "schema_version": 1,
                "source": copy.deepcopy(self.request["source"]),
                "host": copy.deepcopy(self.frame["host"]),
                "guest": copy.deepcopy(self.frame["guest"]),
                "guarded": copy.deepcopy(self.frame["retained"]),
                "backup_store": {"synthetic": True},
                "application": copy.deepcopy(self.frame["application"]),
                "quiesced": True,
                "backup_verified": False,
            }
            observation["guest"].update(
                status="stopped",
                runtime={"vmid": self.request["policy"]["vmid"], "pid": 0, "uptime": 0},
            )
        return {
            "phase": phase,
            "observation": observation,
            "guest_image_verified": phase == "os_quiesced",
        }

    def test_portable_running_state_accepts_joined_fresh_epoch_devices_and_cpu(self):
        value = self.evidence()
        frame = value["observation"]
        frame["host"].update(
            boot_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", mount_namespace="mnt:[9876]"
        )
        frame["kernel"]["init"].update(
            pid=987,
            pstart=4567,
            pid_namespace_inode=87654,
            host_pid_namespace_inode=87655,
        )
        frame["guest"]["runtime"].update(pid=987, uptime=4)
        frame["kernel"]["rootfs"]["device"][1] += 7
        frame["image"]["identity"]["root_device"] = os.makedev(
            *frame["kernel"]["rootfs"]["device"]
        )
        # Policy admits this CPU. The generated stable fingerprint excludes only
        # the proved dynamic selection, not the CPU quota or mapping.
        cpu = self.request["policy"]["cpu_policy"]["allowed"][-1]
        frame["kernel"]["cgroup"]["cpus"] = [cpu]
        frame["image"]["identity"]["affinity"] = [cpu]
        frame["kernel"]["generated_config"] = frame["kernel"][
            "generated_config"
        ].replace("cpuset.cpus = 0", "cpuset.cpus = " + str(cpu))
        frame["retained"]["cpu_selection"] = [cpu]
        for role, item in frame["bindings"].items():
            device = item["host"]["device"] + 100
            item["host"]["device"] = item["guest"]["device"] = device
            item["mount"]["device"] = [os.major(device), os.minor(device)]
        before = copy.deepcopy((self.authority, value))
        with mock.patch.object(
            fixtures.runtime.observe,
            "native",
            side_effect=AssertionError("pure validator called native"),
        ):
            self.current.validate_current(self.authority, "os_quiesced", value)
        self.assertEqual(before, (self.authority, value))

    def test_unchanged_stopped_state_does_not_claim_current_guest_image(self):
        value = self.evidence("stopped")
        self.current.validate_current(self.authority, "stopped", value)
        value["guest_image_verified"] = True
        with self.assertRaises(ValueError):
            self.current.validate_current(self.authority, "stopped", value)

    def test_intrinsically_valid_but_changed_app2_or_retained_identity_refuses(self):
        for phase in ("os_quiesced", "stopped"):
            for fault in (
                "database_sha256",
                "records_sha256",
                "record_count",
                "directory",
                "owner-file",
                "reference-file",
            ):
                value = self.evidence(phase)
                frame = value["observation"]
                retained = frame["retained" if phase == "os_quiesced" else "guarded"]
                if fault == "record_count":
                    frame["application"][fault] = 3
                elif fault in ("database_sha256", "records_sha256"):
                    frame["application"][fault] = "7" * 64
                elif fault == "directory":
                    retained["datasets"]["data"]["directory"]["inode"] += 1
                    if phase == "os_quiesced":
                        for side in ("host", "guest"):
                            frame["bindings"]["data"][side]["inode"] += 1
                elif fault == "owner-file":
                    # The legacy model omits optional exported inode evidence.
                    # Added native identity evidence must not silently differ.
                    retained["ownership"]["file"]["inode"] = 99999
                elif phase == "os_quiesced":
                    next(iter(frame["reference"]["files"].values()))["identity"][1] += 1
                else:
                    continue
                with (
                    self.subTest(phase=phase, fault=fault),
                    self.assertRaises(ValueError),
                ):
                    self.current.validate_current(self.authority, phase, value)

    def test_broken_dynamic_cross_joins_refuse(self):
        for fault in (
            "pid",
            "bind",
            "affinity",
            "root-device",
            "quota",
            "cpu-selection",
        ):
            value = self.evidence()
            frame = value["observation"]
            if fault == "pid":
                frame["guest"]["runtime"]["pid"] += 1
            if fault == "bind":
                frame["bindings"]["data"]["guest"]["device"] += 1
            if fault == "affinity":
                frame["image"]["identity"]["affinity"] = [65535]
            if fault == "root-device":
                frame["image"]["identity"]["root_device"] += 1
            if fault == "quota":
                frame["kernel"]["cgroup"]["cpu_max"] = "200000 100000"
            if fault == "cpu-selection":
                cpu = self.request["policy"]["cpu_policy"]["allowed"][-1]
                self.assertNotEqual(cpu, frame["retained"]["cpu_selection"][0])
                frame["retained"]["cpu_selection"] = [cpu]
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.current.validate_current(self.authority, "os_quiesced", value)

    def test_vendor_live_cpu_rebalance_preserves_boot_selection(self):
        value = self.evidence()
        frame = value["observation"]
        cpu = self.request["policy"]["cpu_policy"]["allowed"][-1]
        self.assertNotEqual(cpu, frame["retained"]["cpu_selection"][0])
        frame["kernel"]["cgroup"]["cpus"] = [cpu]
        frame["image"]["identity"]["affinity"] = [cpu]
        # pvestatd updates live cgroups, not the generated boot config.
        self.current.validate_current(self.authority, "os_quiesced", value)

    def test_empty_generator_selection_keeps_enforced_live_single_cpu(self):
        value = self.evidence()
        frame = value["observation"]
        frame["kernel"]["generated_config"] = frame["kernel"][
            "generated_config"
        ].replace("cpuset.cpus = 0\n", "cpuset.cpus = \n")
        frame["retained"]["cpu_selection"] = []
        self.current.validate_current(self.authority, "os_quiesced", value)

    def test_changed_static_owner_host_root_or_credential_refuses(self):
        for fault in (
            "machine",
            "certificate",
            "version",
            "owner",
            "root-inode",
            "root-uuid",
            "guid",
            "credential",
        ):
            value = self.evidence()
            frame = value["observation"]
            if fault == "machine":
                frame["host"]["host_profile"]["machine_id_sha256"] = "3" * 64
            if fault == "certificate":
                frame["host"]["host_profile"]["leaf_certificate_sha256"] = "3" * 64
            if fault == "version":
                frame["host"]["versions"]["pve-manager"] = "unqualified"
            if fault == "owner":
                frame["guest"]["config"]["tags"] = "cmdmesh-own-" + "3" * 32
            if fault == "root-inode":
                frame["kernel"]["rootfs"]["identity"][1] += 1
            if fault == "root-uuid":
                frame["kernel"]["rootfs"][
                    "uuid"
                ] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            if fault == "guid":
                frame["retained"]["datasets"]["data"]["properties"][
                    "guid"
                ] = "987654321"
            if fault == "credential":
                frame["application"]["config_sha256"] = "3" * 64
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.current.validate_current(self.authority, "os_quiesced", value)

    def test_changed_checkpoint_bytes_are_not_reinterpreted_as_authority(self):
        changed = copy.deepcopy(self.authority)
        changed["completion"]["runtime"]["application"]["record_count"] = 3
        with (
            mock.patch.object(
                fixtures.runtime.observe,
                "native",
                side_effect=AssertionError("native before authority"),
            ),
            self.assertRaises(ValueError),
        ):
            self.current.validate_current(changed, "os_quiesced", self.evidence())

    def test_reference_declarations_support_stopped_without_invented_execution(self):
        reference = copy.deepcopy(self.frame["reference"])
        for unit in reference["units"].values():
            unit.update(ActiveState="inactive", MainPID=0)
            for command in unit["commands"]:
                for key in (
                    "start_real_us",
                    "start_monotonic_us",
                    "stop_real_us",
                    "stop_monotonic_us",
                    "pid",
                    "code",
                    "status",
                ):
                    command[key] = 0
        fixtures.runtime.validate_stopped_reference(self.request, reference)
        with self.assertRaises(ValueError):
            fixtures.runtime.validate_reference(self.request, reference)
        for field, value in (
            ("MainPID", False),
            ("MainPID", 123),
            ("ActiveState", "active"),
            ("directory_membership", []),
        ):
            changed = copy.deepcopy(reference)
            next(iter(changed["units"].values()))[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                fixtures.runtime.validate_stopped_reference(self.request, changed)

    def test_only_known_prior_init_absence_or_valid_reuse_is_accepted(self):
        host = copy.deepcopy(self.frame["host"])
        init = self.frame["kernel"]["init"]
        same = (init["pstart"], init["pid_namespace_inode"])
        for answer in (FileNotFoundError(errno.ENOENT, "gone"), (same[0] + 1, same[1])):
            with (
                self.subTest(answer=answer),
                mock.patch.object(
                    fixtures.runtime.kernel.reader.memory,
                    "init_state",
                    side_effect=answer if isinstance(answer, Exception) else None,
                    return_value=answer,
                ),
            ):
                self.current._prior_fence(host, self.frame)
        for answer in (
            PermissionError(errno.EACCES, "denied"),
            OSError(errno.EIO, "io"),
            FileNotFoundError(),
            same,
            (True, same[1]),
            (0, 0),
        ):
            with (
                self.subTest(answer=answer),
                mock.patch.object(
                    fixtures.runtime.kernel.reader.memory,
                    "init_state",
                    side_effect=answer if isinstance(answer, Exception) else None,
                    return_value=answer,
                ),
                self.assertRaises((ValueError, OSError)),
            ):
                self.current._prior_fence(host, self.frame)
        host["boot_id"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        with mock.patch.object(
            fixtures.runtime.kernel.reader.memory,
            "init_state",
            side_effect=AssertionError("old numeric PID in new epoch"),
        ):
            self.assertEqual(
                self.current._prior_fence(host, self.frame), "manager-epoch-changed"
            )

    def test_actual_cgroup_files_require_recursive_unpopulated_and_stable_reads(self):
        scratch = Path(__file__).resolve().parents[1] / ".generated"
        with tempfile.TemporaryDirectory(dir=scratch) as name:
            root = Path(name)
            path = root / str(self.request["policy"]["vmid"])
            mounted = {
                "filesystems": [{"target": str(root.parent), "fstype": "cgroup2"}]
            }
            with (
                mock.patch.object(self.current, "CGROUP_ROOT", root),
                mock.patch.object(self.current, "ROOT_UID", os.getuid()),
                mock.patch.object(
                    fixtures.runtime.observe,
                    "native",
                    return_value=fixtures.runtime.state.canonical(mounted),
                ),
            ):
                self.assertEqual(
                    self.current._empty_cgroup(self.request["policy"]["vmid"])["state"],
                    "absent",
                )
                path.mkdir(mode=0o755)
                path.chmod(0o755)
                (path / "cgroup.events").write_bytes(b"populated 0\nfrozen 0\n")
                (path / "cgroup.procs").write_bytes(b"")
                (path / "cgroup.events").chmod(0o644)
                (path / "cgroup.procs").chmod(0o644)
                self.assertEqual(
                    self.current._empty_cgroup(self.request["policy"]["vmid"])["state"],
                    "empty",
                )
                for events, procs in (
                    (b"populated 1\nfrozen 0\n", b""),
                    (b"populated 0\nfrozen 0\n", b"999\n"),
                    (b"populated 0\npopulated 0\n", b""),
                ):
                    (path / "cgroup.events").write_bytes(events)
                    (path / "cgroup.procs").write_bytes(procs)
                    with (
                        self.subTest(events=events, procs=procs),
                        self.assertRaises(ValueError),
                    ):
                        self.current._empty_cgroup(self.request["policy"]["vmid"])

    def stopped_providers(self):
        stack = self.enterContext(ExitStack())
        runtime = fixtures.runtime
        guest = self.evidence("stopped")["observation"]["guest"]
        reference = copy.deepcopy(self.frame["reference"])
        for unit in reference["units"].values():
            unit.update(ActiveState="inactive", MainPID=0)
        for obj, name, value in (
            (runtime.observe, "load_guard", self.guard),
            (runtime.observe, "host_facts", copy.deepcopy(self.frame["host"])),
            (runtime.observe, "guest_facts", guest),
            (runtime, "_stopped_reference_facts", reference),
            (runtime.observe, "native", b"STOPPED\n"),
            (self.current, "_root", {"identity": self.profile["rootfs"]["identity"]}),
            (self.current, "_empty_cgroup", {"state": "absent"}),
            (self.guard, "collect_ownership", self.frame["retained"]["ownership"]),
        ):
            stack.enter_context(mock.patch.object(obj, name, return_value=value))
        stack.enter_context(
            mock.patch.object(
                runtime.kernel.reader.memory,
                "init_state",
                side_effect=FileNotFoundError(errno.ENOENT, "gone"),
            )
        )
        stack.enter_context(
            mock.patch.object(
                runtime.observe,
                "read_database",
                side_effect=AssertionError("entry SQL"),
            )
        )
        stack.enter_context(
            mock.patch.object(
                self.guard, "collect", side_effect=AssertionError("entry retained read")
            )
        )
        return guest, reference

    def test_stopped_entry_requires_all_signals_before_retained_reads(self):
        guest, reference = self.stopped_providers()
        self.current._entry_leased(self.authority, "stopped")
        for fault in (
            "running-api",
            "wrong-api-pid",
            "unit-active",
            "unit-pid",
            "lxc-running",
            "populated",
        ):
            fresh_guest, fresh_reference = copy.deepcopy(guest), copy.deepcopy(
                reference
            )
            native = b"STOPPED\n"
            cgroup_error = None
            if fault == "running-api":
                fresh_guest["status"] = "running"
            if fault == "wrong-api-pid":
                fresh_guest["runtime"]["pid"] = 123
            if fault == "unit-active":
                next(iter(fresh_reference["units"].values()))["ActiveState"] = "active"
            if fault == "unit-pid":
                next(iter(fresh_reference["units"].values()))["MainPID"] = 123
            if fault == "lxc-running":
                native = b"RUNNING\n"
            if fault == "populated":
                cgroup_error = ValueError("populated")
            with (
                self.subTest(fault=fault),
                mock.patch.object(
                    fixtures.runtime.observe, "guest_facts", return_value=fresh_guest
                ),
                mock.patch.object(
                    fixtures.runtime,
                    "_stopped_reference_facts",
                    return_value=fresh_reference,
                ),
                mock.patch.object(
                    fixtures.runtime.observe, "native", return_value=native
                ),
                mock.patch.object(
                    self.current,
                    "_empty_cgroup",
                    return_value={"state": "absent"},
                    side_effect=cgroup_error,
                ),
                self.assertRaises(ValueError),
            ):
                self.current._entry_leased(self.authority, "stopped")

    def test_missing_lxc_parent_after_reboot_is_genuine_cgroup_absence(self):
        scratch = Path(__file__).resolve().parents[1] / ".generated"
        with tempfile.TemporaryDirectory(dir=scratch) as name:
            root = Path(name) / "lxc"
            mounted = {
                "filesystems": [{"target": str(root.parent), "fstype": "cgroup2"}]
            }
            with (
                mock.patch.object(self.current, "CGROUP_ROOT", root),
                mock.patch.object(self.current, "ROOT_UID", os.getuid()),
                mock.patch.object(
                    fixtures.runtime.observe,
                    "native",
                    return_value=fixtures.runtime.state.canonical(mounted),
                ),
            ):
                self.assertEqual(
                    self.current._empty_cgroup(self.request["policy"]["vmid"])["state"],
                    "absent",
                )

    def test_slow_caller_work_precedes_final_actual_worker(self):
        self.stopped_providers()
        entry = self.current._entry_leased(self.authority, "stopped")
        source = self.evidence("stopped")["observation"]
        events = []

        @contextmanager
        def worker(*args):
            events.append("worker")
            yield copy.deepcopy(source)
            events.append("worker-close")

        with (
            mock.patch.object(
                fixtures.runtime.observe, "_stopped_source_leased", side_effect=worker
            ),
            mock.patch.object(self.current, "_fast_close", return_value=None),
        ):
            # Test raw is only a hash-bound synthetic stand-in; actual EX
            # ownership and SQL are independently exercised by worker tests.
            raw = b"synthetic-config"
            # Keep the fixture authority intact and substitute only the digest
            # primitive for this context scheduling test.
            original_sha = fixtures.runtime.state.sha256
            with mock.patch.object(
                fixtures.runtime.state,
                "sha256",
                side_effect=lambda data: (
                    self.request["policy"]["application"]["config_sha256"]
                    if data == raw
                    else original_sha(data)
                ),
            ):
                with self.assertRaises(ValueError):
                    with self.current._current_leased(self.authority, entry, raw):
                        events.append("slow-history")
                        source["application"]["records_sha256"] = "8" * 64
                self.assertEqual(
                    events,
                    [
                        "worker",
                        "worker-close",
                        "slow-history",
                        "worker",
                        "worker-close",
                    ],
                )


if __name__ == "__main__":
    unittest.main()
