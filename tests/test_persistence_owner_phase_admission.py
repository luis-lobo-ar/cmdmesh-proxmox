"""Pure joins use actual current/guard validators over synthetic authority frames.

Ancestor checkpoint decoding and native/source/lease authentication are not
qualified by these fixtures. No target observation or metadata action occurs.
"""

import copy
import importlib
import os
import stat
import unittest
from unittest import mock

import test_persistence_owner_admission as fixtures


def admission_inputs(model, phase, *, new_epoch=False):
    """Return coherent synthetic current, entry and explicit historical prior."""
    evidence = model.evidence(phase)
    frame = evidence["observation"]
    if new_epoch:
        frame["host"].update(
            boot_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            mount_namespace="mnt:[9876]",
        )
    reference = copy.deepcopy(model.frame["reference"])
    if phase == "stopped":
        for unit in reference["units"].values():
            unit.update(ActiveState="inactive", MainPID=0)
    retained = frame["retained" if phase == "os_quiesced" else "guarded"]
    root = model.profile["rootfs"]
    entry = {
        "phase": phase,
        "host": copy.deepcopy(frame["host"]),
        "guest": copy.deepcopy(frame["guest"]),
        "reference": reference,
        "root": {key: copy.deepcopy(root[key]) for key in ("path", "identity", "uuid")},
        "ownership": copy.deepcopy(retained["ownership"]),
        "stopped": (
            {
                "lxc_state": "STOPPED",
                "cgroup": {
                    "state": "absent",
                    "mount": {"target": "/sys/fs/cgroup", "fstype": "cgroup2"},
                },
                "prior_fence": (
                    "manager-epoch-changed" if new_epoch else "prior-init-absent"
                ),
            }
            if phase == "stopped"
            else None
        ),
    }
    prior = copy.deepcopy(model.frame) if phase == "stopped" else None
    return evidence, entry, prior


def valid_entry(model, phase, *, new_epoch=False):
    return admission_inputs(model, phase, new_epoch=new_epoch)[1]


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class PhaseAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.model = fixtures.OwnerAdmissionTests("runTest")
        self.model.setUp()
        self.addCleanup(self.model.doCleanups)
        self.codec = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_phase_admission"
        )

    def validate(self, phase, evidence, entry, prior):
        return self.codec.validate_phase_admission(
            self.model.authority, phase, evidence, entry, prior
        )

    def refuses(self, phase, evidence, entry, prior):
        with self.assertRaises(fixtures.fixtures.runtime.state.PersistenceError):
            self.validate(phase, evidence, entry, prior)

    def test_running_and_both_stopped_epochs_are_pure_and_nonmutating(self):
        for phase, epoch in (
            ("os_quiesced", False),
            ("stopped", False),
            ("stopped", True),
        ):
            args = admission_inputs(self.model, phase, new_epoch=epoch)
            before = copy.deepcopy((self.model.authority, args))
            with self.subTest(phase=phase, epoch=epoch), mock.patch.object(
                self.model.current.observe,
                "native",
                side_effect=AssertionError("pure admission called native"),
            ), mock.patch.object(
                self.model.current,
                "_entry_leased",
                side_effect=AssertionError("pure admission entered worker"),
            ):
                self.assertIsNone(self.validate(phase, *args))
            self.assertEqual(before, (self.model.authority, args))

    def test_running_guest_uptime_may_advance_but_not_decrease(self):
        evidence, entry, prior = admission_inputs(self.model, "os_quiesced")
        evidence["observation"]["guest"]["runtime"]["uptime"] += 10
        self.assertIsNone(self.validate("os_quiesced", evidence, entry, prior))
        entry["guest"]["runtime"]["uptime"] += 20
        self.refuses("os_quiesced", evidence, entry, prior)

    def test_stopped_requires_explicit_valid_running_prior(self):
        evidence, entry, prior = admission_inputs(self.model, "stopped")
        self.refuses("stopped", evidence, entry, None)
        wrong = copy.deepcopy(prior)
        wrong["application"]["record_count"] += 1
        self.refuses("stopped", evidence, entry, wrong)
        self.refuses("stopped", evidence, entry, evidence["observation"])

    def test_prior_fence_claim_must_match_boot_epoch(self):
        for epoch, bad in (
            (False, "manager-epoch-changed"),
            (True, "prior-init-absent"),
        ):
            evidence, entry, prior = admission_inputs(
                self.model, "stopped", new_epoch=epoch
            )
            entry["stopped"]["prior_fence"] = bad
            with self.subTest(epoch=epoch):
                self.refuses("stopped", evidence, entry, prior)
        evidence, entry, prior = admission_inputs(self.model, "stopped")
        entry["stopped"]["prior_fence"] = "prior-init-reused"
        self.assertIsNone(self.validate("stopped", evidence, entry, prior))

    def test_exact_entry_host_guest_root_and_ownership_joins(self):
        for phase in ("os_quiesced", "stopped"):
            for fault in ("extra", "phase", "host", "pid", "root", "owner"):
                evidence, entry, prior = admission_inputs(self.model, phase)
                if fault == "extra":
                    entry["extra"] = False
                elif fault == "phase":
                    entry["phase"] = "running"
                elif fault == "host":
                    entry["host"]["mount_namespace"] = "mnt:[9999]"
                elif fault == "pid":
                    entry["guest"]["runtime"]["pid"] += 1
                elif fault == "root":
                    entry["root"]["identity"][1] += 1
                else:
                    entry["ownership"]["file"]["sha256"] = "f" * 64
                with self.subTest(phase=phase, fault=fault):
                    self.refuses(phase, evidence, entry, prior)

    def test_stopped_reference_requires_inactive_native_declarations(self):
        for fault in ("active", "pid", "file", "command"):
            evidence, entry, prior = admission_inputs(self.model, "stopped")
            unit = next(iter(entry["reference"]["units"].values()))
            if fault == "active":
                unit["ActiveState"] = "active"
            elif fault == "pid":
                unit["MainPID"] = 123
            elif fault == "file":
                next(iter(entry["reference"]["files"].values()))["identity"][1] += 1
            else:
                unit["commands"][0]["argv"] = ["/usr/bin/true"]
            with self.subTest(fault=fault):
                self.refuses("stopped", evidence, entry, prior)

    def test_running_reference_must_join_actual_current(self):
        evidence, entry, prior = admission_inputs(self.model, "os_quiesced")
        next(iter(entry["reference"]["units"].values()))["MainPID"] += 1
        self.refuses("os_quiesced", evidence, entry, prior)

    def test_stopped_cgroup_empty_identity_is_directory_metadata(self):
        evidence, entry, prior = admission_inputs(self.model, "stopped")
        entry["stopped"]["cgroup"].update(
            state="empty", identity=[1, 3, stat.S_IFDIR | 0o755, 0, 0]
        )
        self.assertIsNone(self.validate("stopped", evidence, entry, prior))
        for field, bad in (
            (0, True),
            (1, 0),
            (2, stat.S_IFREG | 0o755),
            (2, stat.S_IFDIR | 0o777),
            (3, 123),
        ):
            changed = copy.deepcopy(entry)
            changed["stopped"]["cgroup"]["identity"][field] = bad
            with self.subTest(field=field, bad=bad):
                self.refuses("stopped", evidence, changed, prior)

    def test_cgroup_mount_shape_path_and_no_invented_absent_identity(self):
        for fault in ("mount", "relative", "foreign", "extra", "lxc", "identity"):
            evidence, entry, prior = admission_inputs(self.model, "stopped")
            stopped = entry["stopped"]
            if fault == "mount":
                stopped["cgroup"]["mount"]["fstype"] = "ext4"
            elif fault == "relative":
                stopped["cgroup"]["mount"]["target"] = "sys/fs/cgroup"
            elif fault == "foreign":
                stopped["cgroup"]["mount"]["target"] = "/srv/cgroup"
            elif fault == "extra":
                stopped["extra"] = None
            elif fault == "lxc":
                stopped["lxc_state"] = "RUNNING"
            else:
                stopped["cgroup"]["identity"] = [1, 2, 3, 0, 0]
            with self.subTest(fault=fault):
                self.refuses("stopped", evidence, entry, prior)

    def test_running_cannot_smuggle_stopped_claims(self):
        evidence, entry, prior = admission_inputs(self.model, "os_quiesced")
        entry["stopped"] = admission_inputs(self.model, "stopped")[1]["stopped"]
        self.refuses("os_quiesced", evidence, entry, prior)

    def test_portable_new_epoch_init_loop_and_cpu_use_intrinsic_joins(self):
        evidence, entry, prior = admission_inputs(
            self.model, "os_quiesced", new_epoch=True
        )
        frame = evidence["observation"]
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
        cpu = self.model.request["policy"]["cpu_policy"]["allowed"][-1]
        frame["kernel"]["cgroup"]["cpus"] = [cpu]
        frame["image"]["identity"]["affinity"] = [cpu]
        # Live affinity can rebalance independently of the generated selection.
        for item in frame["bindings"].values():
            device = item["host"]["device"] + 100
            item["host"]["device"] = item["guest"]["device"] = device
            item["mount"]["device"] = [os.major(device), os.minor(device)]
        entry["guest"] = copy.deepcopy(frame["guest"])
        self.assertIsNone(self.validate("os_quiesced", evidence, entry, prior))

    def test_input_and_private_views_close_after_last_semantic_validator(self):
        for subject in ("original", "private"):
            evidence, entry, prior = admission_inputs(self.model, "stopped")
            actual = self.codec._cgroup

            def late(value):
                actual(value)
                if subject == "original":
                    entry["root"]["identity"] = tuple(entry["root"]["identity"])
                else:
                    value["late"] = False

            with self.subTest(subject=subject), mock.patch.object(
                self.codec, "_cgroup", side_effect=late
            ):
                self.refuses("stopped", evidence, entry, prior)

    def test_input_limits_and_non_json_types_refuse(self):
        evidence, entry, prior = admission_inputs(self.model, "os_quiesced")
        for bad in (float("nan"), (), b"data"):
            changed = copy.deepcopy(entry)
            changed["extra"] = bad
            with self.subTest(bad=type(bad)):
                self.refuses("os_quiesced", evidence, changed, prior)
        with mock.patch.object(self.codec, "MAX_NODES", 2):
            self.refuses("os_quiesced", evidence, entry, prior)
        with mock.patch.object(self.codec, "MAX_BYTES", 8):
            self.refuses("os_quiesced", evidence, entry, prior)

    def test_aggregate_alias_expansion_is_bounded_before_canonical_encoding(self):
        repeated = ["x" * 20] * 20
        with mock.patch.object(self.codec, "MAX_BYTES", 256):
            with self.assertRaises(self.codec.state.PersistenceError):
                self.codec._json(repeated)
            with mock.patch.object(
                self.codec.state,
                "canonical",
                side_effect=AssertionError("encoded over-budget input"),
            ), self.assertRaises(self.codec.state.PersistenceError):
                self.codec.validate_phase_admission(
                    repeated, "os_quiesced", {}, {}, None
                )

    def test_preencoding_byte_budget_matches_canonical_escaping(self):
        for value in (
            {"values": [None, True, False, 1, -20]},
            ['\x00\x7f\n\t"\\é😀\ud800'],
            ["repeated"] * 5,
        ):
            size = len(self.codec.state.canonical(value))
            with self.subTest(value=value), mock.patch.object(
                self.codec, "MAX_BYTES", size
            ):
                self.codec._json(value)
            with self.subTest(size=size), mock.patch.object(
                self.codec, "MAX_BYTES", size - 1
            ):
                with self.assertRaises(self.codec.state.PersistenceError):
                    self.codec._json(value)

    def test_malformed_inputs_use_persistence_error(self):
        evidence, entry, prior = admission_inputs(self.model, "os_quiesced")
        for phase, bad in (
            (True, entry),
            ("running", entry),
            ("os_quiesced", None),
            ("os_quiesced", []),
        ):
            with self.subTest(phase=phase, entry=bad):
                self.refuses(phase, evidence, bad, prior)
        for checkpoint in (None, [], {"incomplete": True}):
            with self.subTest(checkpoint=checkpoint), self.assertRaises(
                self.codec.state.PersistenceError
            ):
                self.codec.validate_phase_admission(
                    checkpoint, "os_quiesced", evidence, entry, prior
                )


if __name__ == "__main__":
    unittest.main()
