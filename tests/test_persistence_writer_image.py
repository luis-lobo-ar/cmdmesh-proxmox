"""Active image checks bind one writer without weakening quiesced checks."""

import copy
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_retained_runtime as runtime,
)
from test_persistence_retained_runtime import model
import test_persistence_retained_runtime as fixtures


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"), "provide guard"
)
class WriterImageTests(unittest.TestCase):
    def setUp(self):
        self.request, self.profile, self.value = model()
        _, self.image, _ = runtime.load_profile(self.request, self.profile)
        self.pid = 321
        self.evidence = copy.deepcopy(self.value["image"])
        self.evidence["unit"].update(
            ActiveState="active", SubState="running", MainPID=str(self.pid)
        )
        self.evidence["accounts"].update(
            uid_processes=[self.pid], gid_processes=[self.pid]
        )

    def validate(self, evidence=None, pid=None):
        runtime.validate_image(
            self.profile,
            self.image,
            evidence or self.evidence,
            self.value["kernel"],
            writer_pid=self.pid if pid is None else pid,
        )

    def test_exact_active_writer_qualifies_only_when_explicit(self):
        self.validate()
        with self.assertRaises(runtime.state.PersistenceError):
            runtime.validate_image(
                self.profile, self.image, self.evidence, self.value["kernel"]
            )

    def test_extra_process_or_wrong_main_pid_refuses(self):
        for section, field, value in (
            ("accounts", "uid_processes", [321, 322]),
            ("accounts", "gid_processes", []),
            ("accounts", "home_exists", True),
            ("unit", "MainPID", "322"),
            ("unit", "UnitFileState", "enabled"),
            ("unit", "SubState", "dead"),
        ):
            with self.subTest(field=field):
                evidence = copy.deepcopy(self.evidence)
                evidence[section][field] = value
                with self.assertRaises(runtime.state.PersistenceError):
                    self.validate(evidence)
        for pid in (True, 0, 1, "321"):
            with self.subTest(pid=pid), self.assertRaises(
                runtime.state.PersistenceError
            ):
                self.validate(pid=pid)

    def test_active_writer_does_not_bypass_program_or_account_checks(self):
        for mutation in ("program", "unit", "account", "base"):
            with self.subTest(mutation=mutation):
                evidence = copy.deepcopy(self.evidence)
                if mutation in {"program", "unit"}:
                    path = (
                        self.image.PROGRAM
                        if mutation == "program"
                        else self.image.UNIT_PATH
                    )
                    evidence["artifacts"][path]["sha256"] = "0" * 64
                elif mutation == "account":
                    evidence["accounts"]["account"]["locked"] = False
                else:
                    evidence["accounts"]["base"]["passwd"] = "0" * 64
                with self.assertRaises(runtime.state.PersistenceError):
                    self.validate(evidence)

    def test_actual_guest_probe_uses_explicit_writer_and_closes_process_state(self):
        probe = fixtures.GuestImageProgramTests("runTest")
        frame, profile, kernel, executed = probe.run_program(writer_pid=self.pid)
        runtime.validate_image(profile, self.image, frame, kernel, writer_pid=self.pid)
        self.assertEqual(executed, [True])
        for fault in ("artifact", "process"):
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                probe.run_program(writer_pid=self.pid, fault=fault)


if __name__ == "__main__":
    unittest.main()
