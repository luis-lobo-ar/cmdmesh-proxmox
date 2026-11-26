"""A task log alone cannot establish a normal native worker return."""

import copy
import importlib
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_guest_api as api,
    persistence_state as state,
)


class OwnerReaperTests(unittest.TestCase):
    def setUp(self):
        self.reaper = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils."
            "persistence_owner_reaper"
        )
        self.binding = api.GuestBinding(
            "pve-example", 102, "1" * 64, "2" * 64, "3" * 64
        )
        self.boot = "11111111-2222-3333-4444-555555555555"
        self.sources = "a" * 64
        self.upid = "UPID:pve-example:00000100:00002000:6553F100:vzstart:102:root@pam:"

    def event(self, message, pid, tick, sequence, *, child=False):
        return {
            "MESSAGE": message,
            "PRIORITY": "6",
            "SYSLOG_IDENTIFIER": "pvedaemon",
            "_PID": str(pid),
            "_UID": "0",
            "_GID": "0",
            "_EXE": "/usr/bin/perl",
            "_COMM": ("task UPID:pve-example" if child else "pvedaemon worker")[:15],
            "_SYSTEMD_UNIT": "pvedaemon.service",
            "_SYSTEMD_INVOCATION_ID": "6" * 32,
            "_BOOT_ID": self.boot.replace("-", ""),
            "__REALTIME_TIMESTAMP": str(1700000000000000 + tick),
            "__MONOTONIC_TIMESTAMP": str(tick),
            "__SEQNUM": str(sequence),
            "__SEQNUM_ID": "7" * 32,
            "__CURSOR": (
                f"s={'7'*32};i={sequence:x};b={self.boot.replace('-', '')};"
                f"m={tick:x};t={1700000000000000 + tick:x};x=abcdef0123456789"
            ),
        }

    def evidence(self, *, warnings=True):
        code = "WARNINGS: 1" if warnings else "OK"
        return {
            "document_type": "cmdmesh.proxmox.owner-normal-return-observation",
            "schema_version": 1,
            "source_manifest_sha256": self.sources,
            "task": {
                **api.parse_upid(self.binding, self.upid),
                "status": "stopped",
                "exitstatus": code,
            },
            "log": (
                [{"n": 1, "t": api.WARNING}, {"n": 2, "t": "TASK WARNINGS: 1"}]
                if warnings
                else [{"n": 1, "t": "TASK OK"}]
            ),
            # journalctl may return reverse chronological order.
            "events": [
                self.event(f"<root@pam> end task {self.upid} {code}", 200, 12000, 43),
                self.event(f"starting CT 102: {self.upid}", 256, 11000, 42, child=True),
                self.event(f"<root@pam> starting task {self.upid}", 200, 10000, 41),
            ],
        }

    def validate(self, value, **overrides):
        raw = state.canonical(value)
        args = {"birth_floor": 8192, "excluded_upids": ()}
        args.update(overrides)
        return self.reaper.validate_normal_return(
            self.binding, self.boot, self.sources, raw, state.sha256(raw), **args
        )

    def refuses(self, value, **overrides):
        with self.assertRaises(ValueError):
            self.validate(value, **overrides)

    def test_normal_return_with_exact_known_warning_is_observation_only(self):
        value = self.evidence()
        before = copy.deepcopy(value)
        result = self.validate(value)
        self.assertEqual(value, before)
        self.assertEqual(result["upid"], self.upid)
        self.assertEqual(result["worker"], {"pid": 256, "pstart": 8192})
        self.assertIs(result["normal_return_observed"], True)
        for key in (
            "original_request_fenced",
            "original_native_operation_qualified",
            "ack_recovered",
            "native_action_dispatched",
        ):
            self.assertIs(result[key], False)
        self.assertEqual(
            result["observation_sha256"], state.sha256(state.canonical(value))
        )

    def test_exact_clean_exit_also_has_independent_parent_witness(self):
        self.assertEqual(
            self.validate(self.evidence(warnings=False))["exitstatus"], "OK"
        )

    def test_known_warning_and_forged_terminal_log_cannot_hide_abnormal_exit(self):
        value = self.evidence()
        value["events"][0]["PRIORITY"] = "3"
        self.refuses(value)
        value["events"] = []
        self.refuses(value)

    def test_missing_extra_duplicate_or_unknown_event_refuses(self):
        for events in (
            self.evidence()["events"][:2],
            self.evidence()["events"] * 2,
            [*self.evidence()["events"], self.event("unrelated", 200, 13000, 44)],
        ):
            value = self.evidence()
            value["events"] = events
            self.refuses(value)

    def test_trusted_producer_fields_must_join_all_three_events(self):
        changes = {
            "_BOOT_ID": "0" * 32,
            "_UID": "1000",
            "_GID": "1000",
            "_EXE": "/usr/bin/logger",
            "_COMM": "logger",
            "_SYSTEMD_UNIT": "other.service",
            "_SYSTEMD_INVOCATION_ID": "8" * 32,
            "SYSLOG_IDENTIFIER": "other",
            "PRIORITY": 6,
            "_PID": "257",
            "MESSAGE": "end task " + self.upid,
        }
        for index in range(3):
            for key, replacement in changes.items():
                with self.subTest(index=index, key=key):
                    value = self.evidence()
                    value["events"][index][key] = replacement
                    self.refuses(value)

    def test_parent_pid_is_joined_not_a_fixed_host_pid(self):
        value = self.evidence()
        value["events"][0]["_PID"] = value["events"][2]["_PID"] = "999"
        self.assertIs(self.validate(value)["normal_return_observed"], True)
        for pid in ("0", "1", "256", "0999", True, 999):
            value["events"][0]["_PID"] = value["events"][2]["_PID"] = pid
            self.refuses(value)

    def test_same_boot_journal_sequence_and_monotonic_order_are_required(self):
        for index, field, replacement in (
            (0, "__SEQNUM", "40"),
            (0, "__MONOTONIC_TIMESTAMP", "9000"),
            (0, "__SEQNUM_ID", "8" * 32),
            (0, "__CURSOR", "forged"),
            (0, "__REALTIME_TIMESTAMP", True),
            (0, "__SEQNUM", 43),
        ):
            with self.subTest(field=field):
                value = self.evidence()
                value["events"][index][field] = replacement
                self.refuses(value)

    def test_coherent_cursor_cannot_hide_backwards_monotonic_or_sequence(self):
        for tick, sequence in ((9000, 43), (12000, 40), (12000, 42)):
            value = self.evidence()
            value["events"][0] = self.event(
                f"<root@pam> end task {self.upid} WARNINGS: 1", 200, tick, sequence
            )
            self.refuses(value)

    def test_bounded_exact_task_log_is_required_not_only_last_line(self):
        for log in (
            [{"n": 1, "t": "TASK WARNINGS: 1"}],
            [{"n": 1, "t": "arbitrary output"}, *self.evidence()["log"]],
            [{"n": True, "t": api.WARNING}, {"n": 2, "t": "TASK WARNINGS: 1"}],
        ):
            value = self.evidence()
            value["log"] = log
            self.refuses(value)

    def test_task_identity_status_and_source_manifest_are_external_bindings(self):
        for key, replacement in {
            "pid": True,
            "pstart": True,
            "status": "running",
            "exitstatus": "OK",
            "node": "pve-other",
            "id": "103",
            "user": "other@pam",
            "type": "vzshutdown",
        }.items():
            value = self.evidence()
            value["task"][key] = replacement
            self.refuses(value)
        value = self.evidence()
        value["source_manifest_sha256"] = "b" * 64
        self.refuses(value)

    def test_birth_floor_is_inclusive_but_known_prior_upid_is_excluded(self):
        self.assertIs(
            self.validate(self.evidence(), birth_floor=8192)["normal_return_observed"],
            True,
        )
        self.refuses(self.evidence(), birth_floor=8193)
        self.refuses(self.evidence(), excluded_upids=(self.upid,))
        self.refuses(self.evidence(), birth_floor=True)

    def test_input_hash_bounds_duplicate_keys_and_canonical_bytes(self):
        raw = state.canonical(self.evidence())
        for data, digest in (
            (raw, "0" * 64),
            (raw + b"\n", state.sha256(raw + b"\n")),
            (b"x" * 262145, state.sha256(b"x" * 262145)),
            (
                raw[:-1] + b',"schema_version":1}',
                state.sha256(raw[:-1] + b',"schema_version":1}'),
            ),
        ):
            with self.assertRaises(ValueError):
                self.reaper.validate_normal_return(
                    self.binding,
                    self.boot,
                    self.sources,
                    data,
                    digest,
                    birth_floor=8192,
                )

    def test_exact_schema_types_refuse_python_equality_aliases(self):
        for key, replacement in (("schema_version", True), ("events", {}), ("log", {})):
            value = self.evidence()
            value[key] = replacement
            self.refuses(value)
        value = self.evidence()
        value["events"][0]["unexpected"] = "field"
        self.refuses(value)

    def test_normal_parent_witness_without_child_provenance_refuses(self):
        value = self.evidence()
        del value["events"][1]["_UID"]
        self.refuses(value)
        value = self.evidence()
        value["events"][1]["MESSAGE"] = "starting CT 103: " + self.upid
        self.refuses(value)

    def test_exclusion_input_is_finite_target_bound_and_unambiguous(self):
        for exclusions in (
            [self.upid],
            (self.upid, self.upid),
            (self.upid.replace(":102:", ":103:"),),
            tuple([self.upid] * 33),
        ):
            self.refuses(self.evidence(), excluded_upids=exclusions)

    def test_observation_cannot_smuggle_positive_recovery_flags(self):
        for key in (
            "original_request_fenced",
            "original_native_operation_qualified",
            "ack_recovered",
        ):
            value = self.evidence()
            value[key] = True
            self.refuses(value)

    def test_validator_never_observes_host_clock_files_or_network(self):
        with mock.patch(
            "builtins.open", side_effect=AssertionError("file access")
        ), mock.patch(
            "time.time", side_effect=AssertionError("clock access")
        ), mock.patch(
            "socket.socket", side_effect=AssertionError("network access")
        ):
            self.assertIs(
                self.validate(self.evidence())["normal_return_observed"], True
            )


if __name__ == "__main__":
    unittest.main()
