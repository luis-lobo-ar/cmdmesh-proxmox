"""Retained binds must remain unusable until a separately qualified start."""

from contextlib import contextmanager
import copy
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_attach as attach,
    persistence_config_lock as config_lock,
    persistence_pair_lock as pair_lock,
    persistence_recipient as recipient,
    persistence_state as state,
)
import test_persistence_recipient as fixtures
import test_persistence_blank_guard as blank
from test_persistence_state import manifest

REAL_NATIVE_STEP = attach.native_step
REAL_BACKUP_HISTORY = attach.backup_history
REAL_GENERATED = attach.generated


class AttachmentTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RecipientTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        (self.root / "managed").mkdir(mode=0o700)
        self.request = self.fixture.request
        for role, reference in manifest()["datasets"].items():
            self.request["source_request"]["policy"]["datasets"][role].update(
                name=reference["name"], guid=reference["guid"]
            )
        policy, _ = blank.model()
        self.target = {
            "vmid": 102,
            "config": policy["config"],
            "pending": [],
            "status": {"status": "stopped", "uptime": 0},
            "rootfs": {
                **policy["rootfs"],
                "volume": "local:102/vm-102-disk-0.raw",
                "identity": [*policy["rootfs"]["identity"], 1, 1],
            },
        }
        self.fixture.after = self.target
        self.raw, self.sha = self.fixture.prepared()
        self.units = self.root / "systemd"
        self.units.mkdir(mode=0o755)
        self.locks = self.root / "locks"
        self.locks.mkdir(mode=0o700)
        for vmid in (101, 102):
            for unit in attach.unit_names(vmid):
                directory = self.units / (unit + ".d")
                directory.mkdir(mode=0o700)
                name = attach.preserved_name(vmid == 101)
                (directory / name).write_bytes(
                    b"[Service]\nExecStartPre=/checked/guard\n"
                )
                (directory / name).chmod(0o600)
            (self.locks / f"pve-config-{vmid}.lock").touch(mode=0o600)
        self.calls = []
        self.pair_held = False

        @contextmanager
        def pair(*args, **kwargs):
            self.pair_held = True
            try:
                yield {
                    "pair_key": state.pair_key(
                        self.request["source_request"]["policy"]["datasets"]
                    )
                }
            finally:
                self.pair_held = False

        for patch in (
            mock.patch.object(attach, "UNIT_ROOT", self.units),
            mock.patch.object(
                attach, "RUNTIME_ROOT", self.root / "managed/attachments"
            ),
            mock.patch.object(attach, "ROOT_UID", os.geteuid()),
            mock.patch.object(attach, "ROOT_GID", os.getegid()),
            mock.patch.object(config_lock, "LOCK_ROOT", self.locks),
            mock.patch.object(config_lock, "ROOT_UID", os.geteuid()),
            mock.patch.object(pair_lock, "locked_pair", side_effect=pair),
            mock.patch.object(
                attach, "backup_history", return_value={"closed": "d" * 64}
            ),
            mock.patch.object(
                attach,
                "target_state",
                side_effect=lambda *args, **kwargs: copy.deepcopy(self.target),
            ),
            mock.patch.object(attach, "generated", side_effect=self.generated),
            mock.patch.object(attach, "unit_state", side_effect=self.unit_state),
            mock.patch.object(
                attach, "reload_units", side_effect=lambda: self.calls.append("reload")
            ),
            mock.patch.object(attach, "native_step", side_effect=self.native_step),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def unit_state(self, unit):
        directory = self.units / (unit + ".d")
        denied = (directory / attach.DENIAL_NAME).exists()
        return {
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "MainPID": "0",
            "DropInPaths": [str(path) for path in sorted(directory.iterdir())],
            "commands": (
                [
                    {
                        "path": "/usr/bin/false",
                        "argv": ["/usr/bin/false"],
                        "ignore_errors": False,
                    }
                ]
                if denied
                else [
                    {
                        "path": "/checked/guard",
                        "argv": ["/checked/guard"],
                        "ignore_errors": False,
                    }
                ]
            ),
        }

    def generated(self, request):
        generation = sum(phase in attach.PHASES for phase in self.calls)
        return {
            "path": "/var/lib/lxc/102/config",
            "sha256": "a" * 64,
            "stable_sha256": "b" * 64,
            "identity": [1, 2, 0o100600, 0, 0, 1, 100, generation, generation],
            "text": "synthetic generated config",
            "cpu_selection": [0],
        }

    def native_step(self, request, phase, digest):
        self.assertTrue(self.fixture.inside_lock and self.pair_held)
        self.assertTrue(any(attach.RUNTIME_ROOT.rglob("write-possible.json")))
        self.assertEqual(digest, self.target["config"]["digest"])
        with self.assertRaises(config_lock.ConfigLockError):
            config_lock.require_write_available(101)
        config_lock.require_write_available(102)
        attach.control_state(self.request, denied=True)
        self.calls.append(phase)
        if phase == "unprotect":
            self.target["config"]["protection"] = 0
        elif phase == "attach":
            self.target["config"].update(attach.bind_parameters(request))
        elif phase == "protect":
            self.target["config"]["protection"] = 1
        else:
            self.fail(phase)
        self.target["config"]["digest"] = {
            "unprotect": "d",
            "attach": "e",
            "protect": "f",
        }[phase] * 40
        return {"exit_code": 0, "stdout_sha256": state.sha256(b"null\n")}

    def prepared(self):
        value = attach.prepare(self.raw, self.sha)
        raw = state.canonical(value)
        return raw, state.sha256(raw)

    def test_prepare_reads_current_target_without_creating_claim_or_denial(self):
        raw, sha = self.prepared()
        self.assertEqual(attach.load_prepared(raw, sha)["target"], self.target)
        self.assertFalse(attach.RUNTIME_ROOT.exists())
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.units.rglob(attach.DENIAL_NAME)), [])

    def test_generated_file_drift_refuses_before_claim(self):
        raw, sha = self.prepared()
        changed = {**self.generated(self.request), "sha256": "f" * 64}
        with mock.patch.object(attach, "generated", return_value=changed):
            with self.assertRaises(state.PersistenceError):
                attach.apply(raw, sha)
        self.assertFalse(attach.RUNTIME_ROOT.exists())

    def test_real_generated_reader_seals_exact_profile_and_refuses_raw_mount(self):
        directory = self.root / "lxc/102"
        directory.mkdir(mode=0o700, parents=True)
        path = directory / "config"
        body = (
            "lxc.rootfs.path = /var/lib/lxc/102/rootfs\n"
            "lxc.uts.name = reference-rebuilt\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cgroup2.cpu.max = 100000 100000\n"
            "lxc.cgroup2.cpuset.cpus = 0\n"
        ).encode()
        path.write_bytes(body)
        path.chmod(0o600)
        with mock.patch.object(
            attach.stage, "LXC_ROOT", directory.parent
        ), mock.patch.object(attach.stage, "ROOT_UID", os.geteuid()):
            result = REAL_GENERATED(self.request)
            self.assertEqual(result["sha256"], state.sha256(body))
            self.assertEqual(
                result["identity"], list(attach.observe.stable(path.stat()))
            )
            path.write_bytes(
                body + b"lxc.mount.entry = /foreign target none bind 0 0\n"
            )
            with self.assertRaises(state.PersistenceError):
                REAL_GENERATED(self.request)

    def test_exact_two_bind_fields_and_no_other_options(self):
        self.assertEqual(
            attach.bind_parameters(self.request),
            {
                "mp0": "/srv/reference/data,mp=/var/lib/reference-ledger,backup=0",
                "mp1": "/srv/reference/config,mp=/etc/reference-ledger,backup=0",
            },
        )
        for path in (
            "/srv/data,ro=0",
            "/srv/space here",
            "/srv/data\n",
            "/",
            "/srv/../data",
        ):
            request = copy.deepcopy(self.request)
            request["source_request"]["policy"]["datasets"]["data"]["mountpoint"] = path
            with self.subTest(path=path), self.assertRaises(state.PersistenceError):
                attach.bind_parameters(request)

    def test_once_apply_denies_all_four_starts_and_closes_after_source_lock(self):
        raw, sha = self.prepared()
        result = attach.apply(raw, sha)
        self.assertTrue(result["attachment_verified"])
        self.assertFalse(
            result["boot_verified"]
            or result["rebuild_verified"]
            or result["restore_verified"]
        )
        self.assertEqual(self.calls, ["reload", "unprotect", "attach", "protect"])
        self.assertFalse(self.fixture.inside_lock or self.pair_held)
        self.assertEqual(len(list(self.units.rglob(attach.DENIAL_NAME))), 4)
        self.assertTrue(any(attach.RUNTIME_ROOT.rglob("complete.json")))
        self.assertEqual(attach.status(raw, sha)["target"], result["target"])
        with self.assertRaises(state.PersistenceError):
            attach.apply(raw, sha)
        self.assertEqual(self.calls, ["reload", "unprotect", "attach", "protect"])

    def test_target_or_guard_drift_refuses_before_claim(self):
        raw, sha = self.prepared()
        self.target["config"]["description"] += " changed"
        with self.assertRaises(state.PersistenceError):
            attach.apply(raw, sha)
        self.assertFalse(attach.RUNTIME_ROOT.exists())
        self.assertEqual(self.calls, [])

    def test_uncertain_native_write_retains_denials_and_consumed_pair(self):
        raw, sha = self.prepared()
        with mock.patch.object(attach, "native_step", side_effect=OSError("uncertain")):
            with self.assertRaises(OSError):
                attach.apply(raw, sha)
        self.assertEqual(len(list(self.units.rglob(attach.DENIAL_NAME))), 4)
        self.assertTrue(any(attach.RUNTIME_ROOT.rglob("failed.json")))
        self.assertFalse(any(attach.RUNTIME_ROOT.rglob("complete.json")))
        with self.assertRaises(state.PersistenceError):
            attach.apply(raw, sha)
        # A new request ID must not bypass the same pair's retained claim.
        other = copy.deepcopy(self.request)
        other["operation_id"] = "e" * 64
        raw2 = state.canonical(recipient.prepare(other))
        with self.assertRaises(state.PersistenceError):
            attach.prepare(raw2, state.sha256(raw2))

    def test_ignored_false_or_extra_command_never_permits_configuration_write(self):
        raw, sha = self.prepared()
        original = self.unit_state

        def unsafe(unit):
            value = original(unit)
            if (self.units / (unit + ".d") / attach.DENIAL_NAME).exists():
                value["commands"][0]["ignore_errors"] = True
            return value

        with mock.patch.object(attach, "unit_state", side_effect=unsafe):
            with self.assertRaises(state.PersistenceError):
                attach.apply(raw, sha)
        self.assertNotIn("attach", self.calls)

    def test_projection_admits_only_exact_bindings_and_preserves_all_blank_limits(self):
        config = {**self.target["config"], **attach.bind_parameters(self.request)}
        self.assertEqual(
            attach.validate_bound_config(self.request, config),
            "local:102/vm-102-disk-0.raw",
        )
        for field, value in (
            ("mp2", "/extra,mp=/extra"),
            ("mp0", "/wrong,mp=/var/lib/reference-ledger,backup=0"),
            ("net0", "name=eth0"),
            ("cores", 2),
            ("cpulimit", True),
        ):
            changed = {**config, field: value}
            with self.subTest(field=field), self.assertRaises(state.PersistenceError):
                attach.validate_bound_config(self.request, changed)

    def test_target_change_during_source_closure_prevents_completion(self):
        raw, sha = self.prepared()

        @contextmanager
        def source(request, require_stopped=False):
            self.fixture.inside_lock = True
            try:
                yield copy.deepcopy(self.fixture.facts)
            finally:
                self.fixture.inside_lock = False
                if "protect" in self.calls:
                    self.target["config"]["protection"] = 0

        with mock.patch.object(attach.observe, "source_state", side_effect=source):
            with self.assertRaises(state.PersistenceError):
                attach.apply(raw, sha)
        self.assertFalse(any(attach.RUNTIME_ROOT.rglob("complete.json")))

    def test_each_uncertain_phase_stops_without_retry_or_unplanned_rollback(self):
        original = self.native_step
        raw, sha = self.prepared()

        def uncertain(request, phase, digest):
            if phase == "protect":
                raise OSError("uncertain protection write")
            return original(request, phase, digest)

        with mock.patch.object(attach, "native_step", side_effect=uncertain):
            with self.assertRaises(OSError):
                attach.apply(raw, sha)
        self.assertEqual(self.calls, ["reload", "unprotect", "attach"])
        self.assertEqual(self.target["config"]["protection"], 0)
        self.assertEqual(len(list(self.units.rglob(attach.DENIAL_NAME))), 4)
        self.assertTrue(any(attach.RUNTIME_ROOT.rglob("protect-dispatch.json")))
        self.assertFalse(any(attach.RUNTIME_ROOT.rglob("protect-result.json")))
        with self.assertRaises(state.PersistenceError):
            attach.apply(raw, sha)

    def test_native_commands_have_only_finite_phase_specific_options(self):
        # Run the real dispatcher, not the orchestrator's simulated native step.
        with mock.patch.object(
            attach.observe, "native", return_value=b"null\n"
        ) as native:
            for phase in attach.PHASES:
                REAL_NATIVE_STEP(self.request, phase, "c" * 40)
        commands = [call.args[0] for call in native.call_args_list]
        prefix = [
            "/usr/bin/pvesh",
            "set",
            "/nodes/node-a/lxc/102/config",
            "--digest",
            "c" * 40,
        ]
        self.assertEqual(commands[0], prefix + ["--protection", "0"])
        self.assertEqual(commands[2], prefix + ["--protection", "1"])
        self.assertEqual(
            commands[1],
            prefix
            + [
                "--cores",
                "1",
                "--cpulimit",
                "1",
                "--mp0",
                "/srv/reference/data,mp=/var/lib/reference-ledger,backup=0",
                "--mp1",
                "/srv/reference/config,mp=/etc/reference-ledger,backup=0",
            ],
        )
        with mock.patch.object(attach.observe, "native") as native:
            for phase in ("delete", "start", "force"):
                with self.assertRaises(state.PersistenceError):
                    REAL_NATIVE_STEP(self.request, phase, "c" * 40)
            native.assert_not_called()

    def history(self):
        backup = attach.backup
        runtime = self.root / "managed/persistence"
        patch = mock.patch.object(backup, "RUNTIME_ROOT", runtime)
        patch.start()
        self.addCleanup(patch.stop)
        backup.runtime()
        model = manifest()
        request = {
            "schema_version": 1,
            "operation_id": model["operation_id"],
            "source_request": copy.deepcopy(self.request["source_request"]),
            "tools": {
                name: {"path": path, "sha256": "c" * 64}
                for name, path in backup.TOOL_PATHS.items()
            },
            "recipient": model["recipient"],
        }
        request["source_request"]["backup_store"] = {
            "mountpoint": "/srv/backup",
            "file_uid": 99,
            "file_gid": 99,
        }
        prepared = {
            "document_type": backup.PREPARED,
            "schema_version": 1,
            "profile_version": 1,
            "request": request,
            "observation_sha256": state.sha256(state.canonical(self.fixture.facts)),
        }
        key = attach.pair_key(self.request)
        intent = {
            "pair_key": key,
            "prepared": prepared,
            "prepared_sha256": state.sha256(state.canonical(prepared)),
        }
        directory = runtime / "operations" / model["operation_id"]
        directory.mkdir(mode=0o700)
        backup.write_private(directory / "intent.json", intent)
        identity = {"device": 1, "inode": 2, "uid": 99, "gid": 99, "mode": 0o600}
        completion = {
            "document_type": backup.COMPLETE,
            "schema_version": 1,
            "profile_version": 1,
            "operation_id": model["operation_id"],
            "pair_key": key,
            "intent_sha256": state.sha256(state.canonical(intent)),
            "prepared_sha256": intent["prepared_sha256"],
            "manifest": model,
            "manifest_sha256": state.sha256(state.canonical(model)),
            "manifest_ciphertext": {
                "name": "manifest.json.age",
                "bytes": 100,
                "sha256": "a" * 64,
            },
            "backup_store": {},
            "prefix_identity": {**identity, "mode": 0o700},
            "artifact_identities": {
                name: dict(identity)
                for name in ("data.zfs.age", "config.zfs.age", "manifest.json.age")
            },
            "backup_path": "/srv/backup/cmdmesh-"
            + model["source"]["owner_tag"].removeprefix("cmdmesh-own-")
            + "-"
            + model["operation_id"],
            "backup_verified": True,
        }
        backup.write_private(directory / "complete.json", completion)
        return directory, completion

    def test_real_closed_history_requires_matching_data_and_no_incomplete_pair(self):
        directory, completion = self.history()
        result = REAL_BACKUP_HISTORY(self.request, self.fixture.facts)
        self.assertEqual(set(result), {"a" * 64})
        changed = copy.deepcopy(self.fixture.facts)
        changed["application"]["config_sha256"] = "f" * 64
        with self.assertRaises(state.PersistenceError):
            REAL_BACKUP_HISTORY(self.request, changed)
        (directory / "complete.json").unlink()
        with self.assertRaises((state.PersistenceError, OSError)):
            REAL_BACKUP_HISTORY(self.request, self.fixture.facts)

    def test_closed_backup_with_reversed_role_guids_is_not_the_current_backup(self):
        directory, completion = self.history()
        model = completion["manifest"]
        model["datasets"]["data"]["guid"], model["datasets"]["config"]["guid"] = (
            model["datasets"]["config"]["guid"],
            model["datasets"]["data"]["guid"],
        )
        completion["manifest_sha256"] = state.sha256(state.canonical(model))
        (directory / "complete.json").unlink()
        attach.backup.write_private(directory / "complete.json", completion)
        with self.assertRaises(state.PersistenceError):
            REAL_BACKUP_HISTORY(self.request, self.fixture.facts)

    def test_status_refuses_missing_phase_result(self):
        raw, sha = self.prepared()
        attach.apply(raw, sha)
        next(attach.RUNTIME_ROOT.rglob("protect-result.json")).unlink()
        with self.assertRaises((state.PersistenceError, OSError)):
            attach.status(raw, sha)

    def test_status_recloses_target_after_slow_source_exit(self):
        raw, sha = self.prepared()
        attach.apply(raw, sha)

        @contextmanager
        def source(request, require_stopped=False):
            yield copy.deepcopy(self.fixture.facts)
            self.target["config"]["protection"] = 0

        with mock.patch.object(attach.observe, "source_state", side_effect=source):
            with self.assertRaises(state.PersistenceError):
                attach.status(raw, sha)

    def test_state_change_during_completion_sync_cannot_return_accepted(self):
        raw, sha = self.prepared()
        original = attach.backup.write_private

        def changed(path, value):
            result = original(path, value)
            if path.name == "complete.json":
                self.target["config"]["protection"] = 0
            return result

        with mock.patch.object(attach.backup, "write_private", side_effect=changed):
            with self.assertRaises(state.PersistenceError):
                attach.apply(raw, sha)
        self.assertTrue(any(attach.RUNTIME_ROOT.rglob("failed.json")))


if __name__ == "__main__":
    unittest.main()
