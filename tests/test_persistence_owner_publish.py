"""The initial owner bootstrap keeps starts denied and retires old descriptors."""

import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_publish as publish,
    persistence_observe as observe,
    persistence_state as state,
    persistence_attach as attach,
    persistence_backup as backup,
    persistence_config_lock as config_lock,
    persistence_pair_lock as pair_lock,
    persistence_recipient as recipient,
)
from test_persistence_recipient import example_request


@unittest.skipUnless(
    os.environ.get("CMDMESH_HANDOFF_GUARD_SOURCE"),
    "provide the pinned standalone owner guard",
)
class PublicationPolicyTests(unittest.TestCase):
    def setUp(self):
        source = Path(os.environ["CMDMESH_HANDOFF_GUARD_SOURCE"])
        self.guard_raw = source.read_bytes()
        self.guard = publish.load_guard_source(self.guard_raw)
        policy = json.loads(
            (source.parent / "prestart-manifest.example.json").read_bytes()
        )
        self.request = example_request()
        self.request["source_request"] = {
            "schema_version": 1,
            "source": {
                "selector": {
                    "origin": "example",
                    "node": policy["node"],
                    "kind": "proxmox.lxc",
                    "vmid": policy["vmid"],
                },
                "host_profile": dict.fromkeys(
                    (
                        "machine_id_sha256",
                        "ca_certificate_sha256",
                        "leaf_certificate_sha256",
                    ),
                    "a" * 64,
                ),
                "owner_tag": policy["owner_tag"],
                "generation_tag": policy["generation_tag"],
            },
            "policy": policy,
            "reference_guard": {
                "path": "/srv/reference-guard/guard.py",
                "sha256": observe.REFERENCE_GUARD_SHA256,
            },
            "backup_store": {
                "mountpoint": "/srv/backup",
                "source": "192.0.2.20:/backup",
                "file_uid": 99,
                "file_gid": 99,
            },
            "versions": {
                "pve-manager": "9.2.21",
                "pve-container": "6.1.14",
                "zfsutils-linux": "2.4.0-pve1",
            },
        }
        root = {
            "volume": "local:102/vm-102-disk-0.raw",
            "path": "/var/lib/vz/images/102/vm-102-disk-0.raw",
            "uuid": "44444444-4444-4444-4444-444444444444",
            "identity": [1, 84, 0o100640, 0, 0, 1, 2 * 1024**3, 3, 3],
        }
        self.attached = {
            "target": {"vmid": 102, "rootfs": root},
            "generated": {"stable_sha256": "c" * 64},
            "controls": {
                name: {"files": {"50-cmdmesh-reference.conf": {"sha256": "f" * 64}}}
                for name in (
                    "pve-container@101.service",
                    "pve-container-debug@101.service",
                )
            },
        }

    def test_derivation_creates_a_new_owner_without_mutating_old_policy(self):
        original = copy.deepcopy(self.request)
        policy = publish.policy_from(self.request, self.attached, self.guard)
        self.guard.validate_policy(policy)
        self.assertEqual(policy["schema_version"], 3)
        self.assertEqual(policy["vmid"], 102)
        self.assertEqual(policy["retired_guest"]["vmid"], 101)
        self.assertEqual(policy["retired_guest"]["preserved_dropin_sha256"], "f" * 64)
        self.assertEqual(policy["rootfs"]["inode"], 84)
        self.assertEqual(
            policy["rootfs"]["uuid"], self.attached["target"]["rootfs"]["uuid"]
        )
        self.assertEqual(
            policy["application"], original["source_request"]["policy"]["application"]
        )
        self.assertEqual(self.request, original)

    def test_new_source_descriptor_has_real_new_identity_and_fixed_guard_path(self):
        policy = publish.policy_from(self.request, self.attached, self.guard)
        request = publish.source_from(self.request, policy)
        observe.validate_request(request, self.guard)
        self.assertEqual(request["source"]["selector"]["vmid"], 102)
        self.assertEqual(
            request["source"]["generation_tag"],
            self.request["target"]["generation_tag"],
        )
        self.assertEqual(request["reference_guard"]["sha256"], publish.GUARD_SHA)
        self.assertEqual(
            Path(request["reference_guard"]["path"]),
            publish.claim_path(self.request) / "guard.py",
        )
        self.assertEqual(
            request["source"]["host_profile"],
            self.request["source_request"]["source"]["host_profile"],
        )
        self.assertEqual(
            self.request["source_request"]["source"]["selector"]["vmid"], 101
        )

    def test_conflicting_old_guard_bytes_or_reused_generation_refuse(self):
        changed = copy.deepcopy(self.attached)
        changed["controls"]["pve-container-debug@101.service"]["files"][
            "50-cmdmesh-reference.conf"
        ]["sha256"] = ("e" * 64)
        with self.assertRaises(state.PersistenceError):
            publish.policy_from(self.request, changed, self.guard)
        request = copy.deepcopy(self.request)
        request["target"]["generation_tag"] = request["source_request"]["source"][
            "generation_tag"
        ]
        with self.assertRaises(ValueError):
            publish.policy_from(request, self.attached, self.guard)

    def test_this_bootstrap_does_not_accept_an_already_owner_aware_source(self):
        request = copy.deepcopy(self.request)
        request["source_request"]["policy"]["schema_version"] = 3
        with self.assertRaises(state.PersistenceError):
            publish.policy_from(request, self.attached, self.guard)

    def test_publication_controls_cannot_be_inside_retained_datasets(self):
        for which in ("runtime", "legacy-reference"):
            request = copy.deepcopy(self.request)
            if which == "runtime":
                request["source_request"]["policy"]["datasets"]["data"][
                    "mountpoint"
                ] = str(publish.RUNTIME_ROOT)
            else:
                request["source_request"]["reference_guard"]["path"] = (
                    request["source_request"]["policy"]["datasets"]["config"][
                        "mountpoint"
                    ]
                    + "/guard.py"
                )
            with self.subTest(which=which), self.assertRaises(state.PersistenceError):
                publish.policy_from(request, self.attached, self.guard)

    def test_unapproved_program_bytes_are_refused_before_execution(self):
        with self.assertRaises(state.PersistenceError):
            publish.load_guard_source(
                b"raise RuntimeError('unapproved code executed')\n"
            )

    def test_retirement_stub_fails_without_loading_any_manifest(self):
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(
            dir=ROOT / ".generated", prefix="retired-stub-"
        ) as scratch:
            path = Path(scratch) / "guard.py"
            path.write_bytes(publish.RETIRED_STUB)
            for args in ([], ["--manifest", "/missing/private.json", "--vmid", "101"]):
                result = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(path), *args],
                    capture_output=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout + result.stderr, b"")
            self.assertEqual(
                {item.name for item in Path(scratch).iterdir()}, {"guard.py"}
            )

    def test_retained_old_descriptor_refuses_before_host_or_data_reads(self):
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(
            dir=ROOT / ".generated", prefix="retired-reference-"
        ) as scratch:
            path = Path(scratch) / "guard.py"
            path.write_bytes(publish.RETIRED_STUB)
            path.chmod(0o600)
            old = copy.deepcopy(self.request["source_request"])
            old["reference_guard"]["path"] = str(path)
            with mock.patch.object(observe, "host_facts") as host, mock.patch.object(
                observe, "read_database"
            ) as database:
                with self.assertRaisesRegex(state.PersistenceError, "guard-changed"):
                    observe.observe(old)
            host.assert_not_called()
            database.assert_not_called()


@unittest.skipUnless(
    os.environ.get("CMDMESH_HANDOFF_GUARD_SOURCE"),
    "provide the pinned standalone owner guard",
)
class PublicationFilesystemTests(unittest.TestCase):
    def setUp(self):
        base = PublicationPolicyTests("runTest")
        base.setUp()
        self.request, self.guard, self.guard_raw = (
            base.request,
            base.guard,
            base.guard_raw,
        )
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(
            dir=ROOT / ".generated", prefix="owner-publication-"
        )
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.units = self.root / "systemd"
        self.units.mkdir(mode=0o700)
        self.managed = self.root / "managed"
        self.managed.mkdir(mode=0o700)
        self.legacy = self.root / "legacy/guard.py"
        self.legacy.parent.mkdir(mode=0o700)
        self.legacy.write_bytes(
            (
                Path(os.environ["CMDMESH_HANDOFF_GUARD_SOURCE"]).parent
                / "prestart_guard.py"
            ).read_bytes()
        )
        self.legacy.chmod(0o600)
        self.request["source_request"]["reference_guard"]["path"] = str(self.legacy)
        self.lock_root = self.root / "locks"
        self.lock_root.mkdir(mode=0o700)
        for vmid in (101, 102):
            (self.lock_root / f"pve-config-{vmid}.lock").touch(mode=0o600)
            for unit in attach.unit_names(vmid):
                directory = self.units / (unit + ".d")
                directory.mkdir(mode=0o700)
                name = (
                    "50-cmdmesh-reference.conf"
                    if vmid == 101
                    else "50-cmdmesh-blank-prestart.conf"
                )
                (directory / name).write_bytes(
                    b"[Service]\nExecStartPre=/original/guard\n"
                )
                (directory / name).chmod(0o600)
                (directory / attach.DENIAL_NAME).write_bytes(attach.DENIAL)
                (directory / attach.DENIAL_NAME).chmod(0o600)
        self.application = {
            "instance_id": self.request["source_request"]["policy"]["application"][
                "instance_id"
            ],
            "config_sha256": self.request["source_request"]["policy"]["application"][
                "config_sha256"
            ],
            "mapping": dict(state.MAPPING),
            "database_sha256": "6" * 64,
            "records_sha256": "7" * 64,
            "record_count": 1,
        }
        self.events = []
        self.app_locked = False
        self.old_facts = {
            "source": self.request["source_request"]["source"],
            "application": self.application,
            "quiesced": True,
        }

        @contextmanager
        def source(request, require_stopped=False):
            self.assertTrue(require_stopped)
            self.assertFalse(
                self.app_locked, "application lock nested across source generations"
            )
            version = request["policy"]["schema_version"]
            if version == 2 and self.legacy.read_bytes() == publish.RETIRED_STUB:
                raise state.PersistenceError("persistence-guard-changed")
            self.assert_both_leased()
            self.app_locked = True
            self.events.append("enter" + str(version))
            try:
                if version == 3:
                    self.assertEqual(self.legacy.read_bytes(), publish.RETIRED_STUB)
                    self.assertEqual(
                        json.loads(
                            self.guard.owner_path(request["policy"]).read_bytes()
                        ),
                        self.guard.owner_document(request["policy"]),
                    )
                yield {
                    **copy.deepcopy(self.old_facts),
                    "source": copy.deepcopy(request["source"]),
                }
            finally:
                self.app_locked = False
                self.events.append("close" + str(version))

        for patch in (
            mock.patch.object(publish, "ROOT_UID", os.geteuid()),
            mock.patch.object(publish, "SYSTEM_ROOT", self.root),
            mock.patch.object(publish, "RUNTIME_ROOT", self.managed / "publication"),
            mock.patch.object(attach, "UNIT_ROOT", self.units),
            mock.patch.object(attach, "ROOT_UID", os.geteuid()),
            mock.patch.object(attach, "ROOT_GID", os.getegid()),
            mock.patch.object(backup, "RUNTIME_ROOT", self.managed / "persistence"),
            mock.patch.object(config_lock, "LOCK_ROOT", self.lock_root),
            mock.patch.object(config_lock, "ROOT_UID", os.geteuid()),
            mock.patch.dict(
                self.guard.owner_path.__globals__,
                {"OWNERS_ROOT": self.managed / "owners", "ROOT_UID": os.geteuid()},
            ),
            mock.patch.object(
                publish, "load_guard_source", side_effect=self.guard_source
            ),
            mock.patch.object(observe, "source_state", side_effect=source),
            mock.patch.object(publish, "unit_state", side_effect=self.unit_state),
            mock.patch.object(
                publish,
                "reload_units",
                side_effect=lambda: self.events.append("reload"),
            ),
            mock.patch.object(publish, "guard_cli", side_effect=self.guard_cli),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        with pair_lock.locked_pair(
            self.request["source_request"]["policy"]["datasets"], initialize=True
        ):
            pass
        current = copy.deepcopy(base.attached)
        current["controls"] = self.controls()
        config = recipient.create_request(self.request)
        for key in ("vmid", "ostemplate", "start"):
            del config[key]
        for key in ("cores", "memory", "swap", "unprivileged", "onboot", "protection"):
            config[key] = int(config[key])
        config.update(
            arch="amd64",
            ostype="ubuntu",
            rootfs="local:102/vm-102-disk-0.raw,size=2G",
            digest="f" * 40,
            **attach.bind_parameters(self.request),
        )
        current["target"].update(
            config=config,
            pending=[],
            status={"vmid": 102, "status": "stopped", "uptime": 0},
        )
        current.update(
            prepared_sha256="a" * 64,
            phase="retained-attached-starts-denied",
            attachment_verified=True,
            phase_journal_sha256="d" * 64,
            **attach.FLAGS,
        )
        self.attached = current
        self.completion_sha = state.sha256(state.canonical(current))
        self.frozen = {
            "recipient_prepared": {"request": self.request},
            "target": current["target"],
            "backup_history": {"completed-backup": {"completion_sha256": "c" * 64}},
        }
        self.attachment_raw = state.canonical(self.frozen)
        self.attachment_sha = state.sha256(self.attachment_raw)
        self.attached["prepared_sha256"] = self.attachment_sha
        self.completion_sha = state.sha256(state.canonical(self.attached))
        for patch in (
            mock.patch.object(attach, "load_prepared", return_value=self.frozen),
            mock.patch.object(attach, "status", side_effect=self.attachment_status),
            mock.patch.object(
                publish,
                "attachment_history",
                side_effect=lambda *args: copy.deepcopy(self.attached),
            ),
            mock.patch.object(
                publish,
                "current_target",
                side_effect=lambda *args: copy.deepcopy(self.attached["target"]),
            ),
            mock.patch.object(
                publish,
                "current_generated",
                side_effect=lambda *args: copy.deepcopy(self.attached["generated"]),
            ),
            mock.patch.object(attach, "source_check"),
            mock.patch.object(
                attach, "backup_history", return_value=self.frozen["backup_history"]
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def guard_source(self, raw):
        self.assertEqual(state.sha256(raw), publish.GUARD_SHA)
        return self.guard

    def assert_both_leased(self):
        for vmid in (101, 102):
            with self.assertRaises(config_lock.ConfigLockError):
                config_lock.require_write_available(vmid)

    def unit_state(self, unit):
        paths = sorted((self.units / (unit + ".d")).iterdir())
        return {
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "MainPID": "0",
            "DropInPaths": [str(path) for path in paths],
            "commands": [
                {
                    "path": "/usr/bin/false",
                    "argv": ["/usr/bin/false"],
                    "ignore_errors": False,
                    **{
                        key: 0
                        for key in (
                            "start_real_us",
                            "start_monotonic_us",
                            "stop_real_us",
                            "stop_monotonic_us",
                            "pid",
                            "code",
                            "status",
                        )
                    },
                }
            ],
        }

    def controls(self):
        result = {}
        for vmid in (101, 102):
            for unit in attach.unit_names(vmid):
                files = {
                    path.name: attach.control_file(path)[0]
                    for path in (self.units / (unit + ".d")).iterdir()
                }
                result[unit] = {"files": files, "unit": self.unit_state(unit)}
        return result

    def attachment_status(self, *args):
        self.assertNotEqual(
            self.legacy.read_bytes(),
            publish.RETIRED_STUB,
            "old attachment status called after retirement",
        )
        return {
            **copy.deepcopy(self.attached),
            "completion_sha256": self.completion_sha,
        }

    def guard_cli(self, prepared):
        self.assert_both_leased()
        self.assertTrue(self.app_locked)
        self.assertNotEqual(self.legacy.read_bytes(), publish.RETIRED_STUB)
        self.events.append("guard-cli")
        return {
            "exit_code": 0,
            "stdout_sha256": state.sha256(b'{"outcome": "qualified"}\n'),
        }

    def prepared(self):
        value = publish.prepare(
            self.attachment_raw,
            self.attachment_sha,
            self.completion_sha,
            self.guard_raw,
        )
        raw = state.canonical(value)
        return raw, state.sha256(raw)

    def test_prepare_creates_no_publication_or_owner_files(self):
        before = self.legacy.read_bytes(), self.controls()
        self.prepared()
        self.assertFalse(publish.RUNTIME_ROOT.exists())
        self.assertFalse((self.managed / "owners").exists())
        self.assertEqual(before, (self.legacy.read_bytes(), self.controls()))

    def test_publish_preserves_denials_and_closes_the_old_context_before_new_owner(
        self,
    ):
        raw, sha = self.prepared()
        self.events.clear()
        result = publish.apply(raw, sha, self.guard_raw)
        self.assertTrue(
            result["owner_publication_verified"] and result["legacy_source_refused"]
        )
        self.assertFalse(
            result["boot_verified"]
            or result["rebuild_verified"]
            or result["restore_verified"]
        )
        self.assertEqual(self.legacy.read_bytes(), publish.RETIRED_STUB)
        self.assertIn("guard-cli", self.events)
        self.assertGreater(self.events.index("enter3"), self.events.index("guard-cli"))
        self.assertEqual(self.events[self.events.index("enter3") - 1], "close2")
        for unit, control in self.controls().items():
            self.assertEqual(
                set(control["files"]), {"50-cmdmesh-reference.conf", attach.DENIAL_NAME}
            )
        observed = publish.status(raw, sha)
        self.assertEqual(observed["source_request"], result["source_request"])
        with self.assertRaises(state.PersistenceError):
            publish.apply(raw, sha, self.guard_raw)

    def test_guard_failure_keeps_the_once_claim_and_all_start_denials(self):
        raw, sha = self.prepared()
        with mock.patch.object(publish, "guard_cli", side_effect=OSError("uncertain")):
            with self.assertRaises(OSError):
                publish.apply(raw, sha, self.guard_raw)
        self.assertTrue(any(publish.RUNTIME_ROOT.rglob("failed.json")))
        for unit, control in self.controls().items():
            self.assertIn(attach.DENIAL_NAME, control["files"])
        with self.assertRaises(state.PersistenceError):
            publish.apply(raw, sha, self.guard_raw)

    def test_foreign_owner_path_refuses_without_creating_publication_claim(self):
        raw, sha = self.prepared()
        directory = self.guard.owner_path(json.loads(raw)["policy"]).parent
        directory.mkdir(mode=0o700, parents=True)
        with self.assertRaises(state.PersistenceError):
            publish.apply(raw, sha, self.guard_raw)
        self.assertFalse(publish.RUNTIME_ROOT.exists())

    def test_status_requires_the_recorded_guard_result(self):
        raw, sha = self.prepared()
        publish.apply(raw, sha, self.guard_raw)
        next(publish.RUNTIME_ROOT.rglob("guard-result.json")).unlink()
        with self.assertRaises((state.PersistenceError, OSError)):
            publish.status(raw, sha)

    def test_corrupt_archived_blank_guard_is_not_accepted_as_preserved_work(self):
        raw, sha = self.prepared()
        publish.apply(raw, sha, self.guard_raw)
        archive = next(publish.RUNTIME_ROOT.rglob("target-blank-0.conf"))
        archive.write_bytes(b"corrupted archive\n")
        with self.assertRaises(state.PersistenceError):
            publish.status(raw, sha)

    def test_nonzero_guard_result_stops_before_legacy_reference_retirement(self):
        raw, sha = self.prepared()
        original = self.legacy.read_bytes()
        with mock.patch.object(
            publish,
            "guard_cli",
            return_value={"exit_code": 1, "stdout_sha256": "a" * 64},
        ):
            with self.assertRaises(state.PersistenceError):
                publish.apply(raw, sha, self.guard_raw)
        self.assertEqual(self.legacy.read_bytes(), original)
        self.assertTrue(any(publish.RUNTIME_ROOT.rglob("failed.json")))

    def test_status_hash_refusal_precedes_all_filesystem_access(self):
        raw, sha = self.prepared()
        with mock.patch.object(publish, "file_info") as info, mock.patch.object(
            backup, "private_directory"
        ) as directory:
            with self.assertRaises(state.PersistenceError):
                publish.status(raw, "f" * 64)
        info.assert_not_called()
        directory.assert_not_called()

    def test_owner_changed_after_successor_context_closes_cannot_complete(self):
        raw, sha = self.prepared()
        original = observe.source_state

        @contextmanager
        def source(request, **kwargs):
            with original(request, **kwargs) as value:
                yield value
            if request["policy"]["schema_version"] == 3:
                self.guard.owner_path(request["policy"]).write_bytes(b"{}\n")

        with mock.patch.object(observe, "source_state", side_effect=source):
            with self.assertRaises(state.PersistenceError):
                publish.apply(raw, sha, self.guard_raw)
        self.assertFalse(any(publish.RUNTIME_ROOT.rglob("complete.json")))
        self.assertTrue(any(publish.RUNTIME_ROOT.rglob("failed.json")))

    def test_late_guard_result_damage_retains_complete_and_failed_but_status_refuses(
        self,
    ):
        raw, sha = self.prepared()
        original = backup.write_private

        def write(path, value):
            result = original(path, value)
            if path.name == "complete.json":
                (path.parent / "guard-result.json").write_bytes(b"{}\n")
            return result

        with mock.patch.object(backup, "write_private", side_effect=write):
            with self.assertRaises(state.PersistenceError):
                publish.apply(raw, sha, self.guard_raw)
        self.assertTrue(any(publish.RUNTIME_ROOT.rglob("complete.json")))
        self.assertTrue(any(publish.RUNTIME_ROOT.rglob("failed.json")))
        with self.assertRaises(state.PersistenceError):
            publish.status(raw, sha)
        with self.assertRaises(state.PersistenceError):
            publish.apply(raw, sha, self.guard_raw)

    def test_interruption_after_archiving_legacy_keeps_denials_and_consumes_claim(self):
        raw, sha = self.prepared()
        original = publish.write_raw

        def write(path, value):
            if path == self.legacy:
                raise OSError("injected write interruption")
            return original(path, value)

        with mock.patch.object(publish, "write_raw", side_effect=write):
            with self.assertRaises(OSError):
                publish.apply(raw, sha, self.guard_raw)
        self.assertFalse(self.legacy.exists())
        self.assertTrue(any(publish.RUNTIME_ROOT.rglob("legacy-guard.py")))
        self.assertTrue(any(publish.RUNTIME_ROOT.rglob("failed.json")))
        self.assertFalse(any(publish.RUNTIME_ROOT.rglob("complete.json")))
        for control in self.controls().values():
            self.assertIn(attach.DENIAL_NAME, control["files"])
        with self.assertRaises(state.PersistenceError):
            publish.apply(raw, sha, self.guard_raw)

    def test_changed_guard_result_hash_breaks_the_completion_chain(self):
        raw, sha = self.prepared()
        publish.apply(raw, sha, self.guard_raw)
        result = next(publish.RUNTIME_ROOT.rglob("guard-result.json"))
        result.write_bytes(state.canonical({"exit_code": 0, "stdout_sha256": "a" * 64}))
        with self.assertRaises(state.PersistenceError):
            publish.status(raw, sha)

    def test_boolean_exit_code_is_not_an_exit_status(self):
        raw, sha = self.prepared()
        original = self.legacy.read_bytes()
        with mock.patch.object(
            publish,
            "guard_cli",
            return_value={"exit_code": False, "stdout_sha256": "a" * 64},
        ):
            with self.assertRaises(state.PersistenceError):
                publish.apply(raw, sha, self.guard_raw)
        self.assertEqual(self.legacy.read_bytes(), original)

    def test_owner_change_during_last_native_query_cannot_complete(self):
        raw, sha = self.prepared()
        original = publish.current_generated

        def generated(request):
            result = original(request)
            owner = self.guard.owner_path(json.loads(raw)["policy"])
            if (
                self.legacy.exists()
                and self.legacy.read_bytes() == publish.RETIRED_STUB
            ):
                owner.write_bytes(b"{}\n")
            return result

        with mock.patch.object(publish, "current_generated", side_effect=generated):
            with self.assertRaises(state.PersistenceError):
                publish.apply(raw, sha, self.guard_raw)
        self.assertFalse(any(publish.RUNTIME_ROOT.rglob("complete.json")))

    def test_status_rejects_a_denial_changed_during_last_native_query(self):
        raw, sha = self.prepared()
        publish.apply(raw, sha, self.guard_raw)
        original = publish.current_generated

        def generated(request):
            result = original(request)
            (
                self.units / (attach.unit_names(101)[0] + ".d") / attach.DENIAL_NAME
            ).write_bytes(b"[Service]\n")
            return result

        with mock.patch.object(publish, "current_generated", side_effect=generated):
            with self.assertRaises(state.PersistenceError):
                publish.status(raw, sha)

    def test_new_backup_claim_between_fresh_preflight_and_final_lease_refuses_before_claim(
        self,
    ):
        raw, sha = self.prepared()
        count = 0

        def history(*args):
            nonlocal count
            count += 1
            self.assert_both_leased()
            if count > 1:
                raise state.PersistenceError("persistence-attach-backup-incomplete")
            return self.frozen["backup_history"]

        with mock.patch.object(attach, "backup_history", side_effect=history):
            with self.assertRaises(state.PersistenceError):
                publish.apply(raw, sha, self.guard_raw)
        self.assertFalse(publish.RUNTIME_ROOT.exists())
        self.assertNotEqual(self.legacy.read_bytes(), publish.RETIRED_STUB)
