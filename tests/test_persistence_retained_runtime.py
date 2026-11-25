"""An OS-running observation requires actual retained, image and quiesced data proof."""

import copy
import builtins
from contextlib import ExitStack, closing, redirect_stdout
import fcntl
import importlib
import io
import json
import os
from pathlib import Path
import stat
import sqlite3
import sys
import unittest
import tempfile
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_retained_runtime as runtime,
    persistence_backup as backup,
    persistence_pair_lock as pair,
    persistence_config_lock as config_lock,
)
import test_persistence_blank_runtime as kernel_fixtures


def model():
    source = Path(os.environ["CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"])
    sys.path.insert(0, str(source.parents[2] / "tests"))
    fixture = importlib.import_module("test_reference_handoff_guard")
    policy, retained = copy.deepcopy(fixture.example())
    image_raw = (source.parent / "image.py").read_bytes()
    assert (
        runtime.state.sha256(image_raw)
        == "21bd1353bc6c95f4e4e4b94010c16c5e74b5ae8fb7434e94e3d39dfdb0357227"
    )
    helper = {"__name__": "reference_image_test_fixture"}
    exec(compile(image_raw, "<pinned-image-fixture>", "exec"), helper)
    generated = "lxc.cgroup2.cpu.max = 100000 100000\nlxc.cgroup2.cpuset.cpus = 0\n"
    policy["generated_config_stable_sha256"] = fixture.guard.generated_fingerprint(
        generated.encode()
    )[0]
    retained.update(
        generated_config_stable_sha256=policy["generated_config_stable_sha256"],
        cpu_selection=[0],
    )
    retained["config"].update(
        hostname="reference-ledger",
        memory=512,
        swap=0,
        onboot=0,
        protection=1,
        arch="amd64",
        ostype="ubuntu",
        digest="d" * 40,
    )
    root = policy["rootfs"]
    base = {name: "e" * 64 for name in helper["ACCOUNT_DATABASES"]}
    subids = {name: None for name in helper["SUBID_DATABASES"]}
    profile = {
        "schema_version": 1,
        "guard_python": source.read_text(),
        "image_python": image_raw.decode(),
        "config": copy.deepcopy(retained["config"]),
        "rootfs": {
            "path": root["path"],
            "volume": root["volume"],
            "uuid": root["uuid"],
            "identity": [
                1,
                root["inode"],
                stat.S_IFREG | 0o640,
                0,
                0,
                1,
                root["bytes"],
            ],
        },
        "accounts": {"base": base, "subids": subids},
    }
    request = {
        "schema_version": 1,
        "source": {
            "selector": {
                "origin": "example",
                "node": policy["node"],
                "kind": "proxmox.lxc",
                "vmid": policy["vmid"],
            },
            "host_profile": {
                key: "a" * 64
                for key in (
                    "machine_id_sha256",
                    "ca_certificate_sha256",
                    "leaf_certificate_sha256",
                )
            },
            "owner_tag": policy["owner_tag"],
            "generation_tag": policy["generation_tag"],
        },
        "policy": policy,
        "reference_guard": {
            "path": "/srv/reference-runtime/guard.py",
            "sha256": "1063b39ce19c688667c35f376adfa268e245be2b5758e0f4cb36593b336064e3",
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
    _, kernel = kernel_fixtures.model()
    kernel = {
        key: copy.deepcopy(kernel[key]) for key in kernel_fixtures.runtime.KERNEL_FIELDS
    }
    kernel["cgroup"].update(path=f"0::/lxc/{policy['vmid']}/ns/init.scope", cpus=[0])
    kernel["rootfs"].update(
        path=root["path"],
        resolved_path=root["path"],
        backing_file=root["path"],
        uuid=root["uuid"],
        identity=profile["rootfs"]["identity"],
    )
    kernel["security"][
        "apparmor_label"
    ] = f"lxc-{policy['vmid']}_</var/lib/lxc> (enforce)"
    kernel["generated_config"] = generated
    bindings = {}
    for index, (role, target) in enumerate(runtime.GUEST_BINDS.items(), 1):
        identity = {"device": 37 + index, "inode": 1000 + index}
        retained["datasets"][role]["directory"]["inode"] = identity["inode"]
        bindings[role] = {
            "host": identity,
            "guest": dict(identity),
            "mount": {
                "id": index,
                "device": [0, identity["device"]],
                "root": "/",
                "target": target,
                "source": policy["datasets"][role]["name"],
                "filesystem": "zfs",
                "options": ["nodev", "nosuid", "rw"],
                "super_options": ["rw"],
            },
        }
    account_files = {
        name: {
            "sha256": "e" * 64,
            "identity": [1, 50 + index, stat.S_IFREG | 0o640, 0, 42, 1, 1024, 1, 1],
        }
        for index, name in enumerate(helper["ACCOUNT_DATABASES"])
    }
    account_files.update({name: None for name in helper["SUBID_DATABASES"]})
    image = {
        "environment": {
            "uid": 0,
            "gid": 0,
            "uid_map": [[0, 100000, 65536]],
            "gid_map": [[0, 100000, 65536]],
            "interfaces": ["lo"],
            "python": [3, 12, 3],
            "sqlite": "3.45.1",
            "systemd": {"code": 0, "stdout": "running\n", "stderr": ""},
            "failed": {"code": 0, "stdout": "", "stderr": ""},
        },
        "unit": {
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "SubState": "dead",
            "MainPID": "0",
            "UnitFileState": "disabled",
            "User": "1100",
            "Group": "1100",
            "DropInPaths": "",
            "FragmentPath": helper["UNIT_PATH"],
        },
        "accounts": {
            "uid_owners": ["reference-ledger"],
            "gid_owners": ["reference-ledger"],
            "names_used": True,
            "account": dict(helper["ACCOUNT"]),
            "uid_processes": [],
            "gid_processes": [],
            "home_exists": False,
            "base": base,
            "subids": subids,
            "files": account_files,
        },
        "application_read": {
            "uid": 1100,
            "gid": 1100,
            "sha256": helper["PROGRAM_SHA256"],
            "compiled": True,
        },
        "artifacts": {
            helper["PROGRAM"]: {
                "sha256": helper["PROGRAM_SHA256"],
                "identity": [1, 81, stat.S_IFREG | 0o644, 0, 0, 1, 2048, 1, 1],
            },
            helper["UNIT_PATH"]: {
                "sha256": runtime.state.sha256(helper["service_unit"]()),
                "identity": [1, 82, stat.S_IFREG | 0o644, 0, 0, 1, 428, 1, 1],
            },
        },
        "identity": {
            "hostname": profile["config"]["hostname"],
            "root_device": os.makedev(7, 2),
            "affinity": [0],
        },
    }
    application = {
        "instance_id": policy["application"]["instance_id"],
        "config_sha256": policy["application"]["config_sha256"],
        "mapping": dict(policy["mapping"]),
        "database_sha256": "f" * 64,
        "records_sha256": "e" * 64,
        "record_count": 1,
    }
    value = {
        "schema_version": 1,
        "phase": "os_quiesced",
        "source": copy.deepcopy(request["source"]),
        "host": {
            "host_profile": request["source"]["host_profile"],
            "versions": request["versions"],
            "boot_id": "11111111-2222-3333-4444-555555555555",
            "mount_namespace": "mnt:[123]",
        },
        "guest": {
            "config": copy.deepcopy(profile["config"]),
            "status": "running",
            "pending": [],
            "ha_membership": False,
            "runtime": {"vmid": policy["vmid"], "pid": 234, "uptime": 30},
        },
        "kernel": kernel,
        "retained": retained,
        "bindings": bindings,
        "image": image,
        "application": application,
        "os_runtime_verified": True,
        "application_quiesced": True,
        "mutation_attempted": False,
        "boot_verified": False,
        "rebuild_verified": False,
        "restore_verified": False,
        "backup_verified": False,
    }
    value["image"]["directories"] = {
        name: [1, 100 + index, stat.S_IFDIR | 0o755, 0, 0, 2, 4096, 1, 1]
        for index, name in enumerate(
            (
                "/opt",
                "/opt/reference-ledger",
                "/etc",
                "/etc/systemd",
                "/etc/systemd/system",
            )
        )
    }
    reference = request["reference_guard"]["path"]
    manifest = str(Path(reference).parent / "policy.json")
    argv = [
        "/usr/bin/python3",
        "-I",
        "-S",
        "-B",
        reference,
        "--manifest",
        manifest,
        "--vmid",
        str(policy["vmid"]),
    ]
    dropin = ("[Service]\nExecStartPre=" + " ".join([*argv[:-1], "%i"]) + "\n").encode()
    files = {
        reference: request["reference_guard"]["sha256"],
        manifest: runtime.state.sha256(runtime.state.canonical(policy)),
    }
    units = {}
    for index, unit in enumerate(
        (
            f"pve-container@{policy['vmid']}.service",
            f"pve-container-debug@{policy['vmid']}.service",
        )
    ):
        path = "/etc/systemd/system/" + unit + ".d/50-cmdmesh-reference.conf"
        files[path] = runtime.state.sha256(dropin)
        command = {
            "path": argv[0],
            "argv": argv,
            "ignore_errors": False,
            "start_real_us": 1000000 if index == 0 else 0,
            "start_monotonic_us": 1000 if index == 0 else 0,
            "stop_real_us": 1500000 if index == 0 else 0,
            "stop_monotonic_us": 2000 if index == 0 else 0,
            "pid": 888 if index == 0 else 0,
            "code": 1 if index == 0 else 0,
            "status": 0,
        }
        units[unit] = {
            "LoadState": "loaded",
            "ActiveState": "active" if index == 0 else "inactive",
            "MainPID": 999 if index == 0 else 0,
            "DropInPaths": [path],
            "commands": [command],
            "directory_membership": ["50-cmdmesh-reference.conf"],
        }
    value["reference"] = {
        "files": {
            path: {
                "path": path,
                "sha256": digest,
                "identity": [1, 200 + index, stat.S_IFREG | 0o600, 0, 0, 1, 4096, 1, 1],
            }
            for index, (path, digest) in enumerate(files.items())
        },
        "units": units,
    }
    return copy.deepcopy(request), copy.deepcopy(profile), copy.deepcopy(value)


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"),
    "provide the pinned corrected recipe source",
)
class QuiescedContractTests(unittest.TestCase):
    def setUp(self):
        self.request, self.profile, self.value = model()

    def validate(self):
        return runtime.validate(self.request, self.profile, "os_quiesced", self.value)

    def test_complete_contract_is_pure_and_does_not_use_strict_stopped_observation(
        self,
    ):
        with mock.patch.object(
            runtime.kernel.observe,
            "load_guard",
            side_effect=AssertionError("must use pinned pure code"),
        ), mock.patch.object(
            runtime.kernel.observe,
            "native",
            side_effect=AssertionError("pure validator must not collect"),
        ):
            self.assertIsNone(self.validate())

    def test_active_writer_unknown_helper_and_boolean_profile_refuse(self):
        for fault in ("phase", "helper", "guard", "version"):
            request, profile, value = model()
            phase = "os_quiesced"
            if fault == "phase":
                phase = "active_writer"
            elif fault == "version":
                profile["schema_version"] = True
            else:
                profile["image_python" if fault == "helper" else "guard_python"] = (
                    "raise RuntimeError('unapproved code must not run')"
                )
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                runtime.validate(request, profile, phase, value)

    def test_active_service_user_or_changed_image_refuses(self):
        for fault in (
            "unit",
            "process",
            "shell",
            "program",
            "guest-root",
            "uid-bool",
            "exit-bool",
        ):
            self.request, self.profile, self.value = model()
            image = self.value["image"]
            if fault == "unit":
                image["unit"]["MainPID"] = "234"
            elif fault == "process":
                image["accounts"]["uid_processes"] = [234]
            elif fault == "shell":
                image["accounts"]["account"]["shell"] = "/bin/bash"
            elif fault == "program":
                image["artifacts"]["/opt/reference-ledger/ledger.py"]["sha256"] = (
                    "f" * 64
                )
            elif fault == "guest-root":
                image["identity"]["root_device"] = 1
            elif fault == "uid-bool":
                image["environment"]["uid"] = False
            else:
                image["environment"]["systemd"]["code"] = False
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.validate()

    def test_wrong_backing_owner_running_guest_and_host_refuse(self):
        for fault in ("bind", "owner", "stopped", "host", "kernel", "root-profile"):
            self.request, self.profile, self.value = model()
            if fault == "bind":
                self.value["bindings"]["data"]["guest"]["inode"] += 1
            elif fault == "owner":
                self.value["retained"]["ownership"]["document"]["active"]["vmid"] += 1
            elif fault == "stopped":
                self.value["guest"]["status"] = "stopped"
            elif fault == "host":
                self.value["host"]["host_profile"]["machine_id_sha256"] = "f" * 64
            elif fault == "kernel":
                self.value["kernel"]["rootfs"]["backing_file"] = "/srv/foreign.raw"
            else:
                self.profile["rootfs"]["identity"][1] += 1
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.validate()

    def test_flags_never_replace_consistent_sql_or_allow_mutation_claims(self):
        for fault in ("missing", "empty", "bool-count", "config", "boot", "mutation"):
            self.request, self.profile, self.value = model()
            if fault == "missing":
                del self.value["application"]
            elif fault == "empty":
                self.value["application"]["record_count"] = 0
            elif fault == "bool-count":
                self.value["application"]["record_count"] = True
            elif fault == "config":
                self.value["application"]["config_sha256"] = "f" * 64
            else:
                self.value[
                    "boot_verified" if fault == "boot" else "mutation_attempted"
                ] = True
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.validate()

    def test_changed_reference_manifest_command_or_denial_refuses(self):
        for fault in ("guard", "policy", "argv", "denial", "exit-bool"):
            self.request, self.profile, self.value = model()
            reference = self.value["reference"]
            unit = next(iter(reference["units"].values()))
            if fault in ("guard", "policy"):
                path = (
                    self.request["reference_guard"]["path"]
                    if fault == "guard"
                    else str(
                        Path(self.request["reference_guard"]["path"]).parent
                        / "policy.json"
                    )
                )
                reference["files"][path]["sha256"] = "f" * 64
            elif fault == "argv":
                unit["commands"][0]["argv"][-1] = "999"
            elif fault == "denial":
                unit["directory_membership"].append("99-cmdmesh-retired-prestart.conf")
            else:
                unit["commands"][0]["status"] = False
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.validate()


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"),
    "provide the pinned corrected recipe source",
)
class QuiescedCollectionTests(unittest.TestCase):
    def setUp(self):
        self.request, self.profile, self.value = model()
        (ROOT / ".generated").mkdir(mode=0o700, exist_ok=True)
        tmp = tempfile.TemporaryDirectory(
            prefix="quiesced-runtime-", dir=ROOT / ".generated"
        )
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        policy = self.request["policy"]
        for index, role in enumerate(("data", "config")):
            path = self.root / role
            path.mkdir(mode=0o700)
            policy["datasets"][role]["mountpoint"] = str(path)
            self.value["retained"]["datasets"][role]["properties"]["mountpoint"] = str(
                path
            )
            self.value["retained"]["datasets"][role]["mount"]["target"] = str(path)
            self.profile["config"][
                "mp" + str(index)
            ] = f"{path},mp={runtime.GUEST_BINDS[role]},backup=0"
        self.value["guest"]["config"] = copy.deepcopy(self.profile["config"])
        self.value["retained"]["config"] = copy.deepcopy(self.profile["config"])
        self.config = self.root / "config/application.json"
        raw = runtime.state.canonical(
            {
                "schema_version": 1,
                "instance_id": policy["application"]["instance_id"],
                "uid": 1100,
                "token": "0" * 64,
            }
        )
        self.config.write_bytes(raw)
        self.config.chmod(0o600)
        digest = runtime.state.sha256(raw)
        policy["application"]["config_sha256"] = digest
        self.value["retained"]["application"]["config"]["sha256"] = digest
        self.value["application"]["config_sha256"] = digest
        self.database = self.root / "data/ledger.sqlite3"
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute(runtime.observe.IDENTITY_SQL)
            db.execute(runtime.observe.ENTRIES_SQL)
            db.execute(
                "INSERT INTO identity VALUES (?)",
                (policy["application"]["instance_id"],),
            )
            db.execute(
                "INSERT INTO entries VALUES (1,?,?)",
                ("1" * 32, "meaningful persistent record"),
            )
        self.database.chmod(0o600)
        self.value["retained"]["application"]["database"].update(
            inode=self.database.stat().st_ino, bytes=self.database.stat().st_size
        )
        self.read_database = runtime.observe.read_database
        self.value["application"].update(
            self.read_database(self.database, policy["application"]["instance_id"])
        )
        manifest = str(
            Path(self.request["reference_guard"]["path"]).parent / "policy.json"
        )
        self.value["reference"]["files"][manifest]["sha256"] = runtime.state.sha256(
            runtime.state.canonical(policy)
        )
        locks = self.root / "native-locks"
        locks.mkdir(mode=0o700)
        self.vmids = (policy["vmid"], policy["retired_guest"]["vmid"])
        for vmid in self.vmids:
            (locks / f"pve-config-{vmid}.lock").touch(mode=0o600)
        for patch in (
            mock.patch.object(
                backup, "RUNTIME_ROOT", self.root / "managed/persistence"
            ),
            mock.patch.object(config_lock, "LOCK_ROOT", locks),
            mock.patch.object(config_lock, "ROOT_UID", os.geteuid()),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        with pair.locked_pair(policy["datasets"], initialize=True):
            pass
        self.events = []
        self.seal_database = runtime.seal_database
        guard, _, _ = runtime.load_profile(self.request, self.profile)
        guard.collect = mock.Mock(
            side_effect=AssertionError(
                "strict stopped guard must not collect running data"
            )
        )
        self.locked_config = runtime.observe.locked_config
        self.locked_pair = pair.locked_pair
        self.mocks = {}
        providers = {
            "reference_facts": lambda request: self.provide("reference"),
            "retained_facts": lambda policy, guard: self.provide("retained"),
            "guest_image": lambda request, profile: self.provide("image"),
            "collect_bindings": lambda *args: self.provide("bindings"),
            "reference_files": lambda request: self.provide("reference")["files"],
            "owner_seal": lambda policy, guard: guard.ownership_seal(
                self.provide("retained")["ownership"]
            ),
            "seal_database": self.database_seal,
        }
        for name, callback in providers.items():
            patch = mock.patch.object(runtime, name, side_effect=callback, create=True)
            self.mocks[name] = patch.start()
            self.addCleanup(patch.stop)
        for target, name, callback in (
            (runtime.observe, "load_guard", lambda reference: guard),
            (
                runtime.observe,
                "host_facts",
                lambda request: copy.deepcopy(self.value["host"]),
            ),
            (runtime.observe, "guest_facts", lambda policy: self.provide("guest")),
            (runtime.kernel, "collect", lambda binding: self.provide("kernel")),
            (runtime.kernel.reader.memory, "init_state", lambda pid: (500, 20)),
            (
                runtime.observe,
                "locked_config",
                self.lock_configuration,
            ),
            (runtime.observe, "read_database", self.sql),
            (
                runtime.observe,
                "source_state",
                mock.Mock(
                    side_effect=AssertionError("stopped source state must not run")
                ),
            ),
        ):
            patch = mock.patch.object(target, name, side_effect=callback)
            self.mocks[name] = patch.start()
            self.addCleanup(patch.stop)

    def scopes(self, application=None):
        for vmid in self.vmids:
            with self.assertRaises(config_lock.ConfigLockError):
                config_lock.require_write_available(vmid)
        with self.assertRaises(runtime.state.PersistenceError):
            with self.locked_pair(self.request["policy"]["datasets"]):
                self.fail("pair mutex was not retained")
        if application is not None:
            with self.config.open("rb") as fd:
                if application:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def lock_configuration(self, path, uid, gid):
        self.assertEqual((path, uid, gid), (self.config, 101100, 101100))
        return self.locked_config(path, os.geteuid(), os.getegid())

    def database_seal(self, path, checksum, expected):
        self.scopes(True)
        self.assertEqual(
            (path, expected["uid"], expected["gid"]), (self.database, 101100, 101100)
        )
        actual_owner = {**expected, "uid": os.geteuid(), "gid": os.getegid()}
        return self.seal_database(path, checksum, actual_owner)

    def provide(self, name):
        self.scopes(True if name == "retained" or "sql" in self.events else None)
        self.events.append(name)
        return copy.deepcopy(self.value[name])

    def sql(self, path, instance):
        self.scopes(True)
        self.events.append("sql")
        return self.read_database(path, instance)

    def collect(self):
        return runtime.collect(self.request, self.profile, phase="os_quiesced")

    def released(self):
        for vmid in self.vmids:
            config_lock.require_write_available(vmid)
        with pair.locked_pair(self.request["policy"]["datasets"]):
            pass
        with self.config.open("rb") as fd:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_read_only_collect_holds_real_pair_native_and_application_locks(self):
        before = {
            str(p.relative_to(self.root)): p.read_bytes()
            for p in self.root.rglob("*")
            if p.is_file()
        }
        count = len(list(Path("/proc/self/fd").iterdir()))
        value = self.collect()
        runtime.validate(self.request, self.profile, "os_quiesced", value)
        self.assertEqual(value["application"], self.value["application"])
        self.assertLess(self.events.index("guest"), self.events.index("kernel"))
        self.assertLess(self.events.index("image"), self.events.index("sql"))
        self.assertEqual(count, len(list(Path("/proc/self/fd").iterdir())))
        self.assertEqual(
            before,
            {
                str(p.relative_to(self.root)): p.read_bytes()
                for p in self.root.rglob("*")
                if p.is_file()
            },
        )
        self.released()

    def test_invalid_initial_guest_refuses_before_kernel_guest_or_database(self):
        self.value["guest"]["config"]["tags"] = "foreign-owner"
        with self.assertRaises(ValueError):
            self.collect()
        self.mocks["collect"].assert_not_called()
        self.mocks["guest_image"].assert_not_called()
        self.mocks["locked_config"].assert_not_called()
        self.mocks["read_database"].assert_not_called()
        self.released()

    def test_busy_application_refuses_sql_and_releases_outer_leases(self):
        with self.config.open("rb") as fd:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(ValueError):
                self.collect()
        self.mocks["read_database"].assert_not_called()
        self.mocks["retained_facts"].assert_not_called()
        self.released()

    def test_private_worker_uses_and_preserves_the_callers_real_leases(self):
        guard, _, binding = runtime.load_profile(self.request, self.profile)
        with pair.locked_pair(self.request["policy"]["datasets"]), ExitStack() as held:
            for vmid in self.vmids:
                held.enter_context(config_lock.read_guest(vmid))
            raw = held.enter_context(
                self.locked_config(self.config, os.geteuid(), os.getegid())
            )
            with mock.patch.object(
                pair, "locked_pair", side_effect=AssertionError("recursive pair lock")
            ), mock.patch.object(
                config_lock,
                "read_guest",
                side_effect=AssertionError("recursive native lock"),
            ), mock.patch.object(
                runtime.observe,
                "locked_config",
                side_effect=AssertionError("recursive application lock"),
            ):
                value = runtime._collect_leased(
                    self.request,
                    self.profile,
                    guard,
                    binding,
                    copy.deepcopy(self.value["host"]),
                    raw,
                )
            self.scopes(True)
            self.assertEqual(value["application"], self.value["application"])
            runtime.validate(self.request, self.profile, "os_quiesced", value)
        self.released()

    def test_private_worker_wrong_configuration_refuses_before_any_sql(self):
        guard, _, binding = runtime.load_profile(self.request, self.profile)
        with pair.locked_pair(self.request["policy"]["datasets"]), ExitStack() as held:
            for vmid in self.vmids:
                held.enter_context(config_lock.read_guest(vmid))
            held.enter_context(
                self.locked_config(self.config, os.geteuid(), os.getegid())
            )
            with self.assertRaisesRegex(ValueError, "configuration-changed"):
                runtime._collect_leased(
                    self.request,
                    self.profile,
                    guard,
                    binding,
                    copy.deepcopy(self.value["host"]),
                    b"wrong application bytes",
                )
            self.scopes(True)
        self.mocks["read_database"].assert_not_called()
        self.released()

    def test_public_collector_closes_configuration_after_the_worker_returns(self):
        def inspect(*args):
            self.scopes(True)
            self.config.write_bytes(b"late unmanaged configuration change")
            return copy.deepcopy(self.value)

        with mock.patch.object(runtime, "_collect_leased", side_effect=inspect):
            with self.assertRaisesRegex(ValueError, "configuration-changed"):
                self.collect()
        self.released()

    def test_late_reference_change_refuses_and_releases_all_locks(self):
        calls = 0

        def reference(request):
            nonlocal calls
            calls += 1
            value = self.provide("reference")
            if calls > 1:
                next(iter(value["files"].values()))["sha256"] = "f" * 64
            return value

        self.mocks["reference_facts"].side_effect = reference
        with self.assertRaises(ValueError):
            self.collect()
        self.released()

    def test_database_change_during_last_guest_probe_refuses(self):
        def image(*args):
            result = self.provide("image")
            if "sql" in self.events:
                with closing(sqlite3.connect(self.database)) as db, db:
                    db.execute(
                        "INSERT INTO entries VALUES (2,?,?)",
                        ("2" * 32, "late unmanaged write"),
                    )
            return result

        self.mocks["guest_image"].side_effect = image
        with self.assertRaises(ValueError):
            self.collect()
        self.released()

    def test_nondecreasing_uptime_is_allowed_without_weakening_identity(self):
        def guest(policy):
            value = self.provide("guest")
            value["runtime"]["uptime"] += self.events.count("guest")
            return value

        self.mocks["guest_facts"].side_effect = guest
        value = self.collect()
        self.assertGreater(value["guest"]["runtime"]["uptime"], 30)
        self.released()

    def test_owner_or_reference_changed_during_last_sql_read_refuses(self):
        original = copy.deepcopy(self.value)
        for fault in ("owner", "reference"):
            self.value = copy.deepcopy(original)
            self.events.clear()
            calls = 0

            def sql(path, instance):
                nonlocal calls
                calls += 1
                result = self.sql(path, instance)
                if calls == 2:
                    if fault == "owner":
                        self.value["retained"]["ownership"]["document"]["active"][
                            "vmid"
                        ] += 1
                    else:
                        next(iter(self.value["reference"]["files"].values()))[
                            "sha256"
                        ] = ("f" * 64)
                return result

            self.mocks["read_database"].side_effect = sql
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.collect()
            self.released()

    def test_init_died_during_last_sql_read_cannot_report_running(self):
        self.mocks["init_state"].side_effect = lambda pid: (501, 20)
        with self.assertRaises(ValueError):
            self.collect()
        self.released()

    def test_image_or_kernel_changed_during_final_sql_is_not_accepted(self):
        original = copy.deepcopy(self.value)
        for fault in ("image", "kernel"):
            self.value = copy.deepcopy(original)
            self.events.clear()
            calls = 0

            def sql(path, instance):
                nonlocal calls
                calls += 1
                result = self.sql(path, instance)
                if calls == 2:
                    if fault == "image":
                        self.value["image"]["unit"]["MainPID"] = "900"
                        self.value["image"]["accounts"]["uid_processes"] = [900]
                    else:
                        self.value["kernel"]["rootfs"]["identity"][1] += 1
                return result

            self.mocks["read_database"].side_effect = sql
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.collect()
            self.released()


@unittest.skipUnless(
    os.environ.get("CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"),
    "provide the pinned corrected recipe source",
)
class GuestImageProgramTests(unittest.TestCase):
    def run_program(self, *, fault=None, source=None):
        request, profile, value = model()
        frame = value["image"]
        program_raw = (
            Path(os.environ["CMDMESH_FIXED_HANDOFF_GUARD_SOURCE"]).parent / "ledger.py"
        ).read_bytes()
        reads = {"program": 0, "unit": 0}
        executed = []

        def load(program, namespace):
            executed.append(True)
            builtins.exec(program, namespace)
            unit_raw = namespace["service_unit"]()

            def regular(name, limit=1048576):
                raw = program_raw if name.endswith("ledger.py") else unit_raw
                if name.endswith("ledger.py"):
                    reads["program"] += 1
                    if fault == "artifact" and reads["program"] == 2:
                        raw += b"# changed during final probe\n"
                identity = list(frame["artifacts"][name]["identity"])
                identity[6] = len(raw)
                return raw, tuple(identity)

            fields = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_uid",
                "st_gid",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )

            def unit():
                reads["unit"] += 1
                return copy.deepcopy(frame["unit"])

            def accounts():
                value = copy.deepcopy(frame["accounts"])
                if fault == "process" and reads["unit"] >= 2:
                    value["uid_processes"] = [900]
                return value

            namespace.update(
                environment=lambda: copy.deepcopy(frame["environment"]),
                unit=unit,
                read_as_application=lambda: copy.deepcopy(frame["application_read"]),
                accounts=accounts,
                account_files=lambda: copy.deepcopy(frame["accounts"]["files"]),
                regular=regular,
                directory=lambda *args: None,
                path=lambda name: SimpleNamespace(
                    lstat=lambda: SimpleNamespace(
                        **dict(zip(fields, frame["directories"][name]))
                    )
                ),
            )

        original_stat = os.stat
        output = io.StringIO()
        with mock.patch.object(
            os,
            "stat",
            side_effect=lambda path, *args, **kwargs: (
                SimpleNamespace(st_dev=os.makedev(7, 2))
                if str(path) == "/"
                else original_stat(path, *args, **kwargs)
            ),
        ), mock.patch.object(os, "sched_getaffinity", return_value={0}), mock.patch(
            "socket.gethostname", return_value=profile["config"]["hostname"]
        ), mock.patch.object(
            sys,
            "argv",
            ["guest-probe", profile["image_python"] if source is None else source],
        ), mock.patch(
            "subprocess.run",
            side_effect=AssertionError(
                "modeled guest must not execute native commands"
            ),
        ), redirect_stdout(
            output
        ):
            builtins.exec(
                compile(runtime.GUEST_IMAGE, "<actual-guest-image-program>", "exec"),
                {"__builtins__": {**vars(builtins), "exec": load}},
            )
        return json.loads(output.getvalue()), profile, value["kernel"], executed

    def test_actual_guest_program_produces_the_validated_frame_from_known_helpers(self):
        frame, profile, kernel, executed = self.run_program()
        _, image, _ = runtime.load_profile(model()[0], profile)
        runtime.validate_image(profile, image, frame, kernel)
        self.assertEqual(len(executed), 1)

    def test_actual_guest_program_refuses_unapproved_code_and_late_artifact_change(
        self,
    ):
        for fault in ("source", "artifact", "process"):
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.run_program(
                    source=(
                        "raise RuntimeError('unapproved code')"
                        if fault == "source"
                        else None
                    ),
                    fault=fault,
                )
