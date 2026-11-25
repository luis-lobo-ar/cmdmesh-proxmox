"""Deny both managed starts, then generate one stopped blank guest's config.

This finite prerequisite never installs an allowing guard, starts a guest,
attaches retained mounts, initializes application data or certifies a rebuild.
"""

import os
from pathlib import Path
import re
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_backup as backup,
    persistence_blank_guard as guard,
    persistence_observe as observe,
    persistence_recipient as recipient,
    persistence_state as state,
)

ROOT_UID = 0
UNIT_ROOT = Path("/etc/systemd/system")
LXC_ROOT = Path("/var/lib/lxc")
RUNTIME_ROOT = Path("/var/lib/cmdmesh/reference-blank-stage")
PREPARED = "cmdmesh.proxmox.persistence.prepared-blank-stage"
PROFILE = {
    "document_type": "cmdmesh.proxmox.persistence.blank-stage-runtime",
    "schema_version": 1,
}
DENY = b"[Service]\nExecStartPre=/usr/bin/false\n"


def require(value, code):
    state.require(value, "persistence-blank-stage-" + code)


def unit_names(request):
    vmid = str(request["target"]["vmid"])
    return (
        "pve-container@" + vmid + ".service",
        "pve-container-debug@" + vmid + ".service",
    )


def dropin_path(request, unit):
    require(unit in unit_names(request), "unit-selector")
    return UNIT_ROOT / (unit + ".d") / "40-cmdmesh-blank-deny.conf"


def unit_facts(request):
    result = {}
    for unit in unit_names(request):
        raw = observe.native(
            [
                "/usr/bin/systemctl",
                "show",
                unit,
                "-p",
                "LoadState,ActiveState,MainPID,DropInPaths,ExecStartPre",
            ]
        ).decode()
        fields = {}
        for line in raw.splitlines():
            key, separator, value = line.partition("=")
            require(separator == "=" and key not in fields, "unit-observation")
            fields[key] = value
        fields.setdefault("ExecStartPre", "")
        state.keys(
            fields,
            {"LoadState", "ActiveState", "MainPID", "DropInPaths", "ExecStartPre"},
        )
        require(
            fields["LoadState"] == "loaded"
            and fields["ActiveState"] == "inactive"
            and fields["MainPID"] == "0",
            "unit-not-inactive",
        )
        result[unit] = fields
    return result


def validate_target(request, target):
    state.keys(target, {"vmid", "config", "pending", "status", "rootfs"})
    require(
        type(target["vmid"]) is int and target["vmid"] == request["target"]["vmid"],
        "target",
    )
    volume = recipient.validate_target_config(request, target["config"])
    require(
        state.canonical(target["pending"])
        == state.canonical(recipient.ordered_pending(target["pending"])),
        "pending",
    )
    current = target["status"]
    require(
        type(current) is dict
        and current.get("status") == "stopped"
        and type(current.get("uptime")) is int
        and current["uptime"] == 0
        and type(current.get("pid", 0)) is int
        and current.get("pid", 0) == 0,
        "not-stopped",
    )
    image = target["rootfs"]
    state.keys(image, {"volume", "path", "identity", "uuid"})
    require(
        image["volume"] == volume
        and type(image["identity"]) is list
        and len(image["identity"]) == 9
        and all(type(part) is int and part >= 0 for part in image["identity"]),
        "rootfs-proof",
    )
    guard.validate_root(
        {
            "path": image["path"],
            "identity": image["identity"][:7],
            "uuid": image["uuid"],
        },
        target["vmid"],
    )
    require(
        image["uuid"] != request["source_request"]["policy"]["rootfs"]["uuid"],
        "old-rootfs",
    )


def pristine(request):
    require(UNIT_ROOT.resolve(strict=True) == UNIT_ROOT, "unit-root")
    info = UNIT_ROOT.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == ROOT_UID
        and not info.st_mode & 0o022,
        "unit-root",
    )
    for unit in unit_names(request):
        require(
            not os.path.lexists(dropin_path(request, unit).parent),
            "existing-unit-directory",
        )
    require(
        not os.path.lexists(LXC_ROOT / str(request["target"]["vmid"]) / "config"),
        "existing-generated-config",
    )
    units = unit_facts(request)
    require(
        all(
            not value["DropInPaths"] and not value["ExecStartPre"]
            for value in units.values()
        ),
        "existing-unit-overrides",
    )
    return units


def prepare(recipient_raw, recipient_sha256):
    frozen = recipient.load_prepared(recipient_raw, recipient_sha256)
    result = recipient.status(recipient_raw, recipient_sha256)
    require(
        result["provisioned_verified"] is True
        and result["rebuild_verified"] is False
        and result["restore_verified"] is False,
        "recipient-unqualified",
    )
    validate_target(frozen["request"], result["target"])
    units = pristine(frozen["request"])
    closing = recipient.status(recipient_raw, recipient_sha256)
    require(
        state.canonical(result) == state.canonical(closing)
        and state.canonical(pristine(frozen["request"])) == state.canonical(units),
        "recipient-changed",
    )
    return {
        "document_type": PREPARED,
        "schema_version": 1,
        "profile_version": 1,
        "recipient_prepared": frozen,
        "recipient_sha256": recipient_sha256,
        "target": result["target"],
        "units": units,
    }


def load_prepared(raw, trusted):
    state.digest(trusted)
    require(
        type(raw) is bytes and 0 < len(raw) <= 1048576 and state.sha256(raw) == trusted,
        "prepared-changed",
    )
    value = observe.decode(raw)
    state.keys(
        value,
        {
            "document_type",
            "schema_version",
            "profile_version",
            "recipient_prepared",
            "recipient_sha256",
            "target",
            "units",
        },
    )
    require(
        raw == state.canonical(value)
        and value["document_type"] == PREPARED
        and all(
            type(value[key]) is int and value[key] == 1
            for key in ("schema_version", "profile_version")
        ),
        "prepared-version",
    )
    frozen = recipient.load_prepared(
        state.canonical(value["recipient_prepared"]), value["recipient_sha256"]
    )
    validate_target(frozen["request"], value["target"])
    units = value["units"]
    require(
        type(units) is dict and set(units) == set(unit_names(frozen["request"])),
        "prepared-unit-proof",
    )
    for fields in units.values():
        require(
            fields
            == {
                "LoadState": "loaded",
                "ActiveState": "inactive",
                "MainPID": "0",
                "DropInPaths": "",
                "ExecStartPre": "",
            },
            "prepared-unit-proof",
        )
    return value


def claim_path(prepared):
    request = prepared["recipient_prepared"]["request"]
    key = [
        request["source_request"]["source"]["host_profile"]["machine_id_sha256"],
        request["target"]["vmid"],
    ]
    return RUNTIME_ROOT / state.sha256(state.canonical(key))


def claim(prepared, trusted):
    backup.private_directory(RUNTIME_ROOT.parent)
    try:
        RUNTIME_ROOT.mkdir(mode=0o700)
    except FileExistsError:
        backup.private_directory(RUNTIME_ROOT)
        profile, _ = backup.read_private(RUNTIME_ROOT / "profile.json")
        require(profile == PROFILE, "runtime-profile")
    else:
        backup.write_private(RUNTIME_ROOT / "profile.json", PROFILE)
        backup.sync_directory(RUNTIME_ROOT.parent)
    directory = claim_path(prepared)
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        raise state.PersistenceError(
            "persistence-blank-stage-target-consumed"
        ) from None
    backup.sync_directory(RUNTIME_ROOT)
    backup.write_private(
        directory / "intent.json", {"prepared": prepared, "prepared_sha256": trusted}
    )
    backup.write_private(
        directory / "write-possible.json", {"target": prepared["target"]["vmid"]}
    )
    return directory


def write_deny(request):
    for unit in unit_names(request):
        path = dropin_path(request, unit)
        path.parent.mkdir(mode=0o700)
        backup.sync_directory(UNIT_ROOT)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(DENY)
            stream.flush()
            os.fsync(stream.fileno())
        backup.sync_directory(path.parent)


def denied(request):
    for unit in unit_names(request):
        path = dropin_path(request, unit)
        require(
            path.parent.resolve(strict=True) == path.parent
            and set(p.name for p in path.parent.iterdir()) == {path.name},
            "deny-membership",
        )
        info = path.lstat()
        require(
            path.resolve(strict=True) == path
            and stat.S_ISREG(info.st_mode)
            and info.st_uid == ROOT_UID
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and path.read_bytes() == DENY,
            "deny-file",
        )
    units = unit_facts(request)
    for unit, value in units.items():
        require(
            value["DropInPaths"] == str(dropin_path(request, unit))
            and re.fullmatch(
                r"\{ path=/usr/bin/false ; argv\[\]=/usr/bin/false ; ignore_errors=no ; start_time=\[[^\]\r\n]*\] ; stop_time=\[[^\]\r\n]*\] ; pid=0 ; code=\(null\) ; status=0/0 \}",
                value["ExecStartPre"],
            )
            is not None,
            "deny-unit",
        )
    return units


def reload_units():
    observe.native(["/usr/bin/systemctl", "daemon-reload"])


def native_generation(request, digest):
    node, vmid = (
        request["source_request"]["source"]["selector"]["node"],
        request["target"]["vmid"],
    )
    require(state.matches(r"[a-f0-9]{40}", digest), "config-digest")
    argv = [
        "/usr/bin/pvesh",
        "set",
        f"/nodes/{node}/lxc/{vmid}/config",
        "--digest",
        digest,
        "--cores",
        "1",
        "--cpulimit",
        "1",
    ]
    out = observe.native(argv)
    return {"exit_code": 0, "stdout_sha256": state.sha256(out)}


def generated(request):
    vmid = request["target"]["vmid"]
    path = LXC_ROOT / str(vmid) / "config"
    raw, info = observe.read_regular(path, 65536)
    require(
        info.st_uid == ROOT_UID and info.st_nlink == 1 and not info.st_mode & 0o022,
        "generated-file",
    )
    checksum, selection = guard.generated_fingerprint(raw)
    lines = raw.splitlines()
    for line in (
        f"lxc.rootfs.path = /var/lib/lxc/{vmid}/rootfs".encode(),
        ("lxc.uts.name = " + request["target"]["hostname"]).encode(),
        b"lxc.idmap = u 0 100000 65536",
        b"lxc.idmap = g 0 100000 65536",
    ):
        require(lines.count(line) == 1, "generated-identity")
    require(
        not any(line.startswith((b"lxc.net.", b"lxc.mount.entry =")) for line in lines),
        "generated-extra-access",
    )
    return {
        "path": str(path),
        "text": raw.decode("utf-8"),
        "sha256": state.sha256(raw),
        "stable_sha256": checksum,
        "identity": list(observe.stable(info)),
        "cpu_selection": selection,
    }


def verify(prepared, expected_generated):
    frozen = prepared["recipient_prepared"]
    request = frozen["request"]
    target = recipient.verify_target(request, frozen)
    validate_target(request, target)
    require(
        state.canonical(target) == state.canonical(prepared["target"]), "target-changed"
    )
    units = denied(request)
    output = generated(request)
    require(
        state.canonical(output) == state.canonical(expected_generated),
        "generated-changed",
    )
    require(
        state.canonical(recipient.verify_target(request, frozen))
        == state.canonical(target)
        and state.canonical(denied(request)) == state.canonical(units)
        and state.canonical(generated(request)) == state.canonical(output),
        "closing-state-changed",
    )
    return {
        "phase": "blank-generation-denied",
        "target": target,
        "units": units,
        "generated": output,
        "denied_generation_verified": True,
        "boot_verified": False,
        "rebuild_verified": False,
        "restore_verified": False,
    }


def check_source(prepared, facts):
    frozen = prepared["recipient_prepared"]
    require(
        state.canonical(
            recipient.collect_preflight(frozen["request"], facts, exclude_target=True)
        )
        == state.canonical(frozen["preflight"]),
        "source-changed",
    )


def apply(raw, trusted):
    prepared = load_prepared(raw, trusted)
    request = prepared["recipient_prepared"]["request"]
    require(os.geteuid() == ROOT_UID, "root-required")
    require(not os.path.lexists(claim_path(prepared)), "target-consumed")
    require(
        state.canonical(
            prepare(
                state.canonical(prepared["recipient_prepared"]),
                prepared["recipient_sha256"],
            )
        )
        == raw,
        "preflight-changed",
    )
    directory = None
    try:
        with observe.source_state(
            request["source_request"], require_stopped=True
        ) as facts:
            check_source(prepared, facts)
            require(
                state.canonical(
                    recipient.verify_target(request, prepared["recipient_prepared"])
                )
                == state.canonical(prepared["target"]),
                "target-changed",
            )
            require(
                state.canonical(pristine(request))
                == state.canonical(prepared["units"]),
                "units-changed",
            )
            directory = claim(prepared, trusted)
            write_deny(request)
            reload_units()
            denied(request)
            validate_target(
                request,
                recipient.verify_target(request, prepared["recipient_prepared"]),
            )
            command = native_generation(request, prepared["target"]["config"]["digest"])
            state.keys(command, {"exit_code", "stdout_sha256"})
            require(
                type(command["exit_code"]) is int and command["exit_code"] == 0,
                "generation-command",
            )
            state.digest(command["stdout_sha256"])
            backup.write_private(directory / "generation-command.json", command)
            output = generated(request)
            backup.write_private(directory / "generated.json", output)
            result = verify(prepared, output)
        require(
            state.canonical(verify(prepared, output)) == state.canonical(result),
            "final-state-changed",
        )
        complete = {"prepared_sha256": trusted, **result}
        checksum = backup.write_private(directory / "complete.json", complete)
        return {**complete, "completion_sha256": checksum}
    except BaseException as error:
        if directory is not None:
            try:
                backup.write_private(
                    directory / "failed.json",
                    {
                        "error_code": getattr(
                            error, "code", "persistence-blank-stage-interrupted"
                        )
                    },
                )
            except OSError:
                pass
        raise


def status(raw, trusted):
    prepared = load_prepared(raw, trusted)
    directory = claim_path(prepared)
    backup.private_directory(directory)
    intent, _ = backup.read_private(directory / "intent.json")
    require(
        state.canonical(intent)
        == state.canonical({"prepared": prepared, "prepared_sha256": trusted}),
        "retained-intent",
    )
    request = prepared["recipient_prepared"]["request"]
    command, _ = backup.read_private(directory / "generation-command.json")
    state.keys(command, {"exit_code", "stdout_sha256"})
    require(
        type(command["exit_code"]) is int and command["exit_code"] == 0,
        "generation-command",
    )
    state.digest(command["stdout_sha256"])
    output, _ = backup.read_private(directory / "generated.json")
    with observe.source_state(request["source_request"], require_stopped=True) as facts:
        check_source(prepared, facts)
        result = verify(prepared, output)
    require(
        state.canonical(verify(prepared, output)) == state.canonical(result),
        "final-state-changed",
    )
    return result
