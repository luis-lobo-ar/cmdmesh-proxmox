"""Prepare a separately claimed application test after qualified retained boot.

Preparation is read-only and uses the OS-start status only while the original
application tuple is unchanged. It does not create a claim or start a writer.
"""

from contextlib import contextmanager, ExitStack
import copy
import os
from pathlib import Path

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_backup as backup,
    persistence_retained_boot as boot,
    persistence_retained_runtime as runtime,
    persistence_state as state,
)

RUNTIME_ROOT = Path("/var/lib/cmdmesh/reference-ledger-trial")
PREPARED = "cmdmesh.proxmox.persistence.application-trial-prepared"
PROFILE = {
    "document_type": "cmdmesh.proxmox.persistence.application-trial-runtime",
    "schema_version": 1,
}
BOOT_JOURNAL = frozenset(
    {
        "intent.json",
        "write-possible.json",
        "guard-dispatch.json",
        "guard-result.json",
        "target-0-dispatch.json",
        "target-0-result.json",
        "target-1-dispatch.json",
        "target-1-result.json",
        "target-denial-0.conf",
        "target-denial-1.conf",
        "dispatch.json",
        "acknowledgement.json",
        "task.json",
    }
)


def require(value, code):
    state.require(value, "persistence-writer-trial-" + code)


def claim_path(request):
    return RUNTIME_ROOT / state.pair_key(request["policy"]["datasets"])


def unused(request):
    require(runtime.observe.absolute(str(RUNTIME_ROOT)), "runtime-path")
    for item in request["policy"]["datasets"].values():
        mount = Path(item["mountpoint"])
        require(
            RUNTIME_ROOT != mount and mount not in RUNTIME_ROOT.parents,
            "runtime-inside-retained-state",
        )
    backup.private_directory(RUNTIME_ROOT.parent)
    if os.path.lexists(RUNTIME_ROOT):
        backup.private_directory(RUNTIME_ROOT)
        require(
            backup.read_private(RUNTIME_ROOT / "profile.json")[1]
            == state.canonical(PROFILE),
            "runtime-profile",
        )
    require(not os.path.lexists(claim_path(request)), "pair-consumed")


def payload(nonce):
    require(state.matches(r"[a-f0-9]{32}", nonce), "nonce")
    return "CmdMesh retained-write proof " + nonce


@contextmanager
def _quiesced(request, profile, guard, binding, host):
    policy = request["policy"]
    path = Path(policy["datasets"]["config"]["mountpoint"]) / "application.json"
    uid, gid = (
        policy["mapping"]["offset"] + policy["mapping"][name] for name in ("uid", "gid")
    )
    with runtime.observe.locked_config(path, uid, gid) as raw:
        before = runtime._collect_leased(request, profile, guard, binding, host, raw)
        yield before
        after = runtime._collect_leased(request, profile, guard, binding, host, raw)
        require(
            state.canonical(boot._runtime_identity(before))
            == state.canonical(boot._runtime_identity(after))
            and after["guest"]["runtime"]["uptime"]
            >= before["guest"]["runtime"]["uptime"],
            "quiesced-context-changed",
        )


def _history(parent, completion_sha256, journal):
    """Read immutable raw history, never a stopped source or current OS status."""
    boot.close_retained_history(parent)
    history = copy.deepcopy(boot.after_denials(parent)[1])
    directory = boot.claim_path(parent["source_request"])
    current = boot._history_directory(directory)
    require(
        set(current["files"]) == {*journal, "complete.json"}
        and state.canonical(
            {
                name: item
                for name, item in current["files"].items()
                if name != "complete.json"
            }
        )
        == state.canonical(journal)
        and current["files"]["complete.json"]["sha256"] == completion_sha256,
        "boot-history-changed",
    )
    history["directories"][str(directory)] = current
    own = boot.own_runtime()
    history["files"][str(boot.RUNTIME_ROOT / "profile.json")] = own["file"]
    boot.close_history(history)
    boot.close_own_runtime(own)
    return history, own


def prepare(boot_raw, boot_sha256, boot_completion_sha256, nonce):
    payload(nonce)
    state.digest(boot_completion_sha256)
    parent = boot.decode_prepared(boot_raw, boot_sha256)
    request, profile = copy.deepcopy(parent["source_request"]), copy.deepcopy(
        parent["image_profile"]
    )
    guard, unused_image, binding = runtime.load_profile(request, profile)
    unused(request)
    # Status acquires its own pair/native/application scopes. It must finish
    # before this operation takes those leases or starts an application actor.
    accepted = boot.status(boot_raw, boot_sha256)
    require(
        accepted["prepared_sha256"] == boot_sha256
        and accepted["completion_sha256"] == boot_completion_sha256
        and accepted["phase"] == "retained-os-quiesced"
        and accepted["boot_verified"] is True
        and accepted["application_quiesced"] is True
        and accepted["mutation_attempted"] is False
        and all(
            accepted[key] is False
            for key in ("rebuild_verified", "restore_verified", "backup_verified")
        ),
        "boot-unqualified",
    )
    old_identity = boot._runtime_identity(accepted["runtime"])
    host = accepted["runtime"]["host"]
    guard = runtime.observe.load_guard(request["reference_guard"])
    policy = request["policy"]
    with runtime.pair_lock.locked_pair(policy["datasets"]), ExitStack() as held:
        for vmid in sorted((policy["vmid"], policy["retired_guest"]["vmid"])):
            held.enter_context(runtime.config_lock.read_guest(vmid))
        unused(request)
        history, own = _history(
            parent, boot_completion_sha256, accepted["journal_files"]
        )
        completed, completed_raw = backup.read_private(
            boot.claim_path(request) / "complete.json"
        )
        require(
            state.sha256(completed_raw) == boot_completion_sha256,
            "boot-completion-changed",
        )
        # This immutable floor avoids embedding ever-changing uptime in prepared
        # equality. Fresh observations still require chronological monotonicity.
        floor = completed["runtime"]["guest"]["runtime"]["uptime"]
        state.integer(floor, 0, 2**63 - 1)
        with _quiesced(request, profile, guard, binding, host) as observed:
            require(
                state.canonical(boot._runtime_identity(observed))
                == state.canonical(old_identity)
                and observed["guest"]["runtime"]["uptime"]
                >= accepted["runtime"]["guest"]["runtime"]["uptime"]
                >= floor,
                "quiesced-state-changed",
            )
            require(
                _history(parent, boot_completion_sha256, accepted["journal_files"])
                == (history, own),
                "history-changed",
            )
            unused(request)
            boot.close_history(history)
            boot.close_own_runtime(own)
        boot.close_history(history)
        boot.close_own_runtime(own)
    return {
        "document_type": PREPARED,
        "schema_version": 1,
        "boot_prepared": parent,
        "boot_prepared_sha256": boot_sha256,
        "boot_completion_sha256": boot_completion_sha256,
        "boot_completion": completed,
        "source_request": request,
        "image_profile": profile,
        "runtime_identity": old_identity,
        "uptime_floor": floor,
        "history": history,
        "boot_runtime": own,
        "nonce": nonce,
    }


def _history_shape(history):
    state.keys(history, {"directories", "files"})
    require(
        type(history["directories"]) is dict and type(history["files"]) is dict,
        "history-shape",
    )
    files = dict(history["files"])
    for path, directory in history["directories"].items():
        state.keys(directory, {"identity", "files"})
        require(
            runtime.observe.absolute(path) and type(directory["files"]) is dict,
            "history-shape",
        )
        require(
            type(directory["identity"]) is list
            and len(directory["identity"]) == 9
            and all(
                type(value) is int and value >= 0 for value in directory["identity"]
            ),
            "history-identity",
        )
        for name, item in directory["files"].items():
            require(state.matches(r"[a-z0-9][a-z0-9_.-]{0,127}", name), "history-name")
            files[str(Path(path) / name)] = item
    for path, item in files.items():
        state.keys(item, {"path", "sha256", "identity"})
        require(
            runtime.observe.absolute(path)
            and item["path"] == path
            and type(item["identity"]) is list
            and len(item["identity"]) == 9
            and all(type(value) is int and value >= 0 for value in item["identity"]),
            "history-identity",
        )
        state.digest(item["sha256"])


def decode_prepared(raw, trusted):
    """Pure prepared loader; current execution admission is a separate step."""
    state.digest(trusted)
    require(
        type(raw) is bytes
        and 0 < len(raw) <= 16777216
        and state.sha256(raw) == trusted,
        "prepared-changed",
    )
    value = runtime.observe.decode(raw)
    state.keys(
        value,
        {
            "document_type",
            "schema_version",
            "boot_prepared",
            "boot_prepared_sha256",
            "boot_completion_sha256",
            "boot_completion",
            "source_request",
            "image_profile",
            "runtime_identity",
            "uptime_floor",
            "history",
            "boot_runtime",
            "nonce",
        },
    )
    require(
        raw == state.canonical(value)
        and value["document_type"] == PREPARED
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1,
        "prepared-version",
    )
    parent = boot.decode_prepared(
        state.canonical(value["boot_prepared"]), value["boot_prepared_sha256"]
    )
    state.digest(value["boot_completion_sha256"])
    require(
        state.canonical(value["source_request"])
        == state.canonical(parent["source_request"])
        and state.canonical(value["image_profile"])
        == state.canonical(parent["image_profile"]),
        "prepared-parent",
    )
    payload(value["nonce"])
    state.integer(value["uptime_floor"], 0, 2**63 - 1)
    reconstructed = copy.deepcopy(value["runtime_identity"])
    require("uptime" not in reconstructed["guest"]["runtime"], "prepared-uptime")
    reconstructed["guest"]["runtime"]["uptime"] = value["uptime_floor"]
    runtime.validate(
        value["source_request"], value["image_profile"], "os_quiesced", reconstructed
    )
    _history_shape(value["history"])
    state.keys(value["boot_runtime"], {"directory", "file"})
    require(
        type(value["boot_runtime"]["directory"]) is list
        and len(value["boot_runtime"]["directory"]) == 5
        and all(
            type(part) is int and part >= 0
            for part in value["boot_runtime"]["directory"]
        ),
        "boot-runtime-identity",
    )
    _history_shape(
        {
            "directories": {},
            "files": {
                value["boot_runtime"]["file"]["path"]: value["boot_runtime"]["file"]
            },
        }
    )
    history = value["history"]
    expected = boot.after_denials(parent)[1]
    directory = str(boot.claim_path(value["source_request"]))
    profile = str(boot.RUNTIME_ROOT / "profile.json")
    require(
        set(history["files"]) == {*expected["files"], profile}
        and set(history["directories"]) == {*expected["directories"], directory},
        "history-membership",
    )
    require(
        state.canonical({key: history["files"][key] for key in expected["files"]})
        == state.canonical(expected["files"])
        and state.canonical(
            {key: history["directories"][key] for key in expected["directories"]}
        )
        == state.canonical(expected["directories"]),
        "parent-history",
    )
    require(
        state.canonical(history["files"][profile])
        == state.canonical(value["boot_runtime"]["file"])
        and history["files"][profile]["path"] == profile
        and history["files"][profile]["sha256"]
        == state.sha256(state.canonical(boot.PROFILE)),
        "boot-profile",
    )
    records = history["directories"][directory]["files"]
    require(
        set(records) == BOOT_JOURNAL | {"complete.json"}
        and records["complete.json"]["sha256"] == value["boot_completion_sha256"],
        "boot-history-membership",
    )
    completed = value["boot_completion"]
    require(
        state.sha256(state.canonical(completed)) == value["boot_completion_sha256"]
        and completed["prepared_sha256"] == value["boot_prepared_sha256"]
        and completed["phase"] == "retained-os-quiesced"
        and completed["boot_verified"] is True
        and completed["application_quiesced"] is True
        and completed["mutation_attempted"] is True
        and all(
            completed[key] is False
            for key in ("rebuild_verified", "restore_verified", "backup_verified")
        ),
        "boot-completion",
    )
    runtime.validate(
        value["source_request"],
        value["image_profile"],
        "os_quiesced",
        completed["runtime"],
    )
    require(
        state.canonical(completed["journal_files"])
        == state.canonical({name: records[name] for name in BOOT_JOURNAL})
        and state.canonical(boot._runtime_identity(completed["runtime"]))
        == state.canonical(value["runtime_identity"])
        and value["uptime_floor"] == completed["runtime"]["guest"]["runtime"]["uptime"]
        and state.canonical(value["runtime_identity"]["application"])
        == state.canonical(parent["source_before"]["application"]),
        "boot-runtime-parent",
    )
    return value
