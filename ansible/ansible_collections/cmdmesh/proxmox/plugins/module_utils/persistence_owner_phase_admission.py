"""Pure portable-current and leased-entry joins; no observation or admission IO.

Checkpoint and stopped prior-runtime authority must be externally selected.
Typed LXC/cgroup/prior-init claims do not authenticate their observation. A
source-authenticated executor must obtain and close them under real leases.
"""

from pathlib import Path
import stat

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_current as current,
)

runtime, state, observe = current.runtime, current.state, current.observe
MAX_BYTES = 33554432
MAX_NODES = 200000
MAX_DEPTH = 64


def require(value, code):
    state.require(value, "persistence-owner-phase-admission-" + code)


def same(left, right, code):
    require(state.canonical(left) == state.canonical(right), code)


def _json(value):
    """Bound exact JSON objects before snapshotting, without type normalization."""
    count = 0
    encoded = 0
    active = set()

    def charge(size):
        nonlocal encoded
        encoded += size
        require(encoded <= MAX_BYTES, "input-limit")

    def visit(item, depth):
        nonlocal count
        count += 1
        require(count <= MAX_NODES and depth <= MAX_DEPTH, "input-limit")
        kind = type(item)
        require(kind in (dict, list, str, int, bool, type(None)), "input-type")
        if kind is str:
            require(len(item) <= MAX_BYTES, "input-limit")
            # Match canonical's ensure_ascii encoding without constructing its
            # expanded string. Aliased/repeated values are charged each time.
            charge(
                2
                + sum(
                    (
                        2
                        if char in '"\\\b\f\n\r\t'
                        else (
                            6
                            if ord(char) < 32 or 126 < ord(char) <= 65535
                            else 12 if ord(char) > 65535 else 1
                        )
                    )
                    for char in item
                )
            )
        elif kind in (dict, list):
            require(id(item) not in active, "input-cycle")
            active.add(id(item))
            charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            if kind is dict:
                require(all(type(key) is str for key in item), "input-key")
                for key, part in item.items():
                    visit(key, depth + 1)
                    visit(part, depth + 1)
            else:
                for part in item:
                    visit(part, depth + 1)
            active.remove(id(item))
        elif kind is bool:
            charge(4 if item else 5)
        elif kind is int:
            charge(len(str(item)))
        else:
            charge(4)

    visit(value, 0)


def _cgroup(value):
    require(type(value) is dict, "cgroup")
    kind = value.get("state")
    require(type(kind) is str and kind in {"absent", "empty"}, "cgroup-state")
    state.keys(value, {"state", "mount"} | ({"identity"} if kind == "empty" else set()))
    mount = value["mount"]
    state.keys(mount, {"target", "fstype"})
    require(
        mount["fstype"] == "cgroup2" and observe.absolute(mount["target"]),
        "cgroup-mount",
    )
    target, parent = Path(mount["target"]), current.CGROUP_ROOT.parent
    require(target == parent or target in parent.parents, "cgroup-mount")
    if kind == "empty":
        identity = value["identity"]
        require(
            type(identity) is list
            and len(identity) == 5
            and all(type(part) is int and part >= 0 for part in identity)
            and identity[1] > 0
            and stat.S_ISDIR(identity[2])
            and not identity[2] & 0o022
            and identity[3] == current.ROOT_UID,
            "cgroup-identity",
        )


def _validate(checkpoint, phase, evidence, entry, prior):
    require(type(phase) is str and phase in {"os_quiesced", "stopped"}, "phase")
    current.validate_current(checkpoint, phase, evidence)
    if phase == "stopped":
        require(prior is not None, "prior-required")
    if prior is not None:
        current.validate_current(
            checkpoint,
            "os_quiesced",
            {
                "phase": "os_quiesced",
                "observation": prior,
                "guest_image_verified": True,
            },
        )
    state.keys(
        entry, {"phase", "host", "guest", "reference", "root", "ownership", "stopped"}
    )
    require(entry["phase"] == phase, "entry-phase")
    request = checkpoint["prepared"]["source_request"]
    profile = checkpoint["prepared"]["image_profile"]
    expected = checkpoint["completion"]["runtime"]
    frame = evidence["observation"]
    guard, _, _ = runtime.load_profile(request, profile)
    current._host(request, entry["host"])
    same(entry["host"], frame["host"], "entry-host")
    state.keys(
        entry["guest"], {"config", "status", "runtime", "pending", "ha_membership"}
    )
    observe.validate_guest(request["policy"], entry["guest"])
    same(
        runtime.stable_guest(entry["guest"]),
        runtime.stable_guest(frame["guest"]),
        "entry-guest",
    )
    require(
        frame["guest"]["runtime"]["uptime"] >= entry["guest"]["runtime"]["uptime"],
        "uptime-decreased",
    )
    state.keys(entry["root"], {"path", "identity", "uuid"})
    same(
        entry["root"],
        {key: profile["rootfs"][key] for key in ("path", "identity", "uuid")},
        "entry-root",
    )
    state.keys(entry["ownership"], {"document", "file", "directory", "retired"})
    guard.validate_ownership(request["policy"], entry["ownership"])
    retained = frame["retained" if phase == "os_quiesced" else "guarded"]
    same(
        guard.ownership_seal(entry["ownership"]),
        guard.ownership_seal(retained["ownership"]),
        "entry-ownership",
    )
    if phase == "os_quiesced":
        require(entry["stopped"] is None, "unexpected-stopped")
        runtime.validate_reference(request, entry["reference"])
        same(entry["reference"], frame["reference"], "entry-reference")
    else:
        runtime.validate_stopped_reference(request, entry["reference"])
        same(
            entry["reference"]["files"],
            expected["reference"]["files"],
            "entry-reference",
        )
        stopped = entry["stopped"]
        state.keys(stopped, {"lxc_state", "cgroup", "prior_fence"})
        require(stopped["lxc_state"] == "STOPPED", "lxc-state")
        _cgroup(stopped["cgroup"])
        fence = stopped["prior_fence"]
        require(type(fence) is str, "prior-fence")
        require(
            (
                fence == "manager-epoch-changed"
                if entry["host"]["boot_id"] != prior["host"]["boot_id"]
                else fence in {"prior-init-absent", "prior-init-reused"}
            ),
            "prior-fence",
        )


def validate_phase_admission(checkpoint, phase, current_evidence, entry, prior_runtime):
    """Return None for coherent claims; never authenticate native reads or leases.

    Stopped admission requires an explicit, externally accepted running prior.
    Both original and private input views must remain unchanged through the
    pure validation. Malformed inputs raise PersistenceError.
    """
    original = [checkpoint, phase, current_evidence, entry, prior_runtime]
    try:
        _json(original)
        raw = state.canonical(original)
        require(0 < len(raw) <= MAX_BYTES, "input-limit")
        private = observe.decode(raw)
        _validate(*private)
        for values in (private, original):
            _json(values)
            require(state.canonical(values) == raw, "input-changed")
    except state.PersistenceError:
        raise
    except (
        KeyError,
        IndexError,
        TypeError,
        ValueError,
        AttributeError,
        RecursionError,
        OverflowError,
    ):
        raise state.PersistenceError(
            "persistence-owner-phase-admission-invalid"
        ) from None
