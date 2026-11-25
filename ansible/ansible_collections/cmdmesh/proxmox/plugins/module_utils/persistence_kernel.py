"""Explicit kernel binding for the isolated reference LXC resource profile.

The existing kernel reader also serves blank OS qualification. Its read-only
primitives take a small field projection here, never a fabricated blank policy.
Callers retain responsibility for ownership admission and native config leases.
"""

from dataclasses import dataclass
import os
import re
import socket

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_blank_runtime as reader,
    persistence_observe as observe,
    persistence_state as state,
)


def require(value, code):
    state.require(value, "persistence-kernel-" + code)


@dataclass(frozen=True)
class KernelBinding:
    node: str
    machine_id_sha256: str
    vmid: int
    volume: str
    root_path: str
    root_identity: tuple[int, ...]
    root_uuid: str
    generated_sha256: str
    allowed_cpus: tuple[int, ...]

    def __post_init__(self):
        require(state.matches(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", self.node), "node")
        state.digest(self.machine_id_sha256)
        state.integer(self.vmid, 100, 999999)
        require(
            self.volume == f"local:{self.vmid}/vm-{self.vmid}-disk-0.raw",
            "root-volume",
        )
        require(type(self.root_identity) is tuple, "root-identity")
        reader.guard.validate_root(
            {
                "path": self.root_path,
                "identity": list(self.root_identity),
                "uuid": self.root_uuid,
            },
            self.vmid,
        )
        state.digest(self.generated_sha256)
        require(
            type(self.allowed_cpus) is tuple
            and 0 < len(self.allowed_cpus) <= 4096
            and all(type(cpu) is int and 0 <= cpu <= 65535 for cpu in self.allowed_cpus)
            and tuple(sorted(set(self.allowed_cpus))) == self.allowed_cpus,
            "cpu-selection",
        )

    def _reader_input(self):
        return {
            "vmid": self.vmid,
            "config": {"rootfs": self.volume},
            "rootfs": {
                "path": self.root_path,
                "identity": list(self.root_identity),
                "uuid": self.root_uuid,
            },
            "generated_config_stable_sha256": self.generated_sha256,
            "cpu_policy": {"count": 1, "allowed": list(self.allowed_cpus)},
        }


def validate(binding, evidence):
    require(type(binding) is KernelBinding, "binding-required")
    reader.validate_kernel(binding._reader_input(), evidence)


def check_host(binding):
    require(
        os.geteuid() == 0 and socket.gethostname() == binding.node,
        "wrong-host",
    )
    machine, _ = observe.read_regular("/etc/machine-id", 64)
    require(
        re.fullmatch(b"[a-f0-9]{32}\n?", machine) is not None
        and state.sha256(machine.strip()) == binding.machine_id_sha256,
        "wrong-host",
    )


def collect(binding):
    """Observe only kernel state; no guest execution, application read or mutation."""
    require(type(binding) is KernelBinding, "binding-required")
    check_host(binding)
    evidence = reader.kernel(binding._reader_input())
    validate(binding, evidence)
    check_host(binding)
    return evidence
