#!/usr/bin/python
"""One guarded memory-only change. Core owns the overall procedure journal."""

DOCUMENTATION = r"""
---
module: lxc_memory
short_description: Check or grow one owned running LXC memory ceiling
description:
  - Validates frozen intent and independently reads actual native host and guest state.
  - Changes only memory using the approved Proxmox configuration digest.
  - Does not create guests, modify tags, shrink, restart, retry or roll back.
options:
  prepared:
    description: Strict version-1 cmdmesh.proxmox.lxc-memory.prepared document from preparation.
    type: dict
    required: true
  allow_changes:
    description: Explicit permission for actual growth; not needed for check mode or an unchanged target.
    type: bool
    default: false
author:
  - Luis Lobo Borobia
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
"""

EXAMPLES = r"""
- name: Assess the frozen owned LXC intent
  cmdmesh.proxmox.lxc_memory:
    prepared: "{{ cmdmesh_memory_prepared }}"
  check_mode: true

- name: Apply exactly the approved memory intent
  cmdmesh.proxmox.lxc_memory:
    prepared: "{{ cmdmesh_memory_prepared }}"
    allow_changes: "{{ cmdmesh_allow_changes | default(false) | bool }}"
"""

RETURN = r"""
assessment:
  description: Checked, unchanged or locally postchecked; not overall procedure verification.
  type: str
  returned: success
mutation_attempted:
  description: Whether the single fixed change command was dispatched or may have been dispatched.
  type: bool
  returned: always
command_outcome:
  description: Not-dispatched, succeeded, failed or unknown; separate from observed postconditions.
  type: str
  returned: always
checks:
  description: Fixed supplied-evidence checks from the independent native reads.
  type: dict
  returned: success
"""

import signal
import time

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    memory_remote,
    memory_state,
)


class MemoryChangeError(Exception):
    def __init__(self, code, command_outcome):
        self.code = code
        self.command_outcome = command_outcome
        self.mutation_attempted = command_outcome != "not-dispatched"
        super().__init__(code)


def observe(request):
    started_ms = time.time_ns() // 1000000
    frame = memory_remote.collect(request, observed_at_unix_ms=started_ms)
    if not isinstance(frame, dict) or frame.get("observed_at_unix_ms") != started_ms:
        raise memory_state.MemoryEvidenceError("memory-driver-evidence-invalid")
    return frame


def execute(prepared, *, check_mode, allow_changes):
    command_outcome = "not-dispatched"
    try:
        memory_state.validate_prepared(prepared)
        required = prepared["change_required"]
        if required and not check_mode and not allow_changes:
            raise memory_state.MemoryEvidenceError("memory-change-disabled", "rejected")
        before = observe(prepared["request"])
        checked = memory_state.preflight(
            prepared, before, now_ms=time.time_ns() // 1000000
        )
        if check_mode or not required:
            return {
                "changed": bool(check_mode and required),
                "would_change": required,
                "assessment": "checked" if required else "unchanged",
                "mutation_attempted": False,
                "command_outcome": command_outcome,
                "subject_key": prepared["subject_key"],
                "checks": checked["checks"],
            }
        command_outcome = "unknown"
        try:
            memory_remote.command(
                [
                    "/usr/sbin/pct",
                    "set",
                    str(prepared["request"]["selector"]["vmid"]),
                    "--memory",
                    str(prepared["desired_memory_mb"]),
                    "--digest",
                    prepared["baseline"]["configuration"]["digest"],
                ]
            )
        except memory_remote.RemoteObservationError as error:
            if error.code == "remote-memory-command-failed":
                command_outcome = "failed"
            raise
        command_outcome = "succeeded"
        after = observe(prepared["request"])
        checked = memory_state.verify(prepared, after, now_ms=time.time_ns() // 1000000)
        return {
            "changed": True,
            "would_change": True,
            "assessment": "postchecked",
            "mutation_attempted": True,
            "command_outcome": command_outcome,
            "subject_key": prepared["subject_key"],
            "checks": checked["checks"],
        }
    except (
        memory_state.MemoryEvidenceError,
        memory_remote.RemoteObservationError,
    ) as error:
        raise MemoryChangeError(error.code, command_outcome) from None
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise MemoryChangeError("memory-driver-unavailable", command_outcome) from None


def deadline(_signal, _frame):
    raise memory_remote.RemoteObservationError("memory-driver-deadline")


def main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec={
            "prepared": {"type": "dict", "required": True, "no_log": True},
            "allow_changes": {"type": "bool", "default": False},
        },
        supports_check_mode=True,
    )
    # Protect framework argument failures, then redact invocation explicitly so
    # value-based censoring cannot corrupt safe structured results.
    module.no_log_values.clear()
    invocation = {
        "module_args": {
            "prepared": "withheld",
            "allow_changes": module.params["allow_changes"],
        }
    }
    try:
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(120)
        result = execute(
            module.params["prepared"],
            check_mode=module.check_mode,
            allow_changes=module.params["allow_changes"],
        )
    except MemoryChangeError as error:
        module.fail_json(
            msg=error.code,
            code=error.code,
            changed=error.mutation_attempted,
            mutation_attempted=error.mutation_attempted,
            command_outcome=error.command_outcome,
            remote_state=(
                "uncertain" if error.mutation_attempted else "not-changed-by-this-call"
            ),
            invocation=invocation,
        )
    finally:
        signal.alarm(0)
    module.exit_json(**result, invocation=invocation)


if __name__ == "__main__":
    main()
