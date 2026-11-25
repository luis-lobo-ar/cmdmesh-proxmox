#!/usr/bin/python
"""Ansible boundary for one guarded, bind-free reference OS boot."""

DOCUMENTATION = r"""
---
module: lxc_persistence_blank_boot
short_description: Start one isolated blank reference OS under a pinned pre-start guard
description:
  - Requires a stopped qualified recipient and a separately trusted successful deny/generate completion.
  - Publishes both checked guard invocations before removing only their owned false commands.
  - Sends one verified HTTPS native start and verifies its task and actual kernel/guest readiness.
  - Never installs an application, attaches retained binds, initializes data or changes credentials.
options:
  action:
    description: Prepare, boot once, or observe the same consumed attempt without reposting.
    type: str
    required: true
    choices: [prepare, boot, status]
  stage_prepared_json:
    description: Exact canonical preparation of the already completed deny/generate stage.
    type: str
  stage_prepared_sha256:
    description: Separately trusted hash of the previous stage preparation.
    type: str
  stage_completion_sha256:
    description: Completion hash obtained from the successful trusted controller result, never the node file alone.
    type: str
  prepared_json:
    description: Exact canonical blank boot preparation retained on the controller.
    type: str
  prepared_sha256:
    description: Separately trusted hash of the blank boot preparation.
    type: str
  allow_changes:
    description: Explicit permission for guard publication and one native boot outside check mode.
    type: bool
    default: false
author:
  - Luis Lobo Borobia
attributes:
  check_mode:
    support: partial
    details: Revalidates the completed previous stage and pristine boot paths without publishing or starting.
  diff_mode:
    support: none
"""

EXAMPLES = r"""
- name: Prepare from the successful deny/generate receipt
  cmdmesh.proxmox.lxc_persistence_blank_boot:
    action: prepare
    stage_prepared_json: "{{ retained_stage_json }}"
    stage_prepared_sha256: "{{ retained_stage_sha256 }}"
    stage_completion_sha256: "{{ trusted_stage_completion_sha256 }}"
  register: preparation

# Retain and review exact preparation bytes/hash before permission to write.
- name: Check the exact boot intent without changes
  cmdmesh.proxmox.lxc_persistence_blank_boot:
    action: boot
    prepared_json: "{{ retained_boot_json }}"
    prepared_sha256: "{{ retained_boot_sha256 }}"
  check_mode: true

- name: Publish checked guards and start the blank OS once
  cmdmesh.proxmox.lxc_persistence_blank_boot:
    action: boot
    prepared_json: "{{ retained_boot_json }}"
    prepared_sha256: "{{ retained_boot_sha256 }}"
    allow_changes: true

- name: Observe the same attempt without publication or repost
  cmdmesh.proxmox.lxc_persistence_blank_boot:
    action: status
    prepared_json: "{{ retained_boot_json }}"
    prepared_sha256: "{{ retained_boot_sha256 }}"
"""

RETURN = r"""
assessment:
  description: Prepared, blank-boot-preflight-only, blank-os-postchecked or observed.
  type: str
  returned: success
boot_verified:
  description: Actual isolated blank OS task/kernel/guest checks passed; never implies application readiness.
  type: bool
  returned: always
rebuild_verified:
  description: Always false. No retained-data application rebuild occurs.
  type: bool
  returned: always
restore_verified:
  description: Always false. No restore occurs.
  type: bool
  returned: always
mutation_attempted:
  description: Whether guard publication or start was dispatched or may have been dispatched.
  type: bool
  returned: always
effects_may_exist:
  description: Preserve partial guards, candidate journals and the consumed intent on failure; never replay automatically.
  type: bool
  returned: failure
prepared_json:
  description: Exact canonical preparation to retain without reformatting.
  type: str
  returned: preparation
prepared_sha256:
  description: SHA256 of the canonical preparation.
  type: str
  returned: preparation
"""

import re

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_blank_boot as boot,
    persistence_state as state,
)


def execute(
    action,
    stage_prepared_json=None,
    stage_prepared_sha256=None,
    stage_completion_sha256=None,
    prepared_json=None,
    prepared_sha256=None,
    allow_changes=False,
    *,
    check_mode=False
):
    base = {
        "changed": False,
        "mutation_attempted": False,
        "command_outcome": "not-dispatched",
        "boot_verified": False,
        "rebuild_verified": False,
        "restore_verified": False,
    }
    if action == "prepare":
        raw = state.canonical(
            boot.prepare(
                stage_prepared_json.encode(),
                stage_prepared_sha256,
                stage_completion_sha256,
            )
        )
        return {
            **base,
            "assessment": "prepared",
            "prepared_json": raw.decode(),
            "prepared_sha256": state.sha256(raw),
        }
    state.require(
        action in {"boot", "status"}, "persistence-blank-boot-operation-unsupported"
    )
    if action == "boot" and not check_mode and not allow_changes:
        raise state.PersistenceError("persistence-blank-boot-change-disabled")
    raw = prepared_json.encode()
    if action == "status":
        return {**base, **boot.status(raw, prepared_sha256), "assessment": "observed"}
    if check_mode:
        frozen = boot.load_prepared(raw, prepared_sha256)
        fresh = boot.prepare(
            state.canonical(frozen["stage_prepared"]),
            frozen["stage_sha256"],
            frozen["stage_completion_sha256"],
        )
        state.require(
            state.canonical(fresh) == raw, "persistence-blank-boot-preflight-changed"
        )
        return {
            **base,
            "assessment": "blank-boot-preflight-only",
            "changed": True,
            "would_change": True,
            "prepared_sha256": prepared_sha256,
        }
    return {
        **boot.boot(raw, prepared_sha256),
        "changed": True,
        "mutation_attempted": True,
        "command_outcome": "succeeded",
        "assessment": "blank-os-postchecked",
    }


def failure(error, action, check_mode, allow_changes):
    possible = action == "boot" and not check_mode and allow_changes
    code = getattr(error, "code", None)
    if type(code) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,120}", code) is None:
        code = "persistence-blank-boot-refused"
    return {
        "msg": "Blank boot refused or needs reconciliation. Keep consumed claims and partial guard/task records; observe the same intent without republishing or reposting. A node candidate completion alone is untrusted after failure.",
        "error_code": code,
        "changed": possible,
        "mutation_attempted": possible,
        "effects_may_exist": possible,
        "command_outcome": "unknown" if possible else "not-dispatched",
        "boot_verified": False,
        "rebuild_verified": False,
        "restore_verified": False,
    }


def main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec={
            "action": {
                "type": "str",
                "required": True,
                "choices": ["prepare", "boot", "status"],
            },
            **{
                key: {"type": "str", "no_log": True}
                for key in (
                    "stage_prepared_json",
                    "stage_prepared_sha256",
                    "stage_completion_sha256",
                    "prepared_json",
                    "prepared_sha256",
                )
            },
            "allow_changes": {"type": "bool", "default": False},
        },
        required_if=[
            (
                "action",
                "prepare",
                [
                    "stage_prepared_json",
                    "stage_prepared_sha256",
                    "stage_completion_sha256",
                ],
            ),
            ("action", "boot", ["prepared_json", "prepared_sha256"]),
            ("action", "status", ["prepared_json", "prepared_sha256"]),
        ],
        required_together=[
            ("stage_prepared_json", "stage_prepared_sha256", "stage_completion_sha256"),
            ("prepared_json", "prepared_sha256"),
        ],
        mutually_exclusive=[("stage_prepared_json", "prepared_json")],
        supports_check_mode=True,
    )
    module.no_log_values.clear()
    invocation = {
        "module_args": {
            "action": module.params["action"],
            "allow_changes": module.params["allow_changes"],
            **{
                key: "withheld"
                for key in (
                    "stage_prepared_json",
                    "stage_prepared_sha256",
                    "stage_completion_sha256",
                    "prepared_json",
                    "prepared_sha256",
                )
            },
        }
    }
    try:
        result = execute(**module.params, check_mode=module.check_mode)
    except Exception as error:
        module.fail_json(
            **failure(
                error,
                module.params["action"],
                module.check_mode,
                module.params["allow_changes"],
            ),
            exception="",
            invocation=invocation
        )
    else:
        module.exit_json(**result, invocation=invocation)


if __name__ == "__main__":
    main()
