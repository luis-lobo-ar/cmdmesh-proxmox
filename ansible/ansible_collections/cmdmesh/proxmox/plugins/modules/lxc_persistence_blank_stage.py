#!/usr/bin/python
"""Ansible boundary for denied reference OS configuration generation."""

DOCUMENTATION = r"""
---
module: lxc_persistence_blank_stage
short_description: Deny managed starts and generate an isolated reference LXC config
description:
  - Consumes an already qualified stopped recipient, preserving its original source.
  - Installs a false pre-start command in both normal and debug instance units.
  - Requests only the existing cores=1 and cpulimit=1 values to generate the native LXC config.
  - Does not start a guest, publish an allowing guard, attach binds, initialize data or change credentials.
options:
  action:
    description: Prepare, stage once, or read the same consumed stage.
    type: str
    required: true
    choices: [prepare, stage, status]
  recipient_prepared_json:
    description: Exact retained canonical recipient preparation from the previous component.
    type: str
  recipient_prepared_sha256:
    description: Separately trusted hash of the previous recipient preparation.
    type: str
  prepared_json:
    description: Exact retained canonical deny/generate preparation.
    type: str
  prepared_sha256:
    description: Separately trusted hash of this preparation.
    type: str
  allow_changes:
    description: Explicit permission for the deny/generate stage outside check mode.
    type: bool
    default: false
author:
  - Luis Lobo Borobia
attributes:
  check_mode:
    support: partial
    details: Rechecks exact stopped recipient and pristine unit/config paths without writing.
  diff_mode:
    support: none
"""

EXAMPLES = r"""
- name: Prepare the denied blank OS stage
  cmdmesh.proxmox.lxc_persistence_blank_stage:
    action: prepare
    recipient_prepared_json: "{{ retained_recipient_json }}"
    recipient_prepared_sha256: "{{ retained_recipient_sha256 }}"
  register: preparation

# Retain and review canonical preparation bytes/hash before permission to write.
- name: Recheck without installing guards or generating config
  cmdmesh.proxmox.lxc_persistence_blank_stage:
    action: stage
    prepared_json: "{{ retained_stage_json }}"
    prepared_sha256: "{{ retained_stage_sha256 }}"
  check_mode: true

- name: Deny both starts and generate the stopped config once
  cmdmesh.proxmox.lxc_persistence_blank_stage:
    action: stage
    prepared_json: "{{ retained_stage_json }}"
    prepared_sha256: "{{ retained_stage_sha256 }}"
    allow_changes: true

- name: Observe without replaying a consumed stage
  cmdmesh.proxmox.lxc_persistence_blank_stage:
    action: status
    prepared_json: "{{ retained_stage_json }}"
    prepared_sha256: "{{ retained_stage_sha256 }}"
"""

RETURN = r"""
denied_generation_verified:
  description: Both deny configurations, the stopped recipient and generated native config passed postchecks.
  type: bool
  returned: always
boot_verified:
  description: Always false. This operation never starts the guest.
  type: bool
  returned: always
rebuild_verified:
  description: Always false. No application rebuild occurs.
  type: bool
  returned: always
restore_verified:
  description: Always false. No restore occurs.
  type: bool
  returned: always
assessment:
  description: Prepared, blank-stage-preflight-only, denied-generation-postchecked or observed.
  type: str
  returned: success
mutation_attempted:
  description: Whether guard/config writes were dispatched or may have been dispatched.
  type: bool
  returned: always
effects_may_exist:
  description: Preserve partial guards, config and the consumed intent on failure; never retry automatically.
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
    persistence_blank_stage as stage,
    persistence_state as state,
)


def execute(
    action,
    recipient_prepared_json=None,
    recipient_prepared_sha256=None,
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
        "denied_generation_verified": False,
        "boot_verified": False,
        "rebuild_verified": False,
        "restore_verified": False,
    }
    if action == "prepare":
        raw = state.canonical(
            stage.prepare(recipient_prepared_json.encode(), recipient_prepared_sha256)
        )
        return {
            **base,
            "assessment": "prepared",
            "prepared_json": raw.decode(),
            "prepared_sha256": state.sha256(raw),
        }
    state.require(
        action in {"stage", "status"}, "persistence-blank-stage-operation-unsupported"
    )
    if action == "stage" and not check_mode and not allow_changes:
        raise state.PersistenceError("persistence-blank-stage-change-disabled")
    raw = prepared_json.encode()
    if action == "status":
        return {**base, **stage.status(raw, prepared_sha256), "assessment": "observed"}
    if check_mode:
        frozen = stage.load_prepared(raw, prepared_sha256)
        fresh = stage.prepare(
            state.canonical(frozen["recipient_prepared"]), frozen["recipient_sha256"]
        )
        state.require(
            state.canonical(fresh) == raw, "persistence-blank-stage-preflight-changed"
        )
        return {
            **base,
            "assessment": "blank-stage-preflight-only",
            "changed": True,
            "would_change": True,
            "prepared_sha256": prepared_sha256,
        }
    return {
        **stage.apply(raw, prepared_sha256),
        "changed": True,
        "mutation_attempted": True,
        "command_outcome": "succeeded",
        "assessment": "denied-generation-postchecked",
    }


def failure(error, action, check_mode, allow_changes):
    possible = action == "stage" and not check_mode and allow_changes
    code = getattr(error, "code", None)
    if type(code) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,120}", code) is None:
        code = "persistence-blank-stage-refused"
    return {
        "msg": "Blank stage refused or needs reconciliation. Keep partial deny guards/config and inspect the same consumed intent; do not retry or start the guest.",
        "error_code": code,
        "changed": possible,
        "mutation_attempted": possible,
        "effects_may_exist": possible,
        "command_outcome": "unknown" if possible else "not-dispatched",
        "denied_generation_verified": False,
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
                "choices": ["prepare", "stage", "status"],
            },
            **{
                key: {"type": "str", "no_log": True}
                for key in (
                    "recipient_prepared_json",
                    "recipient_prepared_sha256",
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
                ["recipient_prepared_json", "recipient_prepared_sha256"],
            ),
            ("action", "stage", ["prepared_json", "prepared_sha256"]),
            ("action", "status", ["prepared_json", "prepared_sha256"]),
        ],
        required_together=[
            ("recipient_prepared_json", "recipient_prepared_sha256"),
            ("prepared_json", "prepared_sha256"),
        ],
        mutually_exclusive=[("recipient_prepared_json", "prepared_json")],
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
                    "recipient_prepared_json",
                    "recipient_prepared_sha256",
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
