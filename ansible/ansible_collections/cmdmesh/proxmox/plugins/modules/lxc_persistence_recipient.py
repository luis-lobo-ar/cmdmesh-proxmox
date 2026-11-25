#!/usr/bin/python
"""Ansible boundary for one stopped reference rebuild recipient."""

DOCUMENTATION = r"""
---
module: lxc_persistence_recipient
short_description: Provision a stopped isolated reference rebuild recipient
description:
  - Holds the existing stopped reference source lock while checking/provisioning.
  - Creates one absent protected, unprivileged guest with a new template rootfs and no data/config binds.
  - Does not initialize data, change ownership, start a guest or certify application rebuild.
  - Requires root on the verified standalone PVE host; local ephemeral PAM authentication stays in memory.
options:
  action:
    description: Prepare, provision once, or read status of the consumed attempt.
    type: str
    required: true
    choices: [prepare, provision, status]
  recipient_request:
    description: Version-1 request with source observer, absent destination, template hash and storage.
    type: dict
  prepared_json:
    description: Exact canonical preparation retained on the trusted controller.
    type: str
  prepared_sha256:
    description: Separately retained preparation hash.
    type: str
  allow_changes:
    description: Explicit permission for native create. Not needed in check mode or status.
    type: bool
    default: false
author:
  - Luis Lobo Borobia
attributes:
  check_mode:
    support: partial
    details: Repeats source and destination checks without persistent journals or create requests.
  diff_mode:
    support: none
"""

EXAMPLES = r"""
- name: Prepare a new stopped recipient from the qualified template
  cmdmesh.proxmox.lxc_persistence_recipient:
    action: prepare
    recipient_request: "{{ private_recipient_request }}"
  register: preparation

# Retain and review exact canonical bytes and hash on the controller first.
- name: Check the retained intent without provisioning
  cmdmesh.proxmox.lxc_persistence_recipient:
    action: provision
    prepared_json: "{{ retained_prepared_json }}"
    prepared_sha256: "{{ retained_prepared_sha256 }}"
  check_mode: true

- name: Provision exactly once without starting or initializing
  cmdmesh.proxmox.lxc_persistence_recipient:
    action: provision
    prepared_json: "{{ retained_prepared_json }}"
    prepared_sha256: "{{ retained_prepared_sha256 }}"
    allow_changes: true

- name: Observe the same consumed attempt without reposting
  cmdmesh.proxmox.lxc_persistence_recipient:
    action: status
    prepared_json: "{{ retained_prepared_json }}"
    prepared_sha256: "{{ retained_prepared_sha256 }}"
"""

RETURN = r"""
assessment:
  description: Prepared, recipient-preflight-only, recipient-postchecked or observed.
  type: str
  returned: success
provisioned_verified:
  description: Native task and actual stopped guest/rootfs checks passed.
  type: bool
  returned: always
rebuild_verified:
  description: Always false. Authenticated application rebuild needs a separate trial.
  type: bool
  returned: always
restore_verified:
  description: Always false. No restore occurs.
  type: bool
  returned: always
mutation_attempted:
  description: Whether a create was dispatched or may have been dispatched on failure.
  type: bool
  returned: always
effects_may_exist:
  description: Conservatively true after a permitted create failure; inspect its consumed journal.
  type: bool
  returned: failure
prepared_json:
  description: Exact canonical preparation; retain without reformatting.
  type: str
  returned: preparation
prepared_sha256:
  description: Hash of the exact preparation.
  type: str
  returned: preparation
"""

import re

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_recipient as recipient,
    persistence_state as state,
)


def execute(
    action,
    recipient_request=None,
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
        "provisioned_verified": False,
        "rebuild_verified": False,
        "restore_verified": False,
    }
    if action == "prepare":
        raw = state.canonical(recipient.prepare(recipient_request))
        return {
            **base,
            "assessment": "prepared",
            "prepared_json": raw.decode(),
            "prepared_sha256": state.sha256(raw),
        }
    state.require(
        action in {"provision", "status"}, "persistence-recipient-operation-unsupported"
    )
    if action == "provision" and not check_mode and not allow_changes:
        raise state.PersistenceError("persistence-recipient-change-disabled")
    raw = prepared_json.encode("utf-8")
    if action == "status":
        return {
            **base,
            **recipient.status(raw, prepared_sha256),
            "assessment": "observed",
        }
    if check_mode:
        frozen = recipient.load_prepared(raw, prepared_sha256)
        fresh = recipient.prepare(frozen["request"])
        state.require(
            state.canonical(fresh) == raw,
            "persistence-recipient-source-or-environment-changed",
        )
        return {
            **base,
            "changed": True,
            "would_change": True,
            "assessment": "recipient-preflight-only",
            "prepared_sha256": prepared_sha256,
        }
    return {
        **recipient.provision(raw, prepared_sha256),
        "changed": True,
        "mutation_attempted": True,
        "command_outcome": "succeeded",
        "assessment": "recipient-postchecked",
    }


def failure(error, action, check_mode, allow_changes):
    possible = action == "provision" and not check_mode and allow_changes
    code = getattr(error, "code", None)
    if type(code) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,120}", code) is None:
        code = "persistence-recipient-refused"
    return {
        "msg": "Recipient refused or needs reconciliation. Preserve partial outputs and inspect status of the same consumed intent before further action.",
        "error_code": code,
        "changed": possible,
        "mutation_attempted": possible,
        "effects_may_exist": possible,
        "command_outcome": "unknown" if possible else "not-dispatched",
        "provisioned_verified": False,
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
                "choices": ["prepare", "provision", "status"],
            },
            "recipient_request": {"type": "dict", "no_log": True},
            "prepared_json": {"type": "str", "no_log": True},
            "prepared_sha256": {"type": "str", "no_log": True},
            "allow_changes": {"type": "bool", "default": False},
        },
        required_if=[
            ("action", "prepare", ["recipient_request"]),
            ("action", "provision", ["prepared_json", "prepared_sha256"]),
            ("action", "status", ["prepared_json", "prepared_sha256"]),
        ],
        required_together=[("prepared_json", "prepared_sha256")],
        mutually_exclusive=[("recipient_request", "prepared_json")],
        supports_check_mode=True,
    )
    module.no_log_values.clear()
    invocation = {
        "module_args": {
            "action": module.params["action"],
            "allow_changes": module.params["allow_changes"],
            **{
                key: "withheld"
                for key in ("recipient_request", "prepared_json", "prepared_sha256")
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
