#!/usr/bin/python
"""Ansible boundary for a stopped, denied retained-bind attachment."""

DOCUMENTATION = r"""
---
module: lxc_persistence_attach
short_description: Attach two retained reference binds with all managed starts denied
description:
  - Requires a stopped original, matching closed backup, and isolated stopped replacement.
  - Preserves original pre-start files and installs resetting false commands on both guests.
  - Temporarily disables replacement protection, adds only the data/config binds, then restores protection.
  - Every native write uses a fresh digest and durable dispatch record. Uncertain work is never retried.
  - Does not start guests, publish allowing guards, initialize data or change ownership or credentials.
options:
  action:
    description: Prepare, attach once, or inspect the same completed attachment.
    type: str
    required: true
    choices: [prepare, attach, status]
  recipient_prepared_json:
    description: Exact canonical preparation of the already provisioned recipient.
    type: str
  recipient_prepared_sha256:
    description: Separately trusted hash of the recipient preparation.
    type: str
  prepared_json:
    description: Exact retained canonical attachment preparation.
    type: str
  prepared_sha256:
    description: Separately trusted hash of this attachment preparation.
    type: str
  allow_changes:
    description: Explicit permission for deny and native configuration writes outside check mode.
    type: bool
    default: false
author:
  - Luis Lobo Borobia
attributes:
  check_mode:
    support: partial
    details: Rechecks preparation without creating claims, denials or configuration changes.
  diff_mode:
    support: none
"""

EXAMPLES = r"""
- name: Prepare the stopped attachment
  cmdmesh.proxmox.lxc_persistence_attach:
    action: prepare
    recipient_prepared_json: "{{ retained_recipient_json }}"
    recipient_prepared_sha256: "{{ retained_recipient_sha256 }}"
  register: preparation

- name: Recheck exact retained attachment preparation
  cmdmesh.proxmox.lxc_persistence_attach:
    action: attach
    prepared_json: "{{ retained_attachment_json }}"
    prepared_sha256: "{{ retained_attachment_sha256 }}"
  check_mode: true

- name: Attach once while leaving all four managed starts denied
  cmdmesh.proxmox.lxc_persistence_attach:
    action: attach
    prepared_json: "{{ retained_attachment_json }}"
    prepared_sha256: "{{ retained_attachment_sha256 }}"
    allow_changes: true
"""

RETURN = r"""
attachment_verified:
  description: The stopped protected replacement has the exact two binds and all four start denials passed checks.
  type: bool
  returned: always
boot_verified:
  description: Always false; no guest is started.
  type: bool
  returned: always
rebuild_verified:
  description: Always false; application startup and data access are separate qualifications.
  type: bool
  returned: always
restore_verified:
  description: Always false; no independent restore is performed.
  type: bool
  returned: always
mutation_attempted:
  description: Whether native writes may have been dispatched.
  type: bool
  returned: always
effects_may_exist:
  description: An apply failure may leave denials, temporary protection state and partial binds.
  type: bool
  returned: failure
"""

import re

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_attach as attach,
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
        "attachment_verified": False,
        **attach.FLAGS,
    }
    if action == "prepare":
        raw = state.canonical(
            attach.prepare(recipient_prepared_json.encode(), recipient_prepared_sha256)
        )
        return {
            **base,
            "assessment": "prepared",
            "prepared_json": raw.decode(),
            "prepared_sha256": state.sha256(raw),
        }
    state.require(
        action in {"attach", "status"}, "persistence-attach-operation-unsupported"
    )
    if action == "attach" and not check_mode and not allow_changes:
        raise state.PersistenceError("persistence-attach-change-disabled")
    raw = prepared_json.encode()
    if action == "status":
        return {**base, **attach.status(raw, prepared_sha256), "assessment": "observed"}
    if check_mode:
        frozen = attach.load_prepared(raw, prepared_sha256)
        fresh = attach.prepare(
            state.canonical(frozen["recipient_prepared"]), frozen["recipient_sha256"]
        )
        state.require(
            state.canonical(fresh) == raw, "persistence-attach-preflight-changed"
        )
        return {
            **base,
            "assessment": "attachment-preflight-only",
            "changed": True,
            "would_change": True,
            "prepared_sha256": prepared_sha256,
        }
    return {
        **attach.apply(raw, prepared_sha256),
        "changed": True,
        "mutation_attempted": True,
        "command_outcome": "succeeded",
        "assessment": "attachment-postchecked",
    }


def failure(error, action, check_mode, allow_changes):
    possible = action == "attach" and not check_mode and allow_changes
    code = getattr(error, "code", None)
    if type(code) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,120}", code) is None:
        code = "persistence-attach-refused"
    return {
        "msg": "Attachment refused or needs reconciliation. Keep the consumed claim and partial denials/configuration. Inspect protection and binds; do not retry or start either guest.",
        "error_code": code,
        "changed": possible,
        "mutation_attempted": possible,
        "effects_may_exist": possible,
        "command_outcome": "unknown" if possible else "not-dispatched",
        "attachment_verified": False,
        **attach.FLAGS,
    }


def main():
    from ansible.module_utils.basic import AnsibleModule

    keys = (
        "recipient_prepared_json",
        "recipient_prepared_sha256",
        "prepared_json",
        "prepared_sha256",
    )
    module = AnsibleModule(
        argument_spec={
            "action": {
                "type": "str",
                "required": True,
                "choices": ["prepare", "attach", "status"],
            },
            **{key: {"type": "str", "no_log": True} for key in keys},
            "allow_changes": {"type": "bool", "default": False},
        },
        required_if=[
            (
                "action",
                "prepare",
                ["recipient_prepared_json", "recipient_prepared_sha256"],
            ),
            ("action", "attach", ["prepared_json", "prepared_sha256"]),
            ("action", "status", ["prepared_json", "prepared_sha256"]),
        ],
        required_together=[
            ("recipient_prepared_json", "recipient_prepared_sha256"),
            ("prepared_json", "prepared_sha256"),
        ],
        mutually_exclusive=[("recipient_prepared_json", "prepared_json")],
        supports_check_mode=True,
    )
    # Redact inputs rather than letting Ansible's substring censor alter hashes.
    module.no_log_values.clear()
    invocation = {
        "module_args": {
            "action": module.params["action"],
            "allow_changes": module.params["allow_changes"],
            **{key: "withheld" for key in keys},
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
