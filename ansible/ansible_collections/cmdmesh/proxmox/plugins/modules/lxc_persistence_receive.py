#!/usr/bin/python
"""Ansible entry point for an unmounted reference backup receive."""

DOCUMENTATION = r"""
---
module: lxc_persistence_receive
short_description: Receive authenticated reference streams into absent datasets
description:
  - Prepares or executes one finite data/config receive into an empty owned parent.
  - The controller must authenticate/decrypt backup artifacts against its trusted receipt first.
  - Does not mount datasets, start guests, initialize data or certify application recovery.
options:
  action:
    description: Read-only preparation or once-only receive.
    type: str
    required: true
    choices: [prepare, receive]
  restore_request:
    description: Version-1 request binding target identity, tools and authenticated plaintext stream hashes.
    type: dict
  manifest_json:
    description: Canonical manifest authenticated against the separately trusted completed-backup receipt.
    type: str
  prepared_json:
    description: Exact canonical preparation retained on the trusted controller.
    type: str
  prepared_sha256:
    description: Separately retained hash of the preparation.
    type: str
  allow_changes:
    description: Explicit permission for native receive. Not needed in check mode.
    type: bool
    default: false
author:
  - Luis Lobo Borobia
attributes:
  check_mode:
    support: partial
    details: Repeats target and input preflight without persistent journals or receives.
  diff_mode:
    support: none
"""

EXAMPLES = r"""
- name: Prepare from independently authenticated private inputs
  cmdmesh.proxmox.lxc_persistence_receive:
    action: prepare
    restore_request: "{{ private_receive_request }}"
    manifest_json: "{{ trusted_manifest_json }}"
  register: preparation

# Retain and review the exact preparation on the trusted controller first.
- name: Check the retained receive without writing datasets
  cmdmesh.proxmox.lxc_persistence_receive:
    action: receive
    prepared_json: "{{ retained_prepared_json }}"
    prepared_sha256: "{{ retained_prepared_sha256 }}"
  check_mode: true

- name: Receive once into the approved empty parent
  cmdmesh.proxmox.lxc_persistence_receive:
    action: receive
    prepared_json: "{{ retained_prepared_json }}"
    prepared_sha256: "{{ retained_prepared_sha256 }}"
    allow_changes: true
"""

RETURN = r"""
assessment:
  description: Prepared, target-preflight-only or receive-postchecked.
  type: str
  returned: success
received_verified:
  description: Both unmounted receives and snapshot identity checks passed.
  type: bool
  returned: always
restore_verified:
  description: Always false. Application and source-unavailable recovery require separate tests.
  type: bool
  returned: always
mutation_attempted:
  description: Whether a receive was dispatched or may have been dispatched on failure.
  type: bool
  returned: always
effects_may_exist:
  description: Conservatively true after a permitted receive failure. Inspect its consumed journal.
  type: bool
  returned: failure
prepared_json:
  description: Exact canonical preparation text to retain without reformatting.
  type: str
  returned: preparation
prepared_sha256:
  description: Hash of the exact canonical preparation.
  type: str
  returned: preparation
"""

import re

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_restore as restore,
    persistence_state as state,
)


def execute(
    action,
    restore_request=None,
    manifest_json=None,
    prepared_json=None,
    prepared_sha256=None,
    allow_changes=False,
    *,
    check_mode=False,
):
    base = {
        "changed": False,
        "mutation_attempted": False,
        "received_verified": False,
        "restore_verified": False,
        "command_outcome": "not-dispatched",
    }
    if action == "prepare":
        prepared = restore.prepare_restore(
            restore_request, manifest_json.encode("utf-8")
        )
        raw = state.canonical(prepared)
        return {
            **base,
            "assessment": "prepared",
            "prepared_json": raw.decode(),
            "prepared_sha256": state.sha256(raw),
        }
    state.require(action == "receive", "persistence-receive-operation-unsupported")
    if not check_mode and not allow_changes:
        raise state.PersistenceError("persistence-receive-change-disabled")
    raw = prepared_json.encode("utf-8")
    if check_mode:
        prepared = restore.load_prepared(raw, prepared_sha256)
        fresh = restore.prepare_restore(
            prepared["request"], state.canonical(prepared["manifest"])
        )
        state.require(
            state.canonical(fresh) == raw, "persistence-receive-target-or-input-changed"
        )
        return {
            **base,
            "changed": True,
            "would_change": True,
            "assessment": "target-preflight-only",
            "prepared_sha256": prepared_sha256,
        }
    result = restore.execute_restore(raw, prepared_sha256)
    return {
        **result,
        "changed": True,
        "mutation_attempted": True,
        "command_outcome": "succeeded",
        "assessment": "receive-postchecked",
    }


def failure(error, action, check_mode, allow_changes):
    possible = action == "receive" and not check_mode and allow_changes
    code = getattr(error, "code", None)
    if type(code) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,120}", code) is None:
        code = "persistence-receive-refused"
    return {
        "msg": "Receive refused or needs reconciliation. Preserve partial targets and inspect the consumed journal before further action.",
        "error_code": code,
        "changed": possible,
        "mutation_attempted": possible,
        "effects_may_exist": possible,
        "command_outcome": "unknown" if possible else "not-dispatched",
        "received_verified": False,
        "restore_verified": False,
    }


def main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec={
            "action": {
                "type": "str",
                "required": True,
                "choices": ["prepare", "receive"],
            },
            "restore_request": {"type": "dict", "no_log": True},
            "manifest_json": {"type": "str", "no_log": True},
            "prepared_json": {"type": "str", "no_log": True},
            "prepared_sha256": {"type": "str", "no_log": True},
            "allow_changes": {"type": "bool", "default": False},
        },
        required_if=[
            ("action", "prepare", ["restore_request", "manifest_json"]),
            ("action", "receive", ["prepared_json", "prepared_sha256"]),
        ],
        required_together=[
            ("restore_request", "manifest_json"),
            ("prepared_json", "prepared_sha256"),
        ],
        mutually_exclusive=[("restore_request", "prepared_json")],
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
                    "restore_request",
                    "manifest_json",
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
            invocation=invocation,
        )
    else:
        module.exit_json(**result, invocation=invocation)


if __name__ == "__main__":
    main()
