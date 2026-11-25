#!/usr/bin/python
"""Ansible boundary for a claimed retained OS start with its application paused."""

DOCUMENTATION = r"""
---
module: lxc_persistence_retained_boot
short_description: Start one retained reference OS while excluding its writer
description:
  - Binds an accepted stopped-owner reconciliation and exact image profile.
  - Preserves the retired guest and removes only the current target start denials.
  - Keeps the application locked and disabled throughout native startup and verification.
  - Consumes a permanent claim and never retries an uncertain POST.
  - Does not qualify application rebuild or independent backup recovery.
options:
  action:
    description: Prepare read-only, start once, or inspect a completed start.
    type: str
    required: true
    choices: [prepare, boot, status]
  reconciliation_json:
    description: Exact canonical preparation of the accepted owner reconciliation.
    type: str
  reconciliation_sha256:
    description: Separately trusted reconciliation preparation hash.
    type: str
  completion_sha256:
    description: Separately trusted reconciliation completion hash.
    type: str
  source_sha256:
    description: Separately trusted full stopped Source3 observation hash.
    type: str
  image_profile:
    description: Qualified reference image profile with the exact supported helpers.
    type: dict
  prepared_json:
    description: Exact canonical retained OS start preparation.
    type: str
  prepared_sha256:
    description: Separately trusted retained OS start preparation hash.
    type: str
  allow_changes:
    description: Permit one claimed native start outside check mode.
    type: bool
    default: false
author:
  - Luis Lobo Borobia
attributes:
  check_mode:
    support: partial
    details: Boot reobserves the exact preparation without claims, denials or lifecycle writes.
  diff_mode:
    support: none
"""

EXAMPLES = r"""
- name: Prepare the retained OS start without changing the guest
  cmdmesh.proxmox.lxc_persistence_retained_boot:
    action: prepare
    reconciliation_json: "{{ reconciliation_json }}"
    reconciliation_sha256: "{{ reconciliation_sha256 }}"
    completion_sha256: "{{ reconciliation_completion_sha256 }}"
    source_sha256: "{{ stopped_source_sha256 }}"
    image_profile: "{{ qualified_image_profile }}"
  register: retained_os

- name: Check the exact planned start without consuming its claim
  cmdmesh.proxmox.lxc_persistence_retained_boot:
    action: boot
    prepared_json: "{{ retained_os.prepared_json }}"
    prepared_sha256: "{{ retained_os.prepared_sha256 }}"
  check_mode: true

- name: Inspect an already completed retained OS start
  cmdmesh.proxmox.lxc_persistence_retained_boot:
    action: status
    prepared_json: "{{ retained_os.prepared_json }}"
    prepared_sha256: "{{ retained_os.prepared_sha256 }}"
"""

RETURN = r"""
boot_verified:
  description: The claimed native start and current quiesced runtime passed all checks.
  type: bool
  returned: always
application_quiesced:
  description: The application is disabled and inactive with unchanged configuration and SQL facts.
  type: bool
  returned: always
mutation_attempted:
  description: Whether this invocation may have changed denials or dispatched startup.
  type: bool
  returned: always
effects_may_exist:
  description: A failed start may retain changes, a running guest and a consumed claim.
  type: bool
  returned: failure
"""

import re

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_retained_boot as boot,
    persistence_state as state,
)

FLAGS = {
    "boot_verified": False,
    "application_quiesced": False,
    "rebuild_verified": False,
    "restore_verified": False,
    "backup_verified": False,
}


def execute(
    action,
    reconciliation_json=None,
    reconciliation_sha256=None,
    completion_sha256=None,
    source_sha256=None,
    image_profile=None,
    prepared_json=None,
    prepared_sha256=None,
    allow_changes=False,
    *,
    check_mode=False
):
    boot.require(action in {"prepare", "boot", "status"}, "operation-unsupported")
    boot.require(type(allow_changes) is bool and type(check_mode) is bool, "mode")
    if action == "boot" and not check_mode and allow_changes is not True:
        raise state.PersistenceError("persistence-retained-boot-change-disabled")
    base = {
        "changed": False,
        "mutation_attempted": False,
        "command_outcome": "not-dispatched",
        **FLAGS,
    }
    if action == "prepare":
        value = boot.prepare(
            reconciliation_json.encode(),
            reconciliation_sha256,
            completion_sha256,
            source_sha256,
            image_profile,
        )
        raw = state.canonical(value)
        return {
            **base,
            "assessment": "prepared",
            "prepared_json": raw.decode(),
            "prepared_sha256": state.sha256(raw),
        }
    raw = prepared_json.encode()
    if action == "status":
        return {
            **base,
            **boot.status(raw, prepared_sha256),
            "assessment": "observed",
            "changed": False,
            "mutation_attempted": False,
        }
    if check_mode:
        value = boot.decode_prepared(raw, prepared_sha256)
        fresh = boot.prepare(
            state.canonical(value["reconciliation_prepared"]),
            value["reconciliation_sha256"],
            value["completion_sha256"],
            value["source_sha256"],
            value["image_profile"],
        )
        boot.require(state.canonical(fresh) == raw, "preflight-changed")
        return {
            **base,
            "assessment": "boot-preflight-only",
            "changed": True,
            "would_change": True,
            "prepared_sha256": prepared_sha256,
        }
    return {
        **boot.boot(raw, prepared_sha256),
        "changed": True,
        "mutation_attempted": True,
        "command_outcome": "succeeded",
        "assessment": "retained-os-postchecked",
    }


def failure(error, action, check_mode, allow_changes):
    possible = action == "boot" and not check_mode and allow_changes is True
    code = getattr(error, "code", None)
    if type(code) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,120}", code) is None:
        code = "persistence-retained-boot-refused"
    return {
        "msg": "Retained OS start refused or uncertain. Preserve the claim, archives and journals. Do not repeat the start or remove claims.",
        "error_code": code,
        "changed": possible,
        "mutation_attempted": possible,
        "effects_may_exist": possible,
        "command_outcome": "unknown" if possible else "not-dispatched",
        **FLAGS,
    }


def main():
    from ansible.module_utils.basic import AnsibleModule

    keys = (
        "reconciliation_json",
        "reconciliation_sha256",
        "completion_sha256",
        "source_sha256",
        "image_profile",
        "prepared_json",
        "prepared_sha256",
    )
    module = AnsibleModule(
        argument_spec={
            "action": {
                "type": "str",
                "required": True,
                "choices": ["prepare", "boot", "status"],
            },
            **{
                key: {
                    "type": "dict" if key == "image_profile" else "str",
                    "no_log": True,
                }
                for key in keys
            },
            "allow_changes": {"type": "bool", "default": False},
        },
        required_if=[
            ("action", "prepare", list(keys[:5])),
            ("action", "boot", list(keys[5:])),
            ("action", "status", list(keys[5:])),
        ],
        required_together=[keys[:5], keys[5:]],
        mutually_exclusive=[("reconciliation_json", "prepared_json")],
        supports_check_mode=True,
    )
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
