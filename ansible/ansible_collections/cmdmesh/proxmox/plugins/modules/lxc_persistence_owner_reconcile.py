#!/usr/bin/python
"""Ansible boundary for one preserved, pre-retirement owner failure."""

DOCUMENTATION = r"""
---
module: lxc_persistence_owner_reconcile
short_description: Reconcile a known stopped owner guard refusal once
description:
  - Admits only the exact pre-retirement guard-refusal stage of owner publication.
  - Uses a new permanent pair claim and the corrected, pinned standalone guard.
  - Preserves the failed publication journal, owner record and all start denials.
  - Archives the old target references and retires the legacy reference after guard validation.
  - Does not start a guest, application writer or restore.
options:
  action:
    description: Prepare read-only, reconcile once, or inspect the completed reconciliation.
    type: str
    required: true
    choices: [prepare, reconcile, status]
  parent_prepared_json:
    description: Exact canonical preparation of the failed original publication.
    type: str
  parent_prepared_sha256:
    description: Separately trusted hash of the original preparation.
    type: str
  parent_failure_sha256:
    description: Trusted hash of the canonical map of the six original failure record hashes.
    type: str
  prepared_json:
    description: Exact retained canonical reconciliation preparation.
    type: str
  prepared_sha256:
    description: Separately trusted hash of the reconciliation preparation.
    type: str
  guard_python:
    description: Exact supported corrected standalone guard source.
    type: str
  allow_changes:
    description: Permit metadata writes outside check mode.
    type: bool
    default: false
author:
  - Luis Lobo Borobia
attributes:
  check_mode:
    support: partial
    details: Reobserves the exact failed stage without creating reconciliation files.
  diff_mode:
    support: none
"""

EXAMPLES = r"""
- name: Prepare a known stopped guard failure without changes
  cmdmesh.proxmox.lxc_persistence_owner_reconcile:
    action: prepare
    parent_prepared_json: "{{ failed_publication_json }}"
    parent_prepared_sha256: "{{ failed_publication_sha256 }}"
    parent_failure_sha256: "{{ failure_records_sha256 }}"
    guard_python: "{{ lookup('file', corrected_guard_source, rstrip=false) }}"
  register: reconciliation

- name: Check the exact prepared reconciliation
  cmdmesh.proxmox.lxc_persistence_owner_reconcile:
    action: reconcile
    prepared_json: "{{ reconciliation.prepared_json }}"
    prepared_sha256: "{{ reconciliation.prepared_sha256 }}"
    guard_python: "{{ lookup('file', corrected_guard_source, rstrip=false) }}"
  check_mode: true
"""

RETURN = r"""
owner_reconciliation_verified:
  description: The completed forward metadata reconciliation passed its closing checks.
  type: bool
  returned: always
owner_publication_verified:
  description: The new stopped owner reference passed checks under the new claim.
  type: bool
  returned: always
boot_verified:
  description: Always false; every managed start remains denied.
  type: bool
  returned: always
mutation_attempted:
  description: Whether reconciliation metadata may have been written.
  type: bool
  returned: always
effects_may_exist:
  description: A failure may retain partial changes and a consumed claim.
  type: bool
  returned: failure
"""

import re

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_reconcile as reconcile,
    persistence_state as state,
)


def execute(
    action,
    parent_prepared_json=None,
    parent_prepared_sha256=None,
    parent_failure_sha256=None,
    prepared_json=None,
    prepared_sha256=None,
    guard_python=None,
    allow_changes=False,
    *,
    check_mode=False
):
    base = {
        "changed": False,
        "mutation_attempted": False,
        "command_outcome": "not-dispatched",
        "owner_reconciliation_verified": False,
        "owner_publication_verified": False,
        **reconcile.original.FLAGS,
    }
    reconcile.require(
        action in {"prepare", "reconcile", "status"}, "operation-unsupported"
    )
    if action == "reconcile" and not check_mode and not allow_changes:
        raise state.PersistenceError("persistence-owner-reconcile-change-disabled")
    if action == "prepare":
        raw = state.canonical(
            reconcile.prepare(
                parent_prepared_json.encode(),
                parent_prepared_sha256,
                parent_failure_sha256,
                guard_python.encode(),
            )
        )
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
            **reconcile.status(raw, prepared_sha256),
            "assessment": "observed",
        }
    guard_raw = guard_python.encode()
    if check_mode:
        guard = reconcile.load_guard_source(guard_raw)
        frozen, _ = reconcile.load_prepared(raw, prepared_sha256, guard)
        fresh = reconcile.prepare(
            state.canonical(frozen["parent_prepared"]),
            frozen["parent_prepared_sha256"],
            frozen["parent_failure_sha256"],
            guard_raw,
        )
        reconcile.require(state.canonical(fresh) == raw, "preflight-changed")
        return {
            **base,
            "assessment": "reconciliation-preflight-only",
            "changed": True,
            "would_change": True,
            "prepared_sha256": prepared_sha256,
        }
    return {
        **reconcile.apply(raw, prepared_sha256, guard_raw),
        "changed": True,
        "mutation_attempted": True,
        "command_outcome": "succeeded",
        "assessment": "reconciliation-postchecked",
    }


def failure(error, action, check_mode, allow_changes):
    possible = action == "reconcile" and not check_mode and allow_changes
    code = getattr(error, "code", None)
    if type(code) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,120}", code) is None:
        code = "persistence-owner-reconcile-refused"
    return {
        "msg": "Reconciliation refused or uncertain. Preserve both claims, archives and all start denials. Do not replay either operation or start a guest.",
        "error_code": code,
        "changed": possible,
        "mutation_attempted": possible,
        "effects_may_exist": possible,
        "command_outcome": "unknown" if possible else "not-dispatched",
        "owner_reconciliation_verified": False,
        "owner_publication_verified": False,
        **reconcile.original.FLAGS,
    }


def main():
    from ansible.module_utils.basic import AnsibleModule

    keys = (
        "parent_prepared_json",
        "parent_prepared_sha256",
        "parent_failure_sha256",
        "prepared_json",
        "prepared_sha256",
        "guard_python",
    )
    module = AnsibleModule(
        argument_spec={
            "action": {
                "type": "str",
                "required": True,
                "choices": ["prepare", "reconcile", "status"],
            },
            **{key: {"type": "str", "no_log": True} for key in keys},
            "allow_changes": {"type": "bool", "default": False},
        },
        required_if=[
            ("action", "prepare", [*keys[:3], "guard_python"]),
            (
                "action",
                "reconcile",
                ["prepared_json", "prepared_sha256", "guard_python"],
            ),
            ("action", "status", ["prepared_json", "prepared_sha256"]),
        ],
        required_together=[keys[:3], ("prepared_json", "prepared_sha256")],
        mutually_exclusive=[("parent_prepared_json", "prepared_json")],
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
