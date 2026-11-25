#!/usr/bin/python
"""Ansible boundary for the initial stopped reference owner publication."""

DOCUMENTATION = r"""
---
module: lxc_persistence_owner_publish
short_description: Publish a stopped reference owner while preserving all start denials
description:
  - Consumes the exact completed retained attachment and pinned standalone guard.
  - Preserves every original start denial and archives the replacement's blank guards.
  - Installs an owner-aware policy and retires the old reference into a refusing stub.
  - A durable claim is consumed before publication. Partial failures require reconciliation.
  - Supports only the initial schema-two to schema-three stopped reference handoff.
  - Does not start a guest, release an application writer, rebuild or restore data.
options:
  action:
    description: Prepare, publish once, or inspect the same completed publication.
    type: str
    required: true
    choices: [prepare, publish, status]
  attachment_prepared_json:
    description: Exact canonical preparation of the completed retained attachment.
    type: str
  attachment_prepared_sha256:
    description: Separately trusted hash of that attachment preparation.
    type: str
  attachment_completion_sha256:
    description: Separately trusted hash of the completed attachment receipt.
    type: str
  prepared_json:
    description: Exact retained canonical owner publication preparation.
    type: str
  prepared_sha256:
    description: Separately trusted hash of this owner publication preparation.
    type: str
  guard_python:
    description: Exact immutable standalone owner guard source; its supported hash is enforced.
    type: str
  allow_changes:
    description: Permit publication metadata writes outside check mode.
    type: bool
    default: false
author:
  - Luis Lobo Borobia
attributes:
  check_mode:
    support: partial
    details: Reobserves the original stopped attachment without creating publication or owner files.
  diff_mode:
    support: none
"""

EXAMPLES = r"""
- name: Prepare the initial stopped ownership handoff
  cmdmesh.proxmox.lxc_persistence_owner_publish:
    action: prepare
    attachment_prepared_json: "{{ attachment_json }}"
    attachment_prepared_sha256: "{{ attachment_sha256 }}"
    attachment_completion_sha256: "{{ attachment_completion_sha256 }}"
    guard_python: "{{ lookup('file', owner_guard_source, rstrip=false) }}"
  register: preparation

- name: Recheck the exact proposed handoff without changing files
  cmdmesh.proxmox.lxc_persistence_owner_publish:
    action: publish
    prepared_json: "{{ preparation.prepared_json }}"
    prepared_sha256: "{{ preparation.prepared_sha256 }}"
    guard_python: "{{ lookup('file', owner_guard_source, rstrip=false) }}"
  check_mode: true
"""

RETURN = r"""
owner_publication_verified:
  description: The initial stopped ownership handoff and retained denial files passed checks.
  type: bool
  returned: always
boot_verified:
  description: Always false; every managed start remains denied.
  type: bool
  returned: always
rebuild_verified:
  description: Always false; no writer is started.
  type: bool
  returned: always
restore_verified:
  description: Always false; no independent restore is performed.
  type: bool
  returned: always
mutation_attempted:
  description: Whether publication files may have been written.
  type: bool
  returned: always
effects_may_exist:
  description: An apply failure can leave a consumed claim and partially published metadata.
  type: bool
  returned: failure
"""

import re

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_publish as publish,
    persistence_state as state,
)


def execute(
    action,
    attachment_prepared_json=None,
    attachment_prepared_sha256=None,
    attachment_completion_sha256=None,
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
        "owner_publication_verified": False,
        **publish.FLAGS,
    }
    state.require(
        action in {"prepare", "publish", "status"},
        "persistence-owner-publish-operation-unsupported",
    )
    if action == "publish" and not check_mode and not allow_changes:
        raise state.PersistenceError("persistence-owner-publish-change-disabled")
    if action == "prepare":
        raw = state.canonical(
            publish.prepare(
                attachment_prepared_json.encode(),
                attachment_prepared_sha256,
                attachment_completion_sha256,
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
            **publish.status(raw, prepared_sha256),
            "assessment": "observed",
        }
    guard_raw = guard_python.encode()
    if check_mode:
        guard = publish.load_guard_source(guard_raw)
        frozen = publish.load_prepared(raw, prepared_sha256, guard)
        fresh = publish.prepare(
            state.canonical(frozen["attachment_prepared"]),
            frozen["attachment_sha256"],
            frozen["attachment_completion_sha256"],
            guard_raw,
        )
        state.require(
            state.canonical(fresh) == raw, "persistence-owner-publish-preflight-changed"
        )
        return {
            **base,
            "assessment": "publication-preflight-only",
            "changed": True,
            "would_change": True,
            "prepared_sha256": prepared_sha256,
        }
    return {
        **publish.apply(raw, prepared_sha256, guard_raw),
        "changed": True,
        "mutation_attempted": True,
        "command_outcome": "succeeded",
        "assessment": "publication-postchecked",
    }


def failure(error, action, check_mode, allow_changes):
    possible = action == "publish" and not check_mode and allow_changes
    code = getattr(error, "code", None)
    if type(code) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,120}", code) is None:
        code = "persistence-owner-publish-refused"
    return {
        "msg": "Publication refused or needs reconciliation. Preserve the consumed claim, archives and every start denial. Do not retry, remove denials or start either guest.",
        "error_code": code,
        "changed": possible,
        "mutation_attempted": possible,
        "effects_may_exist": possible,
        "command_outcome": "unknown" if possible else "not-dispatched",
        "owner_publication_verified": False,
        **publish.FLAGS,
    }


def main():
    from ansible.module_utils.basic import AnsibleModule

    keys = (
        "attachment_prepared_json",
        "attachment_prepared_sha256",
        "attachment_completion_sha256",
        "prepared_json",
        "prepared_sha256",
        "guard_python",
    )
    module = AnsibleModule(
        argument_spec={
            "action": {
                "type": "str",
                "required": True,
                "choices": ["prepare", "publish", "status"],
            },
            **{key: {"type": "str", "no_log": True} for key in keys},
            "allow_changes": {"type": "bool", "default": False},
        },
        required_if=[
            ("action", "prepare", [*keys[:3], "guard_python"]),
            ("action", "publish", ["prepared_json", "prepared_sha256", "guard_python"]),
            ("action", "status", ["prepared_json", "prepared_sha256"]),
        ],
        required_together=[keys[:3], ("prepared_json", "prepared_sha256")],
        mutually_exclusive=[("attachment_prepared_json", "prepared_json")],
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
