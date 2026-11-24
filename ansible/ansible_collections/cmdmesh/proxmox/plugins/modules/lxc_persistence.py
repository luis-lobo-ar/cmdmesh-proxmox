#!/usr/bin/python
"""Thin Ansible boundary for the fixed reference persistence operations."""

DOCUMENTATION = r"""
---
module: lxc_persistence
short_description: Inspect, prepare or back up the fixed reference LXC
description:
  - Uses the fixed source observer and journaled backup action.
  - Never stops or starts guests, initializes data, repairs ownership or restores.
  - A backup requires a separately retained canonical intent/hash and explicit changes permission.
options:
  action:
    description: One finite operation on the declared host.
    type: str
    required: true
    choices: [inspect, prepare_backup, backup]
  source_request:
    description: Version-1 source observer request, required for inspect.
    type: dict
  backup_request:
    description: Version-1 fixed backup request, required for prepare_backup.
    type: dict
  prepared_json:
    description: Exact canonical JSON returned by preparation, required for backup.
    type: str
  prepared_sha256:
    description: SHA-256 retained separately from the managed host and backup store.
    type: str
  allow_changes:
    description: Explicit permission for backup dispatch, not needed for check mode.
    type: bool
    default: false
author:
  - Luis Lobo Borobia
attributes:
  check_mode:
    support: partial
    details: Backup check mode repeats source and recipient checks without runtime, snapshot or NAS writes.
  diff_mode:
    support: none
"""

EXAMPLES = r"""
- name: Observe the declared reference source
  cmdmesh.proxmox.lxc_persistence:
    action: inspect
    source_request: "{{ cmdmesh_persistence_source }}"

- name: Prepare a backup of an already stopped reference source
  cmdmesh.proxmox.lxc_persistence:
    action: prepare_backup
    backup_request: "{{ cmdmesh_persistence_backup }}"
  register: prepared

# Retain/review the preparation on the trusted controller before execution.
- name: Check the retained source intent without mutations
  cmdmesh.proxmox.lxc_persistence:
    action: backup
    prepared_json: "{{ cmdmesh_retained_prepared_json }}"
    prepared_sha256: "{{ cmdmesh_retained_prepared_sha256 }}"
  check_mode: true

- name: Execute the retained approved intent once
  cmdmesh.proxmox.lxc_persistence:
    action: backup
    prepared_json: "{{ cmdmesh_retained_prepared_json }}"
    prepared_sha256: "{{ cmdmesh_retained_prepared_sha256 }}"
    allow_changes: true
"""

RETURN = r"""
assessment:
  description: Observed, prepared, source-preflight-only or backup-postchecked.
  type: str
  returned: success
mutation_attempted:
  description: Whether mutation was dispatched or may have been dispatched on failure.
  type: bool
  returned: always
backup_verified:
  description: Source/artifact backup checks passed; does not certify restore or immutable storage.
  type: bool
  returned: always
prepared_json:
  description: Canonical preparation bytes as UTF-8 text; retain exactly without reformatting.
  type: str
  returned: preparation
prepared_sha256:
  description: Trusted-controller hash of those exact bytes.
  type: str
  returned: preparation
effects_may_exist:
  description: Conservatively true after a permitted backup failure; inspect the consumed journal before further action.
  type: bool
  returned: failure
"""

import re

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_backup as backup,
)
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_observe as observe,
)
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_state as state,
)


def execute(
    action,
    source_request=None,
    backup_request=None,
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
        "backup_verified": False,
    }
    if action == "inspect":
        return {
            **base,
            "assessment": "observed",
            "observed": observe.observe(source_request),
        }
    if action == "prepare_backup":
        prepared = backup.prepare_backup(backup_request)
        raw = state.canonical(prepared)
        return {
            **base,
            "assessment": "prepared",
            "prepared": prepared,
            "prepared_json": raw.decode(),
            "prepared_sha256": state.sha256(raw),
        }
    state.require(action == "backup", "persistence-operation-unsupported")
    if not check_mode and not allow_changes:
        raise state.PersistenceError("persistence-backup-change-disabled")
    raw = prepared_json.encode("utf-8")
    if check_mode:
        frozen = backup.load_prepared(raw, prepared_sha256)
        fresh = backup.prepare_backup(frozen["request"])
        state.require(
            state.canonical(fresh) == state.canonical(frozen),
            "persistence-backup-source-changed",
        )
        return {
            **base,
            "changed": True,
            "would_change": True,
            "assessment": "source-preflight-only",
            "prepared_sha256": prepared_sha256,
        }
    result = backup.execute_backup(raw, prepared_sha256)
    return {
        **result,
        "changed": True,
        "mutation_attempted": True,
        "command_outcome": "succeeded",
        "assessment": "backup-postchecked",
    }


def failure(error, action, check_mode, allow_changes):
    possible = action == "backup" and not check_mode and allow_changes
    code = getattr(error, "code", None)
    if type(code) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,120}", code) is None:
        code = "persistence-operation-refused"
    return {
        "msg": "Persistence operation refused or needs reconciliation. Do not repeat a consumed intent; inspect its journal.",
        "error_code": code,
        "changed": possible,
        "mutation_attempted": possible,
        "effects_may_exist": possible,
        "command_outcome": "unknown" if possible else "not-dispatched",
        "backup_verified": False,
    }


def main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec={
            "action": {
                "type": "str",
                "required": True,
                "choices": ["inspect", "prepare_backup", "backup"],
            },
            "source_request": {"type": "dict", "no_log": True},
            "backup_request": {"type": "dict", "no_log": True},
            "prepared_json": {"type": "str", "no_log": True},
            "prepared_sha256": {"type": "str", "no_log": True},
            "allow_changes": {"type": "bool", "default": False},
        },
        required_if=[
            ("action", "inspect", ["source_request"]),
            ("action", "prepare_backup", ["backup_request"]),
            ("action", "backup", ["prepared_json", "prepared_sha256"]),
        ],
        required_together=[("prepared_json", "prepared_sha256")],
        mutually_exclusive=[("source_request", "backup_request", "prepared_json")],
        supports_check_mode=True,
    )
    # Protect framework validation failures first, then explicitly withhold the
    # invocation so value-based censoring cannot corrupt safe returned hashes.
    module.no_log_values.clear()
    invocation = {
        "module_args": {
            "action": module.params["action"],
            "allow_changes": module.params["allow_changes"],
            **{
                key: "withheld"
                for key in (
                    "source_request",
                    "backup_request",
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
