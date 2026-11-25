#!/usr/bin/python
"""Ansible boundary for the claimed reference application lifecycle test."""

DOCUMENTATION = r"""
---
module: lxc_persistence_writer_trial
short_description: Qualify one retained reference application write and stopped checkpoint
description:
  - Prepares from accepted OS-start evidence without creating a claim.
  - An allowed run claims one start, authenticated append, read-back and stop.
  - Requires the original credential and records, then consistent post-stop SQL.
  - Check mode repeats read-only preflight and never starts or writes the application.
  - Unknown outcomes retain their claim; containment never converts failure into success.
  - Status requires the separately trusted completion hash and performs no lifecycle action.
options:
  action:
    description: Operation to perform.
    type: str
    choices: [prepare, run, status]
    required: true
  boot_json:
    description: Canonical accepted boot preparation; required for prepare.
    type: str
  boot_sha256:
    description: Separately trusted boot preparation hash; required for prepare.
    type: str
  boot_completion_sha256:
    description: Separately trusted original boot completion hash; required for prepare.
    type: str
  nonce:
    description: Predeclared 32-character hexadecimal operation nonce; required for prepare.
    type: str
  prepared_json:
    description: Canonical application-trial preparation; required for run and status.
    type: str
  prepared_sha256:
    description: Separately trusted preparation hash; required for run and status.
    type: str
  completion_sha256:
    description: Successful run completion hash retained by the trusted controller; required for status.
    type: str
  allow_changes:
    description: Explicit permission for an actual run. Check mode stays read-only.
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
- name: Prepare one owned reference application test
  cmdmesh.proxmox.lxc_persistence_writer_trial:
    action: prepare
    boot_json: "{{ accepted_boot_preparation_json }}"
    boot_sha256: "{{ trusted_boot_preparation_sha256 }}"
    boot_completion_sha256: "{{ trusted_boot_completion_sha256 }}"
    nonce: "{{ declared_reference_nonce }}"
  register: application_preparation

- name: Run the reviewed reference test when mutations are authorized
  cmdmesh.proxmox.lxc_persistence_writer_trial:
    action: run
    prepared_json: "{{ application_preparation.prepared_json }}"
    prepared_sha256: "{{ application_preparation.prepared_sha256 }}"
    allow_changes: "{{ operator_mutations_allowed }}"
  register: application_qualification

- name: Check the new stopped tuple from the trusted successful receipt
  cmdmesh.proxmox.lxc_persistence_writer_trial:
    action: status
    prepared_json: "{{ application_preparation.prepared_json }}"
    prepared_sha256: "{{ application_preparation.prepared_sha256 }}"
    completion_sha256: "{{ (application_qualification.result_json | from_json).completion_sha256 }}"
"""

RETURN = r"""
prepared_json:
  description: Canonical immutable application-test preparation.
  type: str
  returned: successful prepare
prepared_sha256:
  description: Exact SHA-256 of prepared_json.
  type: str
  returned: successful prepare and check
result_json:
  description: Canonical successful run or read-only status evidence, without credentials or record values.
  type: str
  returned: successful run or status
result_sha256:
  description: Exact SHA-256 of result_json. The native completion hash is inside result_json.
  type: str
  returned: successful run or status
rebuild_verified:
  description: A claimed write/read-back/stop/SQL sequence is qualified; false for preparation or check.
  type: bool
  returned: always
application_write_verified:
  description: The original data plus the single claimed nonce are qualified.
  type: bool
  returned: always
application_quiesced:
  description: The successful run or status proves the writer stopped and SQL checked under EX.
  type: bool
  returned: always
mutation_attempted:
  description: True for an actual successful run, false for read-only operations.
  type: bool
  returned: always
"""

import re

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_state as state,
    persistence_writer_trial as trial,
    persistence_writer_execution as execution,
)

FLAGS = {
    "mutation_attempted": False,
    "application_quiesced": False,
    "application_write_verified": False,
    "rebuild_verified": False,
    "boot_verified": False,
    "restore_verified": False,
    "backup_verified": False,
}


def required(*values):
    state.require(
        all(type(value) is str and value for value in values),
        "persistence-writer-trial-required-arguments",
    )


def execute(
    action,
    *,
    boot_json=None,
    boot_sha256=None,
    boot_completion_sha256=None,
    nonce=None,
    prepared_json=None,
    prepared_sha256=None,
    completion_sha256=None,
    allow_changes=False,
    check_mode=False
):
    state.require(
        action in {"prepare", "run", "status"}, "persistence-writer-trial-action"
    )
    if action == "prepare":
        required(boot_json, boot_sha256, boot_completion_sha256, nonce)
        prepared = trial.prepare(
            boot_json.encode(), boot_sha256, boot_completion_sha256, nonce
        )
        raw = state.canonical(prepared)
        return {
            "changed": False,
            **FLAGS,
            "prepared_json": raw.decode(),
            "prepared_sha256": state.sha256(raw),
        }
    required(prepared_json, prepared_sha256)
    raw = prepared_json.encode()
    if action == "run":
        if check_mode:
            execution.preflight(raw, prepared_sha256)
            return {
                "changed": True,
                "proposed": True,
                **FLAGS,
                "prepared_sha256": prepared_sha256,
            }
        state.require(
            allow_changes is True, "persistence-writer-trial-approval-required"
        )
        result = execution.run(raw, prepared_sha256)
    else:
        required(completion_sha256)
        result = execution.status(raw, prepared_sha256, completion_sha256)
    encoded = state.canonical(result)
    return {
        "changed": action == "run",
        **{name: result[name] for name in FLAGS},
        "result_json": encoded.decode(),
        "result_sha256": state.sha256(encoded),
    }


def failure(error, action, check_mode, allow_changes):
    code = getattr(error, "code", None)
    if type(code) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,120}", code) is None:
        code = "persistence-writer-trial-refused"
    return {
        "msg": "Application trial refused. Preserve its claim and journal; do not replay an unknown start, write or stop.",
        "error_code": code,
        "changed": False,
        **FLAGS,
        "effects_may_exist": action == "run"
        and not check_mode
        and allow_changes is True,
    }


def main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec={
            "action": {
                "type": "str",
                "required": True,
                "choices": ["prepare", "run", "status"],
            },
            "boot_json": {"type": "str", "no_log": True},
            "boot_sha256": {"type": "str"},
            "boot_completion_sha256": {"type": "str"},
            "nonce": {"type": "str", "no_log": True},
            "prepared_json": {"type": "str", "no_log": True},
            "prepared_sha256": {"type": "str"},
            "completion_sha256": {"type": "str"},
            "allow_changes": {"type": "bool", "default": False},
        },
        supports_check_mode=True,
    )
    module.no_log_values.clear()
    invocation = {
        "module_args": {
            "action": module.params["action"],
            "allow_changes": module.params["allow_changes"],
            "payload": "withheld",
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
