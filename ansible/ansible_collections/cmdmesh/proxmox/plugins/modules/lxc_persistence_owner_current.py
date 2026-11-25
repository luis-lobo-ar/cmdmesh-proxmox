#!/usr/bin/python
"""Read-only current-owner boundary from externally accepted writer evidence."""

DOCUMENTATION = r"""
---
module: lxc_persistence_owner_current
short_description: Check current retained-owner state against an accepted writer checkpoint
description:
  - Reconstructs the checkpoint from canonical raw evidence and separately trusted hashes.
  - Checks current host, guest, ownership, root, credentials and retained application state.
  - Checks stopped native state before retained reads in stopped phase.
  - Holds existing pair, native configuration and application leases.
  - Creates no locks, claims or operation heads and performs no guest lifecycle action.
options:
  prepared_json:
    description: Canonical preparation from the accepted writer trial.
    type: str
    required: true
  prepared_sha256:
    description: Externally trusted preparation hash.
    type: str
    required: true
  completion_json:
    description: Canonical completion from the successful writer SDK return.
    type: str
    required: true
  completion_sha256:
    description: Externally trusted successful completion hash, never a failed target candidate.
    type: str
    required: true
  journal:
    description: All thirteen original journal filenames mapped to canonical raw JSON strings.
    type: dict
    required: true
  phase:
    description: Required current state. A stopped guest does not receive fresh image-content verification.
    type: str
    choices: [os_quiesced, stopped]
    default: os_quiesced
  prior_runtime:
    description: Externally accepted last running frame for prior-init fencing. Defaults to the writer frame.
    type: dict
author:
  - Luis Lobo Borobia
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
"""

EXAMPLES = r"""
- name: Check the current running owner without a lifecycle action
  cmdmesh.proxmox.lxc_persistence_owner_current:
    prepared_json: "{{ accepted_writer_preparation_json }}"
    prepared_sha256: "{{ trusted_writer_preparation_sha256 }}"
    completion_json: "{{ accepted_writer_completion_json }}"
    completion_sha256: "{{ trusted_writer_completion_sha256 }}"
    journal: "{{ accepted_writer_raw_journal }}"
    phase: os_quiesced
  register: current_owner

- name: Require consistent retained data without a write or boot claim
  ansible.builtin.assert:
    that:
      - current_owner.owner_current_verified
      - current_owner.application_quiesced
      - current_owner.guest_image_verified
      - not current_owner.mutation_attempted
      - not current_owner.boot_verified
      - not current_owner.restore_verified
"""

RETURN = r"""
owner_current_verified:
  description: Current admission and accepted portable application identity passed.
  type: bool
  returned: always
application_quiesced:
  description: Application exclusion and consistent SQL checks passed.
  type: bool
  returned: always
guest_image_verified:
  description: Fresh running image-content checks passed. Always false in stopped phase.
  type: bool
  returned: always
checkpoint_sha256:
  description: Hash of the validated canonical owner checkpoint.
  type: str
  returned: success
result_json:
  description: Canonical current evidence without credentials or record values.
  type: str
  returned: success
result_sha256:
  description: Exact SHA-256 of result_json.
  type: str
  returned: success
mutation_attempted:
  description: Always false. No application or guest lifecycle action is performed.
  type: bool
  returned: always
"""

import re

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_current as current,
)

state = current.state


def require(value):
    state.require(value, "persistence-owner-current-arguments")


def _raw(value, limit):
    require(type(value) is str)
    raw = value.encode()
    require(0 < len(raw) <= limit)
    return raw


def execute(
    prepared_json,
    prepared_sha256,
    completion_json,
    completion_sha256,
    journal,
    phase="os_quiesced",
    prior_runtime=None,
    *,
    check_mode=False,
):
    require(type(phase) is str and phase in {"os_quiesced", "stopped"})
    require(
        type(check_mode) is bool
        and (prior_runtime is None or type(prior_runtime) is dict)
    )
    require(prior_runtime is None or len(state.canonical(prior_runtime)) <= 4194304)
    prepared = _raw(prepared_json, 8388608)
    completion = _raw(completion_json, 4194304)
    require(type(journal) is dict and len(journal) == 13)
    records = {name: _raw(value, 4194304) for name, value in journal.items()}
    require(sum(map(len, records.values())) <= 16777216)
    checkpoint = current.checkpoint_codec.load_writer_checkpoint(
        prepared_raw=prepared,
        prepared_sha256=prepared_sha256,
        completion_raw=completion,
        completion_sha256=completion_sha256,
        records=records,
    )
    observed = current.collect(checkpoint, phase=phase, prior_runtime=prior_runtime)
    raw = state.canonical(observed)
    require(len(raw) <= 4194304)
    return {
        "changed": False,
        **current.runtime.FLAGS,
        "owner_current_verified": True,
        "application_quiesced": True,
        "guest_image_verified": observed["guest_image_verified"],
        "checkpoint_sha256": state.sha256(state.canonical(checkpoint)),
        "result_json": raw.decode(),
        "result_sha256": state.sha256(raw),
    }


def failure(error):
    code = getattr(error, "code", None)
    if type(code) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,120}", code) is None:
        code = "persistence-owner-current-refused"
    return {
        "msg": "Current-owner inspection refused. Preserve accepted evidence and operation history; no repair or lifecycle action was performed.",
        "error_code": code,
        "changed": False,
        "effects_may_exist": False,
        **current.runtime.FLAGS,
        "owner_current_verified": False,
        "application_quiesced": False,
        "guest_image_verified": False,
    }


def main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec={
            name: {"type": "str", "required": True, "no_log": True}
            for name in (
                "prepared_json",
                "prepared_sha256",
                "completion_json",
                "completion_sha256",
            )
        }
        | {
            "journal": {"type": "dict", "required": True, "no_log": True},
            "phase": {
                "type": "str",
                "choices": ["os_quiesced", "stopped"],
                "default": "os_quiesced",
                "no_log": True,
            },
            "prior_runtime": {"type": "dict", "no_log": True},
        },
        supports_check_mode=True,
    )
    module.no_log_values.clear()
    invocation = {"module_args": {name: "withheld" for name in module.params}}
    invocation["module_args"]["phase"] = module.params["phase"]
    try:
        result = execute(**module.params, check_mode=module.check_mode)
    except Exception as error:
        module.fail_json(**failure(error), exception="", invocation=invocation)
    else:
        module.exit_json(**result, invocation=invocation)


if __name__ == "__main__":
    main()
