#!/usr/bin/python
"""Finite same-owner OS boundary; no resolution or hidden retry."""

DOCUMENTATION = r"""
---
module: lxc_persistence_owner_os
short_description: Initialize, prepare, perform or observe an ordered same-owner OS action
description:
  - Reconstructs portable application authority from externally trusted writer evidence.
  - Initialization writes metadata only. Transition issues one ordered native request.
  - Check mode revalidates real preconditions without metadata writes, claims or POST.
  - Returned candidate heads need external acceptance. Node-discovered heads are never authority.
  - No resolver is exposed; native-worker fencing remains a separate contract.
options:
  action:
    description: Finite operation. Status is completed-only and read-only.
    type: str
    required: true
    choices: [initialize, prepare, transition, status]
  prepared_json:
    description: Canonical accepted writer preparation, not an OS transition preparation.
    type: str
    required: true
  prepared_sha256:
    description: Externally trusted writer preparation hash.
    type: str
    required: true
  completion_json:
    description: Canonical successful writer completion, never a failed node candidate.
    type: str
    required: true
  completion_sha256:
    description: Externally trusted successful writer completion hash.
    type: str
    required: true
  journal:
    description: Exact thirteen original writer journal filenames to raw canonical JSON strings.
    type: dict
    required: true
  head_sha256:
    description: Proposed genesis for initialize, accepted predecessor for prepare, accepted returned head for status.
    type: str
  kind:
    description: Shutdown or resume; only valid for prepare.
    type: str
    choices: [shutdown, resume]
  transition_prepared_json:
    description: Canonical OS preparation returned by prepare. Required for transition and status.
    type: str
  transition_prepared_sha256:
    description: Externally trusted OS preparation hash, paired with transition_prepared_json.
    type: str
  prior_runtime:
    description: Accepted prior running frame for stopped-state fencing; only prepare and status.
    type: dict
  allow_mutation:
    description: Explicit permission for normal-mode initialize or transition. Defaults to false.
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
- name: Check a previously prepared same-owner shutdown without a request
  cmdmesh.proxmox.lxc_persistence_owner_os:
    action: transition
    prepared_json: "{{ accepted_writer_prepared_json }}"
    prepared_sha256: "{{ accepted_writer_prepared_sha256 }}"
    completion_json: "{{ accepted_writer_completion_json }}"
    completion_sha256: "{{ accepted_writer_completion_sha256 }}"
    journal: "{{ accepted_writer_raw13 }}"
    transition_prepared_json: "{{ accepted_os_prepared_json }}"
    transition_prepared_sha256: "{{ accepted_os_prepared_sha256 }}"
  check_mode: true
"""
RETURN = r"""
os_transition_verified:
  description: True only after transition or completed status full native/current proof, never a dry run.
  type: bool
  returned: always
metadata_initialized:
  description: True only after normal-mode initialization succeeds.
  type: bool
  returned: always
mutation_attempted:
  description: False on read-only and dry-run paths. Conservative true if an admitted mutator raises.
  type: bool
  returned: always
result_json:
  description: Canonical successful SDK result, without credential or record values.
  type: str
  returned: success except prepare
result_sha256:
  description: Exact SHA-256 of result_json.
  type: str
  returned: success except prepare
"""
import re
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_transition as sdk,
)

state = sdk.state
FLAGS = {
    "os_transition_verified": False,
    "metadata_initialized": False,
    "application_quiesced": False,
    "application_write_verified": False,
    "backup_verified": False,
    "restore_verified": False,
    "rebuild_verified": False,
    "boot_verified": False,
}


def require(value):
    state.require(value, "persistence-owner-os-arguments")


def _raw(value, limit):
    require(type(value) is str)
    raw = value.encode()
    require(0 < len(raw) <= limit)
    return raw


def _checkpoint(
    prepared_json, prepared_sha256, completion_json, completion_sha256, journal
):
    prepared = _raw(prepared_json, 8388608)
    completion = _raw(completion_json, 4194304)
    require(type(journal) is dict and len(journal) == 13)
    require(all(type(name) is str for name in journal))
    records = {name: _raw(value, 4194304) for name, value in journal.items()}
    require(sum(map(len, records.values())) <= 16777216)
    return sdk.current.checkpoint_codec.load_writer_checkpoint(
        prepared_raw=prepared,
        prepared_sha256=prepared_sha256,
        completion_raw=completion,
        completion_sha256=completion_sha256,
        records=records,
    )


def _result(value):
    raw = state.canonical(value)
    require(len(raw) <= 33554432)
    return {"result_json": raw.decode(), "result_sha256": state.sha256(raw)}


def execute(
    action,
    prepared_json,
    prepared_sha256,
    completion_json,
    completion_sha256,
    journal,
    head_sha256=None,
    kind=None,
    transition_prepared_json=None,
    transition_prepared_sha256=None,
    prior_runtime=None,
    allow_mutation=False,
    *,
    check_mode=False
):
    require(
        type(action) is str
        and action in {"initialize", "prepare", "transition", "status"}
    )
    require(type(allow_mutation) is bool and type(check_mode) is bool)
    require(prior_runtime is None or type(prior_runtime) is dict)
    require(prior_runtime is None or len(state.canonical(prior_runtime)) <= 4194304)
    if action in {"initialize", "prepare", "status"}:
        state.digest(head_sha256)
    else:
        require(head_sha256 is None)
    require(
        (action == "prepare" and type(kind) is str and kind in {"shutdown", "resume"})
        or (action != "prepare" and kind is None)
    )
    if action in {"transition", "status"}:
        transition_raw = _raw(transition_prepared_json, 8388608)
        state.digest(transition_prepared_sha256)
    else:
        require(transition_prepared_json is None and transition_prepared_sha256 is None)
        transition_raw = None
    require(action in {"prepare", "status"} or prior_runtime is None)
    require(action in {"initialize", "transition"} or allow_mutation is False)
    if action in {"initialize", "transition"} and not check_mode:
        require(allow_mutation is True)
    checkpoint = _checkpoint(
        prepared_json, prepared_sha256, completion_json, completion_sha256, journal
    )
    base = {
        "changed": False,
        "mutation_attempted": False,
        "effects_may_exist": False,
        "command_outcome": "not-dispatched",
        "checkpoint_sha256": sdk.digest(checkpoint),
        **FLAGS,
    }
    if action == "prepare":
        value = sdk.prepare(checkpoint, head_sha256, kind, prior_runtime)
        raw = state.canonical(value)
        require(len(raw) <= 8388608)
        return {
            **base,
            "assessment": "prepared",
            "application_quiesced": True,
            "transition_prepared_json": raw.decode(),
            "transition_prepared_sha256": state.sha256(raw),
        }
    if action == "status":
        value = sdk.status(
            checkpoint,
            transition_raw,
            transition_prepared_sha256,
            head_sha256,
            prior_runtime=prior_runtime,
        )
        return {
            **base,
            **value,
            **_result(value),
            "changed": False,
            "mutation_attempted": False,
            "effects_may_exist": False,
            "command_outcome": "not-dispatched",
            "assessment": "observed",
        }
    if check_mode:
        value = (
            sdk.inspect_initialization(checkpoint, head_sha256)
            if action == "initialize"
            else sdk.inspect_transition(
                checkpoint, transition_raw, transition_prepared_sha256
            )
        )
        return {
            **base,
            **_result(value),
            "assessment": action + "-preflight-only",
            "would_change": value["would_change"],
            "changed": value["would_change"],
            "application_quiesced": True,
        }
    try:
        if action == "initialize":
            value = sdk.initialize(checkpoint, head_sha256)
            return {
                **base,
                **_result(value),
                "head_sha256": value["head_sha256"],
                "changed": value["changed"],
                "mutation_attempted": True,
                "metadata_initialized": True,
                "application_quiesced": True,
                "assessment": "metadata-initialized",
            }
        value = sdk.operate(checkpoint, transition_raw, transition_prepared_sha256)
        return {
            **base,
            **value,
            **_result(value),
            "changed": True,
            "effects_may_exist": False,
            "mutation_attempted": True,
            "command_outcome": "succeeded",
            "assessment": "transition-postchecked",
        }
    except Exception as error:
        error._owner_os_possible_effects = True
        error._owner_os_native_possible = action == "transition"
        raise


def failure(error):
    possible = getattr(error, "_owner_os_possible_effects", False) is True
    native_possible = (
        possible and getattr(error, "_owner_os_native_possible", False) is True
    )
    code = getattr(error, "code", None)
    if type(code) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,120}", code) is None:
        code = "persistence-owner-os-refused"
    return {
        "msg": "Owner OS action refused or uncertain. Preserve accepted heads, claims and raw history. Do not retry an uncertain request or adopt a node candidate.",
        "error_code": code,
        "changed": possible,
        "mutation_attempted": possible,
        "effects_may_exist": possible,
        "command_outcome": "unknown" if native_possible else "not-dispatched",
        **FLAGS,
    }


def main():
    from ansible.module_utils.basic import AnsibleModule

    common = (
        "prepared_json",
        "prepared_sha256",
        "completion_json",
        "completion_sha256",
    )
    module = AnsibleModule(
        argument_spec={
            "action": {
                "type": "str",
                "required": True,
                "choices": ["initialize", "prepare", "transition", "status"],
                "no_log": True,
            },
            **{
                name: {"type": "str", "required": True, "no_log": True}
                for name in common
            },
            "journal": {"type": "dict", "required": True, "no_log": True},
            "head_sha256": {"type": "str", "no_log": True},
            "kind": {"type": "str", "choices": ["shutdown", "resume"], "no_log": True},
            "transition_prepared_json": {"type": "str", "no_log": True},
            "transition_prepared_sha256": {"type": "str", "no_log": True},
            "prior_runtime": {"type": "dict", "no_log": True},
            "allow_mutation": {"type": "bool", "default": False, "no_log": True},
        },
        required_if=[
            ("action", "initialize", ["head_sha256"]),
            ("action", "prepare", ["head_sha256", "kind"]),
            (
                "action",
                "transition",
                ["transition_prepared_json", "transition_prepared_sha256"],
            ),
            (
                "action",
                "status",
                [
                    "head_sha256",
                    "transition_prepared_json",
                    "transition_prepared_sha256",
                ],
            ),
        ],
        required_together=[("transition_prepared_json", "transition_prepared_sha256")],
        supports_check_mode=True,
    )
    module.no_log_values.clear()
    invocation = {"module_args": {name: "withheld" for name in module.params}}
    invocation["module_args"]["action"] = module.params["action"]
    invocation["module_args"]["allow_mutation"] = module.params["allow_mutation"]
    try:
        result = execute(**module.params, check_mode=module.check_mode)
    except Exception as error:
        module.fail_json(**failure(error), exception="", invocation=invocation)
    else:
        module.exit_json(**result, invocation=invocation)


if __name__ == "__main__":
    main()
