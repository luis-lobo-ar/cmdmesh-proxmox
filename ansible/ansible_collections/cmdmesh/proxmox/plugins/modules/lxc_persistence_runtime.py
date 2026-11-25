#!/usr/bin/python
"""Read-only Ansible boundary for the retained reference runtime."""

DOCUMENTATION = r"""
---
module: lxc_persistence_runtime
short_description: Inspect a running reference LXC and its explicit application phase
description:
  - Checks explicit kernel, guest bind, image, ownership and reference evidence.
  - Holds the retained-pair mutex and both native configuration read leases.
  - Takes the real application lock before consistent SQL in os_quiesced.
  - Authenticates a peer-bound read without application EX or host SQL in active_writer.
  - Supports only the fixed reference profile.
  - Does not start, stop, configure, repair, import, restore or write application data.
options:
  source_request:
    description: Exact schema-three source request with the corrected known guard.
    type: dict
    required: true
  image_profile:
    description: Pinned helper sources, stopped root/config binding and retained account baseline.
    type: dict
    required: true
  phase:
    description: Explicit application state required by the inspection.
    type: str
    choices: [os_quiesced, active_writer]
    default: os_quiesced
author:
  - Luis Lobo Borobia
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
"""

EXAMPLES = r"""
- name: Inspect the running OS before releasing the application writer
  cmdmesh.proxmox.lxc_persistence_runtime:
    source_request: "{{ stopped_owner_source_request }}"
    image_profile: "{{ retained_reference_image_profile }}"
    phase: os_quiesced
  register: runtime

- name: Inspect an already active writer with its retained credential
  cmdmesh.proxmox.lxc_persistence_runtime:
    source_request: "{{ stopped_owner_source_request }}"
    image_profile: "{{ retained_reference_image_profile }}"
    phase: active_writer
  register: writer

- name: Require observation without lifecycle or recovery claims
  ansible.builtin.assert:
    that:
      - runtime.os_runtime_verified
      - runtime.application_quiesced
      - not runtime.mutation_attempted
      - not runtime.boot_verified
      - not runtime.rebuild_verified
      - not runtime.restore_verified
"""

RETURN = r"""
observed:
  description: Admitted runtime plus consistent SQL or authenticated application read facts.
  type: dict
  returned: success
os_runtime_verified:
  description: The selected running OS and application-phase checks passed.
  type: bool
  returned: always
application_quiesced:
  description: The service is inactive and SQL was inspected under the real application lock.
  type: bool
  returned: always
application_read_verified:
  description: An authenticated peer-bound read passed in active_writer; false for os_quiesced.
  type: bool
  returned: always
mutation_attempted:
  description: Always false; this module only observes.
  type: bool
  returned: always
boot_verified:
  description: Always false; no native start operation was performed.
  type: bool
  returned: always
rebuild_verified:
  description: Always false; no claimed write, stop or post-write SQL checkpoint is performed.
  type: bool
  returned: always
restore_verified:
  description: Always false; no independent recovery is performed.
  type: bool
  returned: always
"""

import re

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_retained_runtime as runtime,
    persistence_writer_runtime as active,
)


def execute(source_request, image_profile, phase="os_quiesced", *, check_mode=False):
    runtime.require(phase in ("os_quiesced", "active_writer"), "phase-unsupported")
    observed = (
        runtime.collect(source_request, image_profile, phase=phase)
        if phase == "os_quiesced"
        else active.collect(source_request, image_profile)
    )
    return {
        "changed": False,
        **runtime.FLAGS,
        "observed": observed,
        "os_runtime_verified": observed["os_runtime_verified"],
        "application_quiesced": observed["application_quiesced"],
        "application_read_verified": observed.get("application_read_verified", False),
    }


def failure(error):
    code = getattr(error, "code", None)
    if type(code) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,120}", code) is None:
        code = "persistence-retained-runtime-refused"
    return {
        "msg": "Retained runtime inspection refused. Preserve ownership and start controls; this inspection performs no repair.",
        "error_code": code,
        "changed": False,
        "effects_may_exist": False,
        "os_runtime_verified": False,
        "application_quiesced": False,
        "application_read_verified": False,
        **runtime.FLAGS,
    }


def main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec={
            "source_request": {"type": "dict", "required": True, "no_log": True},
            "image_profile": {"type": "dict", "required": True, "no_log": True},
            "phase": {
                "type": "str",
                "choices": ["os_quiesced", "active_writer"],
                "default": "os_quiesced",
            },
        },
        supports_check_mode=True,
    )
    module.no_log_values.clear()
    invocation = {
        "module_args": {
            "source_request": "withheld",
            "image_profile": "withheld",
            "phase": module.params["phase"],
        }
    }
    try:
        result = execute(**module.params, check_mode=module.check_mode)
    except Exception as error:
        module.fail_json(**failure(error), exception="", invocation=invocation)
    else:
        module.exit_json(**result, invocation=invocation)


if __name__ == "__main__":
    main()
