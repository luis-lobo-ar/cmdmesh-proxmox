#!/usr/bin/python
"""Read-only Ansible boundary for the retained reference runtime."""

DOCUMENTATION = r"""
---
module: lxc_persistence_runtime
short_description: Inspect a running reference LXC with its application quiesced
description:
  - Checks explicit kernel, guest bind, image, ownership and reference evidence.
  - Holds the retained-pair mutex and both native configuration read leases.
  - Requires the real application lock before consistent SQLite inspection.
  - Supports the fixed reference profile and os_quiesced phase only.
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
    choices: [os_quiesced]
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
  description: Kernel, guest, retained ownership, image, reference and consistent application facts.
  type: dict
  returned: success
os_runtime_verified:
  description: All OS-running and quiesced-application checks passed at observation.
  type: bool
  returned: always
application_quiesced:
  description: The service is inactive and SQL was inspected under the real application lock.
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
  description: Always false; authenticated writer functionality is not tested.
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
)


def execute(source_request, image_profile, phase="os_quiesced", *, check_mode=False):
    runtime.require(phase == "os_quiesced", "phase-unsupported")
    observed = runtime.collect(source_request, image_profile, phase=phase)
    return {
        "changed": False,
        **runtime.FLAGS,
        "observed": observed,
        "os_runtime_verified": observed["os_runtime_verified"],
        "application_quiesced": observed["application_quiesced"],
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
                "choices": ["os_quiesced"],
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
