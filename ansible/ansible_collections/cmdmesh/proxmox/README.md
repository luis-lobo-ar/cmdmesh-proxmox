# cmdmesh.proxmox

Eleven explicit-target operational roles, with one shared refusal/approval role.
Tested locally with Ansible Core 2.19.4 and 2.20.4. Run with `--check` first. Outside check
mode, `cmdmesh_allow_changes: true` is mandatory; this is an acknowledgment, not
a substitute for reviewing targets and changes.

| Role | Inputs and limits |
| --- | --- |
| `proxmox_baseline` | Explicit `proxmox_baseline_host_packages` and `proxmox_baseline_host_absent_packages`; both default empty. Host only, no automatic LXC discovery. |
| `proxmox_apt_repositories` | Debian/Proxmox suite and archive keyring; deliberately configures no-subscription sources. Gather distribution facts and review Ceph suite compatibility first. |
| `proxmox_maintenance` | Assessment defaults on. Actual upgrades require `proxmox_maintenance_assessment_only: false`, `proxmox_maintenance_enabled: true`, `proxmox_maintenance_reboot: true`, one host and no running QEMU/LXC guests. Does not stop or migrate guests for you. |
| `proxmox_vm_backup` | Explicit `proxmox_vm_backup_jobs` list of `name`, `vmid`, `guest_type`, `keep_last`, `on_calendar`; schedules default disabled. Installed timers use per-guest locks and produce textfile metrics. No backup starts during the role; enabling timers can schedule one immediately. |
| `proxmox_nfs_backup_storage` | Explicit enable, storage ID, server/export and options. Backup-only storage; refuses unexpected lookup failures and existing non-NFS storage. New registrations require an absent default mountpoint. Optional `proxmox_nfs_backup_storage_create_only: true` refuses any existing ID before package changes. No destructive replacement. |
| `proxmox_nfs_backup_create` | One-target create-only wrapper, introduced in collection 0.2.2. A missing role refuses resolution on older collections; false create-only policy refuses before the base role. |
| `proxmox_lxc_resources` | Explicit `proxmox_lxc_resources_guests`, node and guest identities, Ansible lifecycle ownership; optional guest `proxmox_lxc_memory_mb`/`proxmox_lxc_swap_mb`. Growth-only, unchanged values cause no `pct set`. |
| `proxmox_lxc_storage` | Explicit `proxmox_lxc_storage_guests`, ownership and guest `proxmox_lxc_rootfs_size_gb`. Requires a readable GiB rootfs size; rejects shrink/ambiguous config. |
| `proxmox_lxc_dns` | Explicit `proxmox_lxc_dns_guests`, ownership, nameservers and search domain. No discovery of every host guest. |
| `proxmox_lxc_devices` | Explicit `proxmox_lxc_devices_guests`, ownership and per-guest `proxmox_lxc_device_passthroughs` list of key/value entries. Restricted `devN` keys and `/dev/` values; not broad arbitrary `pct` flags. |
| `proxmox_kernel_sysctl` | Explicit `proxmox_kernel_sysctls` map, empty by default; writes dedicated managed sysctl file. Requires `ansible.posix` 2.1.0. |
| `proxmox_hpe_smart_array` | Disabled unless enabled; requires explicit controller slot, PCI ID and product pattern, Debian 13 amd64, pinned HPE repository key and tools. Query/LED helper only; no array mutation. Hardware qualification remains operator responsibility. |

For all LXC host-side roles, the Proxmox host has `proxmox_node` and
`lifecycle_owner: ansible`. Each selected guest is a private inventory hostname
with matching `proxmox_node`, integer `proxmox_vmid` and no conflicting lifecycle
owner. Terraform-managed guests must not be selected. The roles only touch
explicitly supplied guest names; IDs are not inferred from network discovery.

Collection playbooks: `cmdmesh.proxmox.host_baseline`, `cmdmesh.proxmox.backup`,
`cmdmesh.proxmox.maintenance`, `cmdmesh.proxmox.lxc_resources` and
`cmdmesh.proxmox.lxc_storage`. They use the `cmdmesh_targets` inventory group by
default; override `cmdmesh_target` and always provide an explicit CLI limit.

The repository contains no credentials, host inventory or state for a real lab.
Check mode runs inventory probes but not mutation commands. Remote command output
can contain private inventory details: keep Ansible logs private. Timeout or lost
SSH does not prove a remote change stopped; inspect actual guest/storage state
before retrying. Growth is not undone automatically, maintenance reboot has no
automatic package rollback, and backup retention may remove old archives. Review
capacity, restore coverage, retention and host access before authorizing changes.

## Reference persistence module in development

`cmdmesh.proxmox.lxc_persistence` exposes readonly `inspect`, `prepare_backup`
and an explicitly permitted `backup` over the fixed reference profile. Backup
check mode repeats the frozen source checks without consuming the operation or
writing snapshots/NAS output. Real dispatch requires exact retained canonical
bytes/hash and `allow_changes: true`; failures retain partial state and never
retry automatically. Invocation arguments and runtime traces are withheld while
safe returned hashes remain intact. See the [profile contract and examples](../../../../docs/persistence-profile.md#ansible-entry-point).

Local tests and a native running observer are qualified. Native stopped-source
backup, rebuild and independent restore remain pending; this module is still a
development interface, not a promoted production recovery procedure.

`cmdmesh.proxmox.lxc_persistence_receive` is the separate receive stage in
development. Its `prepare` action binds an exact empty owned recovery parent,
host/pool fingerprints and independently authenticated private plaintext streams.
`receive` requires the retained canonical preparation/hash and explicit permission;
check mode repeats preflight only. Actual receives stay unmounted/read-only and
validate snapshot GUIDs. `received_verified` never implies application or
source-unavailable recovery. See the [receive contract](../../../../docs/persistence-profile.md#unmounted-receive).

## Guarded memory module

`cmdmesh.proxmox.lxc_memory` is a separate memory-only building block for the
verified procedure under development. It accepts a strict prepared document
from the [memory evidence contract](https://github.com/luis-lobo-ar/cmdmesh-proxmox/blob/main/docs/lxc-memory-evidence.md).
It does not extend the older memory/swap role's input or claim that role provides
the new continuity/postcondition guarantees.

The module independently reads the actual node, machine/CA/leaf, host boot,
owner/generation tags, running init identity, config and cgroup ceiling. Fresh
preflight must match the frozen baseline and private headroom policy. Actual
growth runs only `pct set <vmid> --memory <target> --digest <approved-digest>`.
It reobserves and checks the memory-only result. No shrink, guest restart, tag
creation, retry or automatic rollback is implemented.

```yaml
- name: Assess an existing frozen memory intent
  cmdmesh.proxmox.lxc_memory:
    prepared: "{{ cmdmesh_memory_prepared }}"
  check_mode: true
```

Normal growth additionally requires `allow_changes: true`. A no-op returns
unchanged without that permission or an additional headroom requirement. Check
mode follows Ansible's convention: `changed: true` means it would change, while
`mutation_attempted` stays false. The prepared baseline/desired values remain
frozen; fresh data does not overwrite the approved variables.

Success reports `assessment: checked`, `unchanged` or `postchecked`, fixed checks
and mutation facts. Command outcome is separately `not-dispatched`, `succeeded`,
`failed` or `unknown`. A successful command with an unchanged or unenforced limit
fails postchecking. Failure after dispatch reports possible effects and uncertain
state; it never automatically retries. Framework argument failures protect the
prepared input, and normal results withhold invocation details. Keep logs private
and reconcile actual state before another
authorized attempt. Invocation details withhold the prepared document without
censoring the returned correlation hash.

Reserved timeout status 124 and signal-style termination are conservatively
unknown. A native command can reuse those statuses, so the driver does not infer
its final effects from them. See the [GNU timeout exit contract](https://www.gnu.org/software/coreutils/manual/html_node/timeout-invocation.html).

Native commands have ten-second supervisors; the module has a 120-second outer
deadline. Controller interruption does not prove remote termination. Initial
local tests cover the driver with synthetic native reads, plus actual Ansible
packaging/refusal on a non-Proxmox target. Successful real-node growth, concurrency
conflicts and interruption recovery still require owned-disposable qualification.
Core's independent postcollection and consumed-intent journal remain separate P4
work. Module `postchecked` alone is not overall procedure verification.
