# cmdmesh.proxmox

Eleven explicit-target operational roles, with one shared refusal/approval role.
Tested locally with Ansible Core 2.19.4. Run with `--check` first. Outside check
mode, `cmdmesh_allow_changes: true` is mandatory; this is an acknowledgment, not
a substitute for reviewing targets and changes.

| Role | Inputs and limits |
| --- | --- |
| `proxmox_baseline` | Explicit `proxmox_baseline_host_packages` and `proxmox_baseline_host_absent_packages`; both default empty. Host only, no automatic LXC discovery. |
| `proxmox_apt_repositories` | Debian/Proxmox suite and archive keyring; deliberately configures no-subscription sources. Gather distribution facts and review Ceph suite compatibility first. |
| `proxmox_maintenance` | Assessment defaults on. Actual upgrades require `proxmox_maintenance_assessment_only: false`, `proxmox_maintenance_enabled: true`, `proxmox_maintenance_reboot: true`, one host and no running QEMU/LXC guests. Does not stop or migrate guests for you. |
| `proxmox_vm_backup` | Explicit `proxmox_vm_backup_jobs` list of `name`, `vmid`, `guest_type`, `keep_last`, `on_calendar`; schedules default disabled. Installed timers use per-guest locks and produce textfile metrics. No backup starts during the role; enabling timers can schedule one immediately. |
| `proxmox_nfs_backup_storage` | Explicit enable, storage ID, server/export and options. Backup-only storage; refuses unexpected lookup failures and existing non-NFS storage. No destructive replacement. |
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
