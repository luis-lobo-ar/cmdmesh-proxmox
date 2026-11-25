# CmdMesh Proxmox

Reusable Proxmox inventory, Ansible operations and a Terraform LXC module. Each
component works independently; CmdMesh adds discovery and execution controls.

The inventory executable is 0.1.0, native inspector 0.4.0 and Ansible collection 0.2.2.
They are versioned separately. Local tests use synthetic HTTPS and guest-command fixtures.
It is **not** certified for every Proxmox version, storage backend or server model.
No infrastructure is changed by installing this repository.

## Read-only inventory

Requires Python 3.10+ on Linux. No Python packages are needed for the executable.

```console
./bin/cmdmesh-proxmox --fixture examples/inventory.fixture.json
./bin/cmdmesh-proxmox inventory --config ./private/provider.json
```

Copy `examples/provider.json` to a private directory and supply the referenced
credential environment variables using your secret manager. Use a least-privilege
Proxmox API token scoped to the inventory you need; verify that it can enumerate
both nodes and guests. Never put the token value in the JSON file or shell history.
The optional `ca_file` selects your supplied CA instead of system trust; use an
absolute path or resolve it from the invocation directory. TLS hostname and chain
verification are mandatory. There is no password-login or insecure mode.

The endpoint is an HTTPS origin, such as `https://pve.example.invalid:8006`, not an
API path. Requests use GET only. Redirects and ambient HTTP proxy settings are
disabled to avoid forwarding credentials. A fixture is explicit, never a fallback
after a network or authentication failure.

For CmdMesh subprocess use, send one JSON request on stdin:

```json
{"schema_version":1,"operation":"inventory","config":{"endpoint":"https://pve.example.invalid:8006","token_id_env":"PVE_TOKEN_ID","token_secret_env":"PVE_TOKEN_SECRET","timeout_seconds":10}}
```

The executable emits a normalized schema-version-1 snapshot with `complete`,
`resources` and `warnings`. Kinds are `proxmox.node`, `proxmox.vm` and
`proxmox.lxc`; guest IDs have the form `node-a/101`. Root/auth/TLS failures return
`complete:false`, never a successful empty inventory. One failed guest collection
retains other resources but marks the whole snapshot incomplete. API bodies and
credentials are not printed in diagnostics.

Protocol mode exits zero when it emits a valid snapshot, including incomplete
snapshots. Consumers **must** inspect `complete`; process exit alone is not health.
Direct `--config` and `--fixture` commands return one for incomplete snapshots.

Limits: 2 MiB per input/response, 128 nodes, 20,000 total resources, configurable
per-request timeout of at most 60 seconds, and a 120-second Linux process deadline.
There are no retries, write endpoints, guest operations or implicit credential
discovery.

## Native inspections

The separate inspection bundle resolves origin/node/kind/VMID with typed input,
source completeness and freshness, and known failure/recovery guidance. It works
offline without credentials and can use the existing GET-only API collector for
live observations. It never selects the first duplicate or turns an offline file
into live evidence.

```sh
umask 077
mkdir -p .generated
python3 tools/build_inspector.py --out .generated/proxmox-inspect.pyz
.generated/proxmox-inspect.pyz --input examples/inspection/describe.json
.generated/proxmox-inspect.pyz --input examples/inspection/resolve-offline.json
python3 examples/inspection/compare.py | .generated/proxmox-inspect.pyz
```

The artifact's digest covers its bundled implementation, including reused
inventory and fixed probe code. It also compares complete before/after evidence,
diagnoses explicit controller tools and scratch, verifies SSH access and expected
UID, and checks TLS trust/name without sending API credentials.
The `lxc-memory-observe` action checks an owned running LXC's configured and
enforced memory through pinned node TLS and strict SSH. It does not resize it.
`lxc-memory-procedure` adds read-only preparation, fresh preflight and independent
postchecks around a frozen intent. Known failed checks retain their evidence;
the phase action never dispatches a change. See
[the phase example](docs/inspection.md#assess-an-owned-memory-procedure).
See [the inspection guide](docs/inspection.md) for private configuration, exact
schemas, trust limits and failure recovery. Core's `inspection` commands and
`cmdmesh_inspection` MCP tool use this same artifact protocol. No inspection
installs tools, repairs access or authorizes mutation.

## Ansible collection

Install development dependencies in a virtual environment; the API executable
does not require them:

```console
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/ansible-galaxy collection install -r ansible/requirements.yml -p .ansible/collections
export ANSIBLE_COLLECTIONS_PATH="$PWD/ansible/ansible_collections:$PWD/.ansible/collections"
.venv/bin/ansible-playbook -i ./private/inventory.yml cmdmesh.proxmox.host_baseline --limit node-a --check -e @./private/vars.yml
```

`examples/inventory.yml` and `examples/vars.yml` are fictional starting points,
not reachable targets. Review roles and inventory before executing even check mode:
Ansible is code, and check mode is not a sandbox. These exported roles explicitly
force only read-only probes to run during check mode.

Every operational role depends on `cmdmesh.proxmox.operation_guard`. It refuses a
normal run unless `cmdmesh_allow_changes: true` is explicitly supplied. Default
behavior is therefore assessment with `--check`, or refusal without approval.
This setting does not replace human change approval, host selection or backups.
Use a single explicit host/group and `--limit`; never use an unreviewed broad
inventory. See the [collection guide](ansible/ansible_collections/cmdmesh/proxmox/README.md)
for all twelve roles and their safeguards.

For a new backup-only NFS registration, the role's explicit
`proxmox_nfs_backup_storage_create_only: true` refuses existing storage IDs before
package changes. New mountpoints must be absent, including symlinks or uncovered
directories, and are checked again after dependency preparation. Existing-store
management remains available with the default false value. Storage status and a
successful mount do not prove backup coverage or recoverability. The fixed
[persistence profile](docs/persistence-profile.md) is still under development.
The separate `proxmox_nfs_backup_create` role (collection 0.2.2) gives new-store
recipes a resolvable capability boundary: an older collection fails before
connecting instead of ignoring a new variable. The inventory executable and
inspection protocol versions are unchanged.

The developing persistence profile also has a thin `lxc_persistence` Ansible
module: observe a declared reference source, prepare a stopped-source backup,
or execute its retained canonical intent once. Check mode is source preflight
only; real backup requires `allow_changes: true`. The local backup tests and a
native running-source observation pass. Native stopped-source backup, rebuild
and restore remain unqualified. See the [action contract and examples](docs/persistence-profile.md#ansible-entry-point).

The separate developing `lxc_persistence_receive` module receives independently
authenticated data/config streams into absent datasets below an empty owned
parent. It keeps them unmounted and read-only, checks their snapshot GUIDs, and
never reports application recovery. See the [receive contract](docs/persistence-profile.md#unmounted-receive).

The developing `lxc_persistence_recipient` module provisions a fresh stopped,
network-isolated replacement rootfs while preserving the original reference
source. It deliberately omits retained binds during template extraction and does
not start or initialize an application. See the [recipient contract](docs/persistence-profile.md#stopped-rebuild-recipient).

The developing `lxc_persistence_blank_stage` module prepares that fresh guest for
later OS bootstrap by denying both managed start paths and generating its stopped
native config. It never starts the guest or attaches retained data. Check mode,
one-use writes and read-only status share the same preparation contract. Native
qualification remains pending; see [the stage and guard limits](docs/persistence-profile.md#denied-configuration-generation-developing).

Workflow authors can share the existing backup mutex through
`persistence_pair_lock.locked_pair`. Its GUID-pair identity serializes backup and
handoff operations across processes. Read the [shared-lock contract](docs/persistence-profile.md#shared-pair-lock)
before using it in an operation controller.

Retained-source controllers can use the separate
[native configuration leases](docs/persistence-profile.md#native-guest-configuration-leases)
without supplying a blank-guest policy. The native writer must run after its
target read lease has closed.

The source observer also accepts the pinned schema-three owner guard for a
stopped successor. It checks owner/retirement facts and holds the successor's
native read lease through SQL and reference-file closure. Running successors are
explicitly unsupported by this collector; see
[stopped owner observation](docs/persistence-profile.md#stopped-successor-source-observation-developing).

The developing [explicit kernel binding](docs/persistence-profile.md#explicit-kernel-evidence-developing)
provides process, root-image, mapping and resource evidence independently of blank
guest policy. It does not establish ownership, guest bind backing or application
health. A separate retained-runtime collector must supply those checks.

The developing `lxc_persistence_runtime` module supports two read-only phases.
[Quiesced inspection](docs/persistence-profile.md#running-os-with-a-quiesced-application-developing)
takes the actual application lock for consistent SQL.
[Active-writer inspection](docs/persistence-profile.md#active-writer-observation-developing)
authenticates a retained-credential read through a verified local socket peer,
without application EX or host-side database reads. Both phases hold pair/native
leases and check guest backing, image, owner and references. Neither phase starts
or enables the service, appends a record, or claims rebuild or restore. The
claimed native write/read-back/stop/SQL sequence remains pending. The developing
[`lxc_persistence_writer_trial` boundary](docs/persistence-profile.md#claimed-application-lifecycle-developing)
prepares and controls that once-only test with explicit mutation permission,
failure containment and separately trusted read-only status. Local qualification
does not establish native rebuild or disaster-recovery acceptance.

The developing `lxc_persistence_attach` module configures the reference data and
configuration binds on a stopped replacement. It denies normal and debug starts
for both guests, uses three digest-checked native updates to disable protection,
add the binds and restore protection, and leaves all starts denied. A partial
failure retains its claim and needs reconciliation. It does not prove a working
rebuild or restore. See [stopped attachment](docs/persistence-profile.md#stopped-retained-attachment-developing).

The initial owner-publication module builds on that exact completed attachment.
It archives the blank guards, installs the successor policy/owner and retires the
old reference while all four starts remain denied. Preparation and check mode
are read-only. It does not activate an application; see
[stopped ownership handoff](docs/persistence-profile.md#initial-stopped-owner-publication-developing).

For the specific pre-retirement guard-refusal stage, the developing
`lxc_persistence_owner_reconcile` module uses a new claim and corrected guard.
It preserves the failed journal, owner and every start denial. Preparation and
check mode are read-only; execution requires explicit changes permission.
Other failure stages and guest activation are unsupported. See
[known failed-guard reconciliation](docs/persistence-profile.md#known-failed-guard-reconciliation-developing).

The developing `lxc_persistence_blank_boot` module consumes a separately trusted
successful stage, publishes pinned pre-start checks and submits one isolated OS
start. It verifies actual kernel/guest readiness and keeps application/recovery
claims false. Check and status never start or republish. Native qualification is
pending; see [the blank OS boundary](docs/persistence-profile.md#one-blank-os-start-developing).

## Terraform LXC module

`terraform/modules/lxc` contains a `bpg/proxmox` module. The standalone example
pins provider 0.97.0 and retains its generated dependency lockfile:

```console
terraform -chdir=terraform/examples/lxc init -backend=false -input=false
terraform -chdir=terraform/examples/lxc validate
```

Validation does not contact a Proxmox host or prove an apply safe. Copy the example
to a private environment, configure verified TLS trust and credentials there, and
review a saved Terraform plan before any apply. No backend or state is supplied.
Nesting defaults false. Storage and bridge are explicit required inputs; device
passthrough is empty unless requested. Lifecycle changes can require shutdown,
replacement or provider-specific operations; inspect the actual plan.

Exactly one tool owns each guest field. The default module owns guest existence,
CPU, memory, root disk, devices, network and DNS. Do not run host-side Ansible
`pct` roles against those Terraform-managed fields. The optional Ansible LXC roles
require `lifecycle_owner: ansible` on the target and selected guests, plus explicit
guest lists. Ansible may still manage packages/files inside Terraform-created
guests through independent guest-targeted playbooks.

## Tests and limits

```console
PATH="$PWD/.venv/bin:$PATH" python3 -m unittest discover -s tests -v
PATH="$PWD/.venv/bin:$PATH" python3 tools/check-ansible.py
terraform fmt -check -recursive terraform
terraform -chdir=terraform/examples/lxc validate
```

HTTPS tests create disposable loopback servers and certificates at runtime, never
use live APIs, and verify auth, TLS rejection, redirects, malformed/oversized data
and partial results. Actual Ansible runs use a synthetic `pct` executable to prove
check-only behavior, approval/ownership rejection, growth and shrink refusal.

Maintenance, NFS storage, backup restore and hardware tools still need explicit
disposable-host qualification before production use. A configured backup timer is
not proof of successful restore. LXC bind-mounted datasets need a separately
designed backup policy; `vzdump` does not include them automatically. The ZFS
persistent-data recipe is tracked separately and is not a recovery guarantee.
