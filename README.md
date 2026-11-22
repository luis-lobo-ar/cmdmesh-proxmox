# CmdMesh Proxmox

Reusable Proxmox inventory, Ansible operations and a Terraform LXC module. Each
component works independently; CmdMesh adds discovery and execution controls.

Version 0.1 is locally tested against synthetic HTTPS and guest-command fixtures.
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
See [the inspection guide](docs/inspection.md) for private configuration, exact
schemas, trust limits and failure recovery. The core inspection bridge remains
in development. No inspection installs tools, repairs access or authorizes mutation.

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
for all eleven roles and their safeguards.

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
