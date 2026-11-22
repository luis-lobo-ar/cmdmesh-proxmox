# LXC memory evidence contract

Use `lxc-memory-observe` to check the configured and enforced memory of one
explicitly owned running LXC. Native inspector 0.3.0 adds this read-only action;
the five earlier actions retain their behavior. Memory resizing and the verified
Ansible procedure remain separate P4 work.

## Run a live observation

Copy [the request](../examples/inspection/lxc-memory-observe.json) and
[private configuration template](../examples/inspection/memory-provider-config.json)
to an ignored private directory. Set the exact node/VMID, independently qualified
host fingerprints and existing owner/generation markers. The placeholders are
synthetic. Do not retag a production guest to force it through this owned-resource
profile.

Build a new archive using the inspection guide, then run:

```sh
.generated/proxmox-inspect.pyz \
  --input /private/memory-request.json \
  --config /private/memory-provider.json
```

The request requires `selector`, `host_profile`, `owner_tag` and `generation_tag`.
An optional 32-hex `request_id` is generated when omitted. No offline frame,
caller timestamp, arbitrary command or code path is accepted. Use `describe` to
read the exact schema. No API token is needed or sent.

Configure explicit `tls` settings with one private node CA and explicit `ssh`
settings with root access, the intended identity and known-hosts file. Shared
API settings alone do not select the node for this action. Runtime-default trust,
extra certificates, custom proxy certificates and fallback authentication are
unsupported by this first profile.

The collector captures CA bytes once, verifies TLS name/chain, matches the
expected CA and served leaf fingerprints, and sends its bundled fixed collector
over strict SSH. The remote host must report the same CA/standard leaf, pinned
machine ID and actual node before it reads the guest. It creates no guest process
or remote scratch file. Local SSH uses private temporary scratch and a clean
environment; ambient keys, passwords, agents, proxies and multiplexing are off.

An observed result includes `observation`, stable `subject_key`, and `source`
with collector hash, captured trust receipt and controller start/end times.
`current_observation: true` means this action collected qualified state through
those channels; it becomes historical after collection. `mutation_authorized`
remains false. It does not prove reserved RAM, application health or that a
later change will work.

The SSH subprocess has a 30-second deadline. Results qualify only if total
collection elapsed time is at most 30 seconds and evidence meets the 30-second
freshness limit. These are acceptance limits, not waiting periods. TLS and TCP
use socket timeouts; DNS and other preparation remain subject to the outer
120-second inspector deadline. SSH output is limited to 64 KiB and must be valid UTF-8 and
strict JSON. Duplicate keys, nonfinite values, replayed request IDs/times and
incomplete or mismatched evidence fail. Failure returns a fixed diagnostic and
recovery guidance without raw SSH output or configuration values. The independent
remote process has a 45-second deadline if client access is lost. Normal local
cleanup and core-owned cancellation follow the inspection guide; external killing
of standalone mode does not imply remote process termination.

The archive pin covers the facade, validator, remote source and shared access
code. Python/stdlib, SSH and installed node tools remain trusted runtime inputs.
Loopback TLS and synthetic SSH tests qualify transport behavior; live resizing,
recovery and private adoption have not yet been certified.

## Typed evidence validation

`ansible/ansible_collections/cmdmesh/proxmox/plugins/module_utils/memory_state.py`
defines strict version-1
`cmdmesh.proxmox.lxc-memory.observation` evidence. `validate_observation` accepts
an observation, the expected request, controller time and maximum evidence age.
The expected request contains a request ID, exact origin/node/LXC/VMID selector,
host fingerprints, owner tag and generation tag.

Required evidence has these fields:

| Field | Required content |
| --- | --- |
| Identity | `request_id`, `origin`, `node`, `kind`, integer `vmid` |
| `host_profile` | SHA-256 fingerprints for machine ID, private CA and served node leaf |
| `host_boot_id_sha256` | SHA-256 of the actual host kernel boot ID, stable across collection |
| `tags` | Actual `cmdmesh-ansible`, one `cmdmesh-own-<32 hex>` and one `cmdmesh-gen-<32 hex>` marker |
| `configuration` | Proxmox `digest`, integer `memory_mb`/`swap_mb`, `other_sha256`, boolean `locked`/`pending` |
| `runtime` | Running status, integer `memory_limit_bytes`, `init_start_ticks` and `pid_namespace_inode` |
| `host_capacity` | Positive `total_bytes` and nonnegative `available_bytes`, no greater than total |
| `versions` | Exact `pve-manager` and `pve-container` versions |
| Source limits | Integer `observed_at_unix_ms`, boolean `complete`, bounded `warnings` array |

The document type and `schema_version` are mandatory. Unknown fields, missing
nested fields and invalid types fail. Booleans and numeric strings are not
integers. All nested fields are required; no missing measurement becomes zero.

The memory fields use Proxmox's MB convention: one unit is 1,048,576 bytes.
Runtime memory must match the configuration in those units. This validates an
observed ceiling, not reserved RAM or application availability. Swap is recorded
as unchanged-state evidence; this does not qualify swap mutation.

The first candidate version pair is PVE manager 9.2.21 and pve-container 6.1.14.
These are decoder/profile inputs, not live workflow certification. Other versions
are unsupported until separately qualified. Stopped, locked, pending, partial,
warned, future or stale evidence cannot establish readiness. Conflicting,
duplicate, missing or wrong ownership/generation markers fail.

The returned copy has `validation_scope: supplied-evidence-only`,
`current_observation: false` and `mutation_authorized: false`. A live collector
must establish channel identity and actual collection before using this evidence
in a verified procedure. Rewriting a timestamp cannot supply that provenance.

The computed `subject_key` hashes the private CA fingerprint, machine-ID
fingerprint, actual node, kind and VMID. Caller origin labels, certificate leaf
rotation, owner tags and generations do not create a different resource lock.
Plans still bind those values independently. This is a same-controller lock key,
not distributed exclusion across administrators or proof of a remote identity.
The separate host boot fingerprint supports continuity checks across a procedure;
guest init start ticks and namespace inodes alone can repeat after a host reboot.
Boot identity does not change the stable resource lock key.

`MemoryEvidenceError` exposes a fixed code and outcome, never supplied values.
The caller must retain failed evidence as unqualified and provide recovery
guidance. It must not retry, shrink or claim applied/verified success from this
decoder alone. The live action establishes collection provenance separately.
The verified Ansible procedure remains P4 work.

## Fixed remote collector

The collection's canonical `plugins/module_utils/memory_remote.py` is standalone
standard-library source bundled into the live SSH action. It reads host identity
before running native commands, rejects another node/machine/CA/leaf
and custom proxy certificates, then reads exact package versions and supported
Proxmox interfaces. It does not read private keys.

All commands are fixed: package query, `pct help set`, Proxmox GET queries and
`lxc-info` for the selected numeric ID. No create, set, resize, restart, guest
execution or arbitrary command input exists. Duplicate IDs, another resource kind,
missing/locked/pending config, malformed JSON and changing init identity fail.
The remaining configuration is hashed with only memory and the concurrency digest
excluded. Raw configuration values are not returned.

The collector follows the init process's host cgroup-v2 membership and reads
memory limits through its ancestors. A tighter ancestor limit is retained.
The global root may lack `memory.max`; a non-root missing interface is accepted
only when controller availability confirms memory is not local there. Missing or
unlimited evidence never becomes a made-up memory value. See the
[kernel cgroup hierarchy/interface reference](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
and [LXC PID query reference](https://linuxcontainers.org/lxc/manpages/man1/lxc-info.1.html).

The process uses regular, bounded nonblocking file reads. Native command stdout
is bounded to 2 MiB and stderr is discarded. A fixed GNU coreutils timeout
supervisor bounds each command to 10 seconds, and normal/deadline cleanup stops
the command's owned group. The overall standalone collector has a 45-second
deadline. It creates no remote scratch files or guest processes.

The caller supplies controller-derived collection time and a correlation ID.
Those assertions alone establish no live provenance. A complete raw frame still
requires `memory_state` validation and the authenticated client channel before
it can contribute to a procedure result.

The remote JSON decoder rejects duplicate keys and nonfinite numbers, including
exponent overflow. The same finite-number fix also hardens the shared inventory and
inspection decoders: invalid data returns a structured failure rather than
escaping during serialization. Valid legacy protocol behavior stays unchanged.

## Fixed preparation and pre/post checks

The canonical `module_utils/memory_state.py` also contains pure `prepare`,
`preflight` and `verify` functions for the next procedure. They are internal
building blocks, not additional native actions or a completed mutation workflow.
The deterministic builder embeds their canonical bytes under the existing
`memory_state.py` and `memory_remote.py` archive names. There are no second
checked-in helper copies. The remote collector remains standalone source so SSH
execution does not depend on Ansible or sibling modules being installed remotely.

`prepare` validates supplied initial evidence and freezes a version-1
`cmdmesh.proxmox.lxc-memory.prepared` document with exactly:

- `request`: exact selector, host profile and owner/generation markers.
- `subject_key`: stable physical resource identity derived from that evidence.
- `baseline`: full validated historical observation.
- `desired_memory_mb`: integer desired ceiling, at least the current value.
- `change_required`: boolean derived from baseline and desired memory.
- `capacity_policy`: the explicitly selected headroom policy.

For example, a private policy can be:

```json
{"mode":"observed-available-headroom","minimum_remaining_bytes":1073741824}
```

For growth, the required condition is
`growth_bytes + minimum_remaining_bytes <= fresh MemAvailable`. This is a
snapshot headroom check. It does not reserve RAM or measure all guest commitments.
An already-correct desired value is an unchanged result and requires no extra
headroom. Shrinking is unsupported. The policy is still validated for a no-op.

Every preflight revalidates the prepared document and fresh evidence. Host/guest
identity, ownership, host boot, init process, versions, host total memory and
unrelated configuration must match. The full Proxmox configuration digest and
memory preimage must remain unchanged. Current headroom is checked again for
growth; the approved variables and baseline are never rewritten with fresh data.

Postchecks require the desired configured and enforced memory, the same running
guest and host boot, and unchanged unrelated state. Real growth requires a
different configuration digest; a no-op requires the same one. Volatile free
memory need not equal its baseline. An unchanged or unenforced limit cannot pass
because a command exited zero.

Successful pure checks return fixed versioned check IDs and booleans with
`validation_scope: supplied-evidence-only`, `current_observation: false` and
`mutation_authorized: false`. A frozen baseline may be historical; each current
pre/post observation must be fresh and no earlier than it. No caller-supplied
frame becomes live evidence through these functions. The live facade and core
procedure must establish provenance, binding, consumed intent and final status.
