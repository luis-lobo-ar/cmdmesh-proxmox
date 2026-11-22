# LXC memory evidence contract

This internal P4 building block validates supplied observations. It does not
collect live state, resize a container or register another inspection action yet.
The existing five native actions retain their current behavior.

`inspection/memory_state.py` defines strict version-1
`cmdmesh.proxmox.lxc-memory.observation` evidence. `validate_observation` accepts
an observation, the expected request, controller time and maximum evidence age.
The expected request contains a request ID, exact origin/node/LXC/VMID selector,
host fingerprints, owner tag and generation tag.

Required evidence has these fields:

| Field | Required content |
| --- | --- |
| Identity | `request_id`, `origin`, `node`, `kind`, integer `vmid` |
| `host_profile` | SHA-256 fingerprints for machine ID, private CA and served node leaf |
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

`MemoryEvidenceError` exposes a fixed code and outcome, never supplied values.
The caller must retain failed evidence as unqualified and provide recovery
guidance. It must not retry, shrink or claim applied/verified success from this
decoder alone. The fixed remote collector below is another building block.
The live TLS/SSH action and verified Ansible procedure remain P4 work.

## Fixed remote collector

`inspection/memory_remote.py` is standalone standard-library source for a future
SSH action. It is not registered or included in the native archive yet. It reads
host identity before running native commands, rejects another node/machine/CA/leaf
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
