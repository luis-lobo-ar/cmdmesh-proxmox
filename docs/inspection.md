# Inspect an exact Proxmox target

Use this component when a guest ID or remembered name is insufficient to identify
the target. It matches an explicit origin, node, resource kind and numeric VMID,
then reports whether the evidence is complete, recent and live or merely an
offline assertion. It does not authorize a change or prove application health.

The current standalone actions are `describe` and `target-resolve`. Other P3
primitives and the core CLI/MCP inspection bridge are subsequent work. Do not
register this archive as the legacy inventory executable: their protocols differ.

## Build and try without Proxmox

Requires Linux and Python 3.10+ with its standard library. From this repository:

```sh
umask 077
mkdir -p .generated
python3 tools/build_inspector.py --out .generated/proxmox-inspect.pyz
.generated/proxmox-inspect.pyz --version
.generated/proxmox-inspect.pyz --input examples/inspection/describe.json
.generated/proxmox-inspect.pyz --input examples/inspection/resolve-offline.json
```

The builder prints a SHA-256 receipt. The artifact contains exactly the inspector,
its entrypoint and the existing inventory implementation as an embedded module.
It does not copy private configuration or arbitrary repository contents. ZIP
entry metadata is fixed, so equal source bytes produce equal artifact bytes.
Output is mode 0700 and must be a new path; existing files and symlinks are refused.
Use a new output name when rebuilding rather than overwriting a reviewed artifact.

The SHA covers both inspector and reused inventory code in that archive. Imported
Python standard-library code and the interpreter remain trusted runtime inputs.
This is an integrity pin, not a signature or sandbox. See Python's
[application archive contract](https://docs.python.org/3/library/zipapp.html).

The offline example returns `outcome:"observed"`, `resolution:"resolved"` and the
exact `example/node-a/proxmox.lxc/101` identity. Its `source.mode` is `offline`,
`current_observation` is false and `mutation_authorized` is false. This completes
an offline matching task; it is not a current-state deployment preflight.

## Discover the input contract

`describe` returns the finite action list, aliases, JSON input schemas, expected
results, known failures and recovery guidance. It performs no provider call and
does not validate private credentials/configuration. JSON schemas describe input
shapes; runtime checks also enforce cross-resource identity consistency.

For guests, the selector requires:

- `origin`: an explicit private source namespace.
- `node`: the exact Proxmox node name, not an SSH alias.
- `kind`: `proxmox.lxc` or `proxmox.vm`.
- `vmid`: integer 100–999999999. Booleans and string IDs are rejected.

For a node, use `kind:"proxmox.node"` and omit `vmid`. Names are display attributes,
not selection authority. Duplicate kind/ID rows, missing node evidence or an ID
that disagrees with `properties.node/vmid` are rejected before matching.

## Collect from a real API

Copy [the configuration example](../examples/inspection/provider-config.json)
to an ignored private directory. Supply the existing credential environment
references through your secret manager. Token values never belong in request
files, arguments or public configuration.

```sh
.generated/proxmox-inspect.pyz \
  --input examples/inspection/resolve-live.json \
  --config /private/proxmox-inspection.json
```

`input.source` is exactly `{"mode":"live"}`; it cannot contain a caller-supplied
snapshot or timestamp. The selector origin must match private `config.origin`
before any network request. Live collection reuses the same GET-only, verified
HTTPS implementation as the legacy inventory provider. It never falls back to
offline data after authentication, permission, TLS or network failure.

`origin` is a configured namespace bound to this selected endpoint, not an
independently verified cluster UUID. The result records the configuration digest,
collection start/end times and canonical snapshot digest. Before/after CA hashes
detect ordinary trust-file changes; SSL separately opens that path, so the hash
does not freeze the trust file or attest to immutable bytes throughout collection.
The result is not a cryptographic remote-identity attestation.

Omit `api.ca_file` to use the controller's default trust. If supplied, it must be
a nonempty string identifying a readable regular PEM CA file. Explicit false,
zero, null, empty and container values are rejected before any API request;
they never silently select default trust. FIFOs/devices are refused without
blocking. Obtain the CA through an already trusted channel; do not fetch and
trust an unverified certificate or disable name verification.

Collection uses multiple API requests and is not an atomic cluster snapshot.
`complete` means the returned collections completed without warnings, not that
token ACLs exposed every expected resource. `source.visibility_qualified` remains
false until an independent workflow qualifies expected coverage. A matching live
target can still be a current observation within the reported scope.

## Interpret the result

All results use `document_type:"cmdmesh.inspection.result"`, schema version 1,
the requested operation, `outcome`, `data` and `diagnostics`. Diagnostics have
stable `code`, readable `summary`, `next_checks` and `recovery`. They do not emit
credential values, raw API response bodies or arbitrary exception text.

| Condition | Result |
| --- | --- |
| Exact valid offline match | Resolved identity, caller-asserted source, never current live evidence |
| Exact valid live match | Resolved identity and current API observation within reported scope |
| Missing target in complete scope | Rejected, `resolution:"absent"`; no inference about other origins or hidden resources |
| Incomplete or warned collection | Incomplete, `resolution:"indeterminate"`; a visible candidate does not establish complete scope |
| Duplicate/conflicting identity | Rejected with source/identity diagnostics; never first-match selection |
| Invalid explicit CA or configuration | Rejected before API use where detectable |
| Authentication, trust or transport failure | Unavailable; no fixture fallback or automatic repair |

An offline `observed_at_unix_ms` is optional and caller-asserted. Its freshness is
unknown, reported-recent, stale or invalid; it never becomes live provenance.
`max_age_seconds` is an explicit freshness limit (default 60, range 1–86400), not
a waiting period. A stale/future live collection cannot become a current target.
Mutation authority remains false even for a successful live identity observation.

CLI exits 0 for an observed result, 1 for rejected/incomplete/unavailable or
unsupported results, and 2 for argument syntax errors. Observed is not verified
application availability. Inspect the result fields for the task you are doing.
The Linux process deadline is 120 seconds. Input is bounded to 16 MiB; underlying
API response and resource limits remain those of the inventory provider.

For configured integration transport, send the same request on stdin with an
additional `config` object. Direct `--input` files exclude `config`; the separate
private file supplies it. Unknown request fields, actions and versions fail.
This protocol does not extend or reinterpret the old inventory request schema.
