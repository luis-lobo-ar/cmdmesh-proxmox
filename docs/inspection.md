# Inspect an exact Proxmox target

Use this component when a guest ID or remembered name is insufficient to identify
the target. It matches an explicit origin, node, resource kind and numeric VMID,
then reports whether the evidence is complete, recent and live or merely an
offline assertion. It does not authorize a change or prove application health.

The standalone actions are `describe`, `target-resolve`, `observation-compare`,
`controller-diagnose`, `ssh-diagnose`, `tls-diagnose` and `lxc-memory-observe`.
Core exposes the same protocol through its `inspection` CLI commands and
`cmdmesh_inspection` MCP tool. Do not
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
its entrypoint, fixed probes, memory evidence/collector modules and the shared
inventory implementation, plus a generated hash-only driver profile.
It does not copy private configuration or arbitrary repository contents. ZIP
entry metadata is fixed, so equal source bytes produce equal artifact bytes.
Output is mode 0700 and must be a new path; existing files and symlinks are refused.
Use a new output name when rebuilding rather than overwriting a reviewed artifact.

The SHA covers both inspector and reused inventory code in that archive. Imported
Python standard-library code and the interpreter remain trusted runtime inputs.
This is an integrity pin, not a signature or sandbox. See Python's
[application archive contract](https://docs.python.org/3/library/zipapp.html).

`driver-profile.json` identifies the memory profile/version and hashes the
canonical Ansible module and both shared helpers. The driver is hashed without
copying or executing it. Helper hashes use the same captured bytes embedded in
the archive. A driver change therefore changes the artifact pin even when the
inspection code stays the same. This metadata does not certify a resize: procedure
preparation must match the actual collection files to it, and execution still
needs independent verification. The live procedure facade remains under development.

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
collection start/end times and canonical snapshot digest. For an explicit CA,
`source.trust` records `mode: explicit-ca-snapshot` and the SHA-256 of the bytes
loaded into the single SSL context used by every API request. Changing the file
after capture does not change that context. Default trust records
`mode: runtime-default` with a null digest. It does not attest to an immutable
system trust store. Neither mode is a cryptographic remote-identity attestation.

Omit `api.ca_file` to use the controller's default trust. If supplied, it must be
a nonempty string identifying a readable regular ASCII PEM CA file, at most 2 MiB.
Empty files and invalid certificate data fail. Explicit false,
zero, null, empty and container values are rejected before any API request;
they never silently select default trust. FIFOs/devices are refused without
blocking. Obtain the CA through an already trusted channel; do not fetch and
trust an unverified certificate or disable name verification.

Collection uses multiple API requests and is not an atomic cluster snapshot.
`complete` means the returned collections completed without warnings, not that
token ACLs exposed every expected resource. `source.visibility_qualified` remains
false until an independent workflow qualifies expected coverage. A matching live
target can still be a current observation within the reported scope.

## Compare before and after observations

`observation-compare` checks two supplied `cmdmesh.proxmox.observation` version-1
documents. It does not contact a host or prove who collected those documents.
Its result remains `provenance: caller-asserted`, `current_observation: false`
and `mutation_authorized: false`, even when the comparison matches.

Run the synthetic capacity-change example with your built inspector:

```sh
python3 examples/inspection/compare.py | .generated/proxmox-inspect.pyz
```

Expect `outcome: observed`, `comparison: matches` and `accepted_deltas: 1`.
The example changes no infrastructure. It supplies one exact allowed transition
for LXC 101's `maxmem`, from 1024 to 2048. Omitting or changing that transition
rejects the comparison. The result does not authorize a resize.

Use `describe` for the complete input schema. Each observation requires origin,
node, collection time, hostname, a package digest, protected-file digests,
APT-file digests, three management service states, and an inventory snapshot.
The snapshot must contain exactly the selected node and its guests. Every
resource requires numeric nonnegative uptime and status; guests also require
name, node and integer VMID. Duplicate identities fail before map construction.
Zero guests is valid with complete node evidence. Empty protected-file evidence
is invalid; an empty APT list is valid when collection is complete.

Both observations must be complete, free of warnings, ordered, not future-dated,
and within `max_age_seconds` (default 60, maximum 86400). Management services
must be active and the node online. Missing evidence cannot become a default.
Nondecreasing uptime is expected. Decreasing uptime, resource membership and
other field changes require exact permitted deltas.

Each delta has `path`, `before` and `after`. Paths are arrays of literal segments:

| Evidence | Path |
| --- | --- |
| Package set | `["packages_sha256"]` |
| Hostname | `["hostname"]` |
| One protected or APT file | `["protected", "/etc/hosts"]` or `["apt_lists", "/absolute/file"]` |
| One management service | `["services", "pveproxy"]` |
| One resource property | `["resources", "proxmox.lxc", "node-a/101", "maxmem"]` |
| Whole resource addition/removal | `["resources", "proxmox.lxc", "node-a/101"]` |

For membership changes, the value is the complete resource properties object,
with `null` on the absent side. Duplicate, unused, wildcard or mismatched deltas
fail. At most 1000 deltas are accepted. Origin/node changes cannot be permitted.
Expected service downtime still returns incomplete management health.
Private workflows must establish ownership and collect evidence through a
trusted channel before using this comparison as one postcondition. A matching
comparison alone proves neither application availability nor recoverability.

## Diagnose the controller

Start from [the private probe configuration example](../examples/inspection/probe-config.example.json).
Copy it into your private project, replace its placeholders, and prepare an
owner-only scratch directory. Then select one of the fixed input examples:

```sh
.generated/proxmox-inspect.pyz --input examples/inspection/controller.json --config /private/project/probe-config.json
.generated/proxmox-inspect.pyz --input examples/inspection/ssh.json --config /private/project/probe-config.json
.generated/proxmox-inspect.pyz --input examples/inspection/tls.json --config /private/project/probe-config.json
```

The supplied addresses and paths are examples. Do not run them unchanged.

Use `controller-diagnose` before attributing an execution failure to a host. Input
declares `required_tools`, each with a `minimum` and `maximum_exclusive` version,
and `minimum_free_bytes`. Version bounds have three numeric components. Set
`require_unix_socket: true` only when the intended workflow needs that capability.
Supported fixed probes are Python `--version`, Ansible `--version`, Terraform
`version`, and SSH `-V`. OpenSSH's `p` component becomes the third number.

Private configuration supplies `controller.scratch_root` and `controller.tools`,
an object mapping those tool IDs to trusted absolute executable paths. Scratch
must already exist, belong to the current user, have no group/other permissions
and have no symlink in its path. Diagnosis creates and removes its own mode-0700
child directory. It does not install tools, remove files or change permissions.

Each tool runs with fixed arguments, a clean environment and a private working
directory. Ansible receives a real private configuration file; `/dev/null` is
not used as a configuration file. Ambient Ansible configuration, Python imports
and credential environment values are not inherited. Output is bounded to 64 KiB
per probe and execution to three seconds. Raw output is withheld. Unknown,
nonzero or out-of-range versions cannot pass.

When core supplies `CMDMESH_INSPECTION_PROCESS_GROUP=1`, the inspector verifies
that it leads the owned process group. Probe children inherit that group so core
can stop tools and ordinary descendants on completion, timeout or interruption.
The marker is lifecycle metadata, not permission. Standalone mode owns a separate
group per probe and cleans it on normal completion or its deadline. External
SIGKILL of an unsupervised standalone process does not provide core's cleanup
guarantee. Tools that deliberately escape supervision are outside this trust model.
External termination can leave a private scratch child. Review ownership before
removing stale local scratch; this inspection never cleans unrelated directories.

Cross-package qualification uses the immutable core source pin in
`.github/core.json`. CI builds that core and executes the actual archive through
it, including timeout, cancellation and normal completion with ordinary nested
children. To run the same tests locally, provide your qualified core binary:

```sh
CMDMESH_BIN=/private/tools/cmdmesh python3 -m unittest discover -s tests -v
```

Without `CMDMESH_BIN`, the separate cross-package test class is skipped. Such a
run is not complete protocol qualification.

An observed result certifies only the supplied version ranges and measured local
prerequisites. It does not certify every feature of that tool, remote access or
application compatibility. The selected executable is trusted code, not sandboxed.

## Diagnose explicit SSH access

`ssh-diagnose` input contains `origin` and `expected_uid`. Private configuration
contains matching `origin`, `controller.scratch_root`, and this `ssh` object:

```json
{
  "executable": "/usr/bin/ssh",
  "host": "192.0.2.10",
  "port": 22,
  "user": "operator",
  "identity_file": "/private/keys/proxmox",
  "known_hosts_file": "/private/ssh/known_hosts"
}
```

Key/trust paths must be absolute regular files. Paths containing whitespace or
SSH expansion syntax are unsupported. The probe first checks DNS/TCP, then runs
the fixed remote command `id -u`. It uses `-F none`, explicit identity and known
hosts, strict host-key checking, no identity agent, no password prompts, no agent
forwarding, no proxies and no connection multiplexing. `CertificateFile=none`
prevents implicit loading of a sibling certificate. Only public-key authentication
with the explicit key is attempted. It never reads an alias
configuration, creates credentials or replaces a key. SSH config parsing is not
a harmless inspection: `Match exec` can execute a local command. See
[ssh configuration evaluation](https://man.openbsd.org/ssh_config).

The result distinguishes connectivity, host-key, authentication and wrong-UID
failures. Successful UID observation proves neither Proxmox authorization nor
application health. The namespace is configured, not a verified cluster UUID.

## Diagnose TLS without API credentials

`tls-diagnose` input contains `origin`. Private configuration contains matching
`origin` and `tls` with `host`, integer `port`, `server_name`, and optional
`ca_file`. Use `host` for connection and `server_name` for the certificate's
intended concrete DNS name or IP address. Wildcards and malformed requested names
are rejected. A wildcard certificate SAN may still validate a concrete name.
No HTTP request or token is sent.

The probe uses the shared captured-CA constructor and verifies the certificate
chain, validity and exact name. It reports name mismatch separately from chain
failure, plus a peer-certificate digest and captured-trust receipt on success.
Invalid explicit CA values never select system trust. There is no verification
bypass field or insecure retry. A TLS success does not prove API permissions or
application health. The interpreter and default trust store remain runtime inputs.
See Python's [SSL context and in-memory CA data reference](https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_verify_locations).

## Interpret the result

JSON input and API data must use finite representable numbers. Literal NaN or
Infinity and overflowing exponents such as `1e999` are refused. Malformed numeric
evidence is not replaced with zero or allowed to escape as a serialization traceback.

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
