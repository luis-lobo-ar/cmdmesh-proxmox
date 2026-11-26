# Read-only retirement attempt inspection

`persistence_owner_attempt.inspect_attempt(binding, intent_raw, intent_sha256)`
is an internal context manager. The caller must already hold the real owner-pair
exclusive lease, both native configuration shared leases and application
exclusive lease. The inspector does not acquire or certify those leases.
The canonical H0 bytes and digest are externally selected; the node does not
select an intent, authority, successor or path.

The context yields an immutable `Observation` with `raw`, `sha256` and `seal`.
Retain bytes inside the context, but export or accept a candidate only after
successful context and outer lease exits. An exception, observer overflow,
read failure or resource-release failure suppresses a successful return.
The result always says `forensic_only` and `candidate_only`; fence, native,
metadata-resolution, publication and successor-admission flags stay false.

## Evidence and states

The inspector authenticates the old accepted basis, original file hashes and
full nine-field identities, shared runtime and stable parent identities against
H0. The only additional old-pair control is the fixed retirement marker. It
observes the prospective handoff runtime, selected pair, intent and completion
without initializing them. Known zero-byte or partial files are preserved as
bounded base64 bytes, SHA-256 and full nine-field metadata. A symlink, hardlink
or unsafe ownership/mode is metadata-only evidence; it is not followed or read.
Unknown immediate names are visible and block the attempt; unknown directories
are never descended. Do not publish these private raw metadata observations.

| Status | Meaning, without permission |
| --- | --- |
| `unused` | Selected claim is absent; runtime may be absent or valid. |
| `bootstrap-incomplete` | Runtime directory exists empty, without its profile. |
| `empty-claim` | Valid runtime and selected empty claim directory exist. |
| `h0-only` | Exact externally selected H0 exists; marker and H1 are absent. |
| `h0-marker` | Exact H0 and canonical marker exist; H1 is absent. |
| `complete-candidate` | Pure H1 validation and actual H0/marker descriptors join. |
| `blocked` | Partial, foreign, unknown, unsafe or inconsistent attempt. |

Existing schema-1 runtime is explicitly `blocked` with
`legacy-runtime-profile`; it requires a separately reviewed reconciliation.
It is never upgraded or treated as unused. Schema 2 selects exactly
`linux-otmpfile-procfd-exclusive-link-v1` at the unchanged metadata root.
The profile module is a declaration, not an atomic publisher. A complete
candidate does not prove that this protocol was used, an original callback
returned, a historical fsync succeeded, or current/fence truth was admitted.

Only `ENOENT` means absent. Permission and I/O errors propagate. At most 64
immediate entries are scanned at each known level; per-file and aggregate read
limits apply before body reads and to every read request, including growth.
Output is bounded. No generic recursive search or target-selected pathname is
used. This conservative finite profile can refuse very large shared runtimes.

## Joining closing proofs

The seal exposes `check_memberships()`, `close_named()` and `check_events()`.
A composed caller performs **all readers' membership scans first**, then all
named/held metadata and raw-memory checks, final fixed process/root probes, and
event drains. It can include this seal in those stages. The context then
repeats only named, memory and event closure; it does not introduce another
directory scan after the caller's final probes. A standalone caller that has
not scanned after the yield gets an automatic final scan.

Owned exact-membership directories and files close all nine metadata fields.
Shared ancestors and shared runtime directories close stable five fields;
the record explicitly exports `directory_closure_fields`. Shared runtime
membership projects the selected pair, profile and unknown names. Valid
unrelated sibling pair directory churn is allowed, not frozen into an exact
global list. Ancestor identities and absence checks are FD-bound. Selected
name changes, old-file writes (including equal-byte writes), unexpected owned
members, self-events and overflow refuse. Event drains have an eight-batch,
256-KiB budget, so unrelated continuous churn cannot hold leases indefinitely.

The leaf uses Linux read-only FD/inotify syscalls through libc. It runs no
Proxmox/native lifecycle command or subprocess, opens no application database,
configuration plaintext or recovery key, and performs no fsync, metadata write,
claim, repair, ordinary retry or `Claim` reconstruction. Its constants are not
a public skip-lock or callback interface.

Tests use disposable synthetic metadata and real local files, FDs, inotify and
pair-lock fixture setup. Native leases and historical/current truth are caller
obligations, not proved by this leaf. The complete fixture is created using the
older direct writer and has its profile changed **during test setup only**;
this deliberately does not qualify the prospective atomic writer. Tests that
isolate actual mutation events model an equal-metadata closer explicitly.

## Pure validation of selected captures

The developing `persistence_owner_attempt_codec.validate_capture` accepts the
same binding and selected H0 plus externally selected capture bytes and digest.
It validates bounded file bytes, integer identities, paths and tables, then
replays this inspector's layout classifier through an in-memory reader. The
entire canonical reconstruction must match. Present child facts and directory
membership must agree in both directions; omitted facts do not imply absence.

The codec performs no observation or write. It checks internal consistency,
including valid complete candidates, while refusing blocked/partial/legacy
states for continuation planning. It cannot authenticate the producer, actual
ENOENT, held descriptors, observer closure, current state or publication
durability. Those remain caller gates. The live reader's directory observation
is separated from the classifier so accidental filesystem access in pure replay
fails the IO-denial tests.
