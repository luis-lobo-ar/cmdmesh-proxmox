# Planning one missing owner-handoff record

These are developing internal APIs. They do not execute a continuation, acquire
leases, authenticate an observation producer or authorize a native operation.
The existing retirement writer does not use them yet.

An interrupted metadata operation can leave a valid prefix. The next caller
needs to distinguish that prefix from a partial, inconsistent or foreign
record before selecting any write. A reported status label is insufficient.

## Validate selected capture bytes

`persistence_owner_attempt_codec.validate_capture(binding, h0_raw, h0_sha256,
capture_raw, capture_sha256)` validates an externally selected inspector record
without filesystem or network access. It validates bounded tables, fixed paths,
integer metadata, raw-byte hashes and canonical base64 before replaying the
inspector's existing layout and semantic classifier in memory. The entire
reconstructed canonical record must equal the selected bytes.

The replay rebuilds statuses, flags, policies, required files, memberships and
absence facts. Every present immediate child must appear in its directory's
projected membership; a file descriptor cannot coexist with a claim that its
name was absent from that list. Shared sibling pairs omitted by the inspector's
documented projection are not added back. Missing tables do not imply absence.

Legacy schema-1, partial, unsafe and unknown states refuse this planning codec.
The read-only inspector still preserves their forensic records. Valid complete
candidates can be decoded, but require separate requalification rather than a
continuation plan.

A valid JSON record proves internal consistency only. It cannot prove actual
ENOENT, descriptor ownership, observer lifetime, source authenticity, historical
fsync or live current truth. The later caller must authenticate its source and
closed receipt, then acquire real leases and observe fresh state.

## Prepare a finite plan

`persistence_owner_continuation.prepare_continuation(binding, h0_raw, h0_sha256,
capture_raw, capture_sha256, action)` returns frozen `Plan(raw, sha256)` bytes.
Only these state/action pairs are supported:

| Captured state | Action | Missing fixed record |
| --- | --- | --- |
| `bootstrap-incomplete` | `finish-runtime` | Canonical schema-2 runtime profile. |
| `empty-claim` | `record-intent` | The exact selected H0 in the existing claim directory. |
| `h0-only` | `publish-marker` | The marker derived from that H0. |
| `h0-marker` | `record-completion` | H1, derived later from fresh closing evidence. |

For example, a process can create the claim directory and fail before publishing
its intent. Inspect that exact directory, externally select its closed capture,
then prepare `record-intent`. The plan binds the existing directory and missing
fixed destination. It neither creates a second claim nor pretends the original
invocation published H0. No executor is included in this component.

An unused namespace follows a separately gated clean-begin path. A full candidate
follows separate read-only requalification. No action resets a claim, changes a
nonce, overwrites a record, appends to partial H1, reconstructs a stale capability
or retries the original native request.

The plan binds the selected H0 and whole capture hashes, storage protocol/runtime
profile, stage, action, fixed destination, and known payload hash/size. Completion
has no predicted payload hash or closing evidence. Its future H1 must be derived
from a real closing observation.

## Fresh matching and unsupported restart states

The whole capture hash records provenance; it is not the fresh-state equality
test. The plan separately hashes a source-defined matching policy and expected
projection: files and owned directories close all nine metadata fields, shared
directories and ancestors close five, and memberships/absence retain their exact
source-defined projections. Unrelated valid sibling churn can change unclosed
shared timestamps or directory size. The same change to an owned directory must
change the required projection.

All authority flags remain false. The plan lists the later source/provenance,
worker-fence, native-before-config, current admission, filesystem, observer and
resource-exit gates. Runtime bootstrap also requires short global serialization.

Ordinary completion requires a fresh `os_quiesced` current frame in the selected
epoch. After a manager restart, an `onboot=0` guest may instead be stopped. That
state requires a separately qualified phase-aware reconciliation path. Historical
E0/E1 cannot stand in for a fresh frame; no native ACK or successful original
callback may be invented. This required reconciliation and the metadata executor
remain future work before full crash recovery can be claimed.
