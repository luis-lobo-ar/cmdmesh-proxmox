# Inspecting and publishing phase-aware handoff metadata

These developing SDK entry points connect version-2 completion semantics to
the existing metadata observer, capture replay and publication witness.
They do not implement a managed recovery executor.

Every version-2 entry requires the decoded checkpoint and its selected hash,
the binding, exact H0 bytes/hash, and selected contract bytes/hash. A checkpoint
hash alone is insufficient. Selection validates the original and private input
views; it does not discover authority from a node-side file.

| Entry point | Result |
| --- | --- |
| `persistence_owner_attempt.inspect_attempt_v2` | A read-only observation with held file/event readers and canonical capture2 bytes. |
| `persistence_owner_attempt_codec.validate_capture_v2` | Pure reconstruction of a selected, nonblocked capture2. |
| `persistence_owner_continuation_v2.prepare_continuation` | One exact missing-record plan from the actual selected capture2. |
| `persistence_owner_publication_witness.observe_control_publication_v2` | A single-use witness for one of four fixed publications. |

These are borrowed-lease interfaces. The caller must retain the actual pair
exclusive, native configuration shared and application exclusive leases, plus
source/actor qualification and current admission. They are not standalone
commands to run without that controller context.

## Historical and current completion records

Capture2 includes the checkpoint/contract hashes and source-derived completion
schema/disposition. These labels are recomputed during replay.

| Observed completion | Classification | Ordinary publication plan |
| --- | --- | --- |
| Absent, with a valid prefix | Existing finite prefix stage; `absent`. | Only the exact missing edge. |
| Valid schema1 with matching actual dependencies | `complete-candidate`; `historical-requalification-required`. | Refused. |
| Valid schema2 matching the selected contract and actual dependencies | `complete-candidate`; `semantic2-candidate`. | Refused. |
| Partial, malformed, noncanonical, unknown schema or stale dependencies | Blocked; `invalid`, with bounded forensic bytes where the reader permits. | Refused. |

The observer compares completion descriptors with the actual held H0 and marker
files. A structurally valid descriptor in a payload is insufficient. Unsafe or
oversized entries retain the existing refusal policy. Pure replay rejects
blocked captures; it does not claim to replay arbitrary unsafe filesystem state.

Neither complete-candidate class establishes that a callback succeeded or was
lost. Both remain non-authoritative observations. A separate fresh post-publication
qualification is required before recovery acceptance. Partial files must be
preserved for explicit reconciliation, never appended, converted or reset.

Legacy inspector/replay APIs retain their schema1 behavior. Legacy completion
validation remains available for historical review. A new version-2 planner
rejects schema1 captures and plans; it never strips fields to fabricate an older
capture or substitutes a selected hash. The shared pure storage-field assembler
preserves the old planner's canonical output bytes.

## One controlled publication

The version-2 witness validates the selected checkpoint and contract before
opening observers for all four actions: runtime, H0, marker and completion.
It rechecks selection at the last prewrite boundary and through resource exits.
Only schema2 completion bytes may enter `record-completion` through this API.
Runtime2, bootstrap, H0 and marker bytes remain unchanged.

The anonymous-file publisher, closed receipt, finite inotify language, dependency
readers, process ownership, sticky failure and idempotent release behavior are
shared with the existing witness. There is no caller-selected validator, mask,
alternate publisher, supplied receipt or fallback to legacy semantics.

The intended executor must retain overlapping observation scopes:

1. Hold the true leases and permanent immutable-old/reference/database witnesses.
2. Inspect the fresh attempt, match its selected plan and arm the planned
   publication witness while the inspector remains active.
3. Close the read-only inspector before the intentional publication, with the
   replacement witnesses still armed.
4. Publish once, then obtain post-publication current/database and joined resource
   closure without resetting an event queue.
5. Await all resource and lease exits before externally accepting the outcome.

Keeping an absence watch across its own intentional write correctly refuses.
Dropping it before replacement observers are armed creates a gap. Local tests
prove that the inspector/planned-witness overlap can close and then publish, and
that a same-byte old-file write during that overlap is still detected. They do
not implement or qualify the full permanent reference/database/lease envelope.

The managed event/filesystem profile, real fresh current/SQL ordering, worker
inventory and fence, final post-H1 observation, lost-callback acceptance and native
successor admission remain separate qualification work. No valid selection,
capture, plan or leaf receipt grants those permissions.
