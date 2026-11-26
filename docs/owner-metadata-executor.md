# Executing and requalifying owner metadata

`persistence_owner_metadata_executor` is a developing self-leased SDK executor.
It acquires its own pair, native-configuration and application leases. It never
starts or stops a guest. Managed qualification remains pending. Local tests use
real Linux locks, files, events and publishers with modeled native/current/source
boundaries.

Owner handoff components require ordinary Python 3.11 or newer on 64-bit Linux.
The local qualification used Python 3.12.3; managed qualification must check the
target interpreter and filesystem too.

## Select the operation

| Entry point | Required immutable `Admission.action` |
| --- | --- |
| `execute_begin` | `begin`. Create the declared runtime/pair/H0 prefix, ending at `h0-only`. |
| `execute_continuation` | `finish-runtime`, `record-intent`, `publish-marker` or `record-completion`. Publish only that missing record. |
| `requalify_complete` | `requalify-complete`. Read retained metadata and obtain fresh closing evidence without changing it. |

Write entry points take these keyword arguments:

- `admission`: the selected [execution admission](owner-execution-admission.md).
- `capture_raw`, `capture_sha256`: the selected closed capture2.
- `plan_raw`, `plan_sha256`: its selected begin or continuation plan.
- `phase`: `os_quiesced` or `stopped`.
- `prior_runtime_raw`, `prior_runtime_sha256`: the last accepted running
  observation, required explicitly for a stopped entry.
- `allow_mutation=True`, `check_mode=False`: explicit normal execution mode.

Mode fields require exact booleans. Check mode cannot publish or return a fake
successful write. No entry point accepts a borrowed scope, worker callback,
arbitrary destination, alternate backend or supplied receipt. The trusted
controller must authenticate and select the source package and input hashes.

## Publication order

The full attempt inspector starts before the projected old-root observer.
Original journal, reference, database, actor and vendor-source observations are
armed before the first current-state SQL worker. Its closing frame is E1.
Completion publication derives H1 from that actual frame.

Selected actor records retain their existing raw-text and identity schema. The
executor derives each expected SHA256 from the exact UTF-8 raw bytes, including
empty text and trailing newlines, then compares the fresh held file's bytes and
identity. It does not require an additional stored digest field. Vendor files
retain their independently selected expected digests and fixed file policy.

The second context supplies the post-publication closing frame E2. Pending
resource events are checked after its initial worker and before the first write.
Directory and publication witnesses overlap before the preceding observer
closes. Runtime initialization and `finish-runtime` use the short shared
bootstrap mutex, released before another SQL worker.

After E2, the executor seals the database, performs fixed current checks, joins
membership scans, closes named metadata/process facts, and checks events. Every
resource and lease must exit successfully before a candidate is returned.
Cleanup preserves the first failure and attempts remaining exits.

An error can leave a full unaccepted file. Inspect and select that state for a
separate operation. Never overwrite, append, reset or automatically retry it.

## Requalify a full candidate

`requalify_complete` additionally takes `complete_raw` and `complete_sha256`.
For H1 schema2, provide its original `original_contract_raw` and
`original_contract_sha256`, even when the current executing contract differs.
The preserved capture and H1 retain the original contract. The outer result
identifies the current execution policy.

Schema1 uses its explicit historical completion codec. A sound schema1 H1 under
runtime1 follows a distinct read-only forensic path. Its capture stays labeled
`blocked` with the sole legacy-runtime-profile reason. Ordinary planners and
write entry points continue to refuse runtime1. No bytes are normalized or
rewritten.

Fresh requalification does not establish that the original callback, fsync or
native operation succeeded. Unknown entries, partial records, incompatible
profiles and missing original inputs refuse this path.

## Accept the closed result externally

`Candidate(raw, sha256)` records the selected admission/checkpoint/contract,
closing frames, final capture and publication receipts. Original native
qualification, recovered ACK, native dispatch, successor native admission and
metadata acceptance flags stay false.

The controller authenticates the closed source/input/transport receipt and
applies its action-specific acceptance policy. Preserve the exact returned
bytes within a declared output budget. This executor alone is not a
disaster-recovery proof or native permission.
