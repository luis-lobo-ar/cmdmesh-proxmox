# Watching one expected control-file publication

The developing `persistence_owner_publication_witness.observe_control_publication`
context derives one fixed destination and payload from the binding, selected H0
and finite action. It accepts no caller-selected path, mask callback or skip-lock
mode. `event_profile` must explicitly select
`linux-procfd-parent-modify-create-close-v1`.

| Action | Fixed publication |
| --- | --- |
| `finish-runtime` | The declared runtime profile in an existing empty runtime directory. |
| `record-intent` | The selected H0 in an existing empty pair directory. |
| `publish-marker` | The H0-derived marker in the existing legacy pair. |
| `record-completion` | Selected, semantically validated completion bytes. |

Create the witness before releasing the read-only attempt inspector, then retain
the outer immutable-old, reference, database and actual lease witnesses. The
context watches the planned parent; it does not replace those outer witnesses
or perform external capture/plan matching, current admission or worker fencing.
The executor that composes these scopes is still required.

Inside the context, call `publish()` once. It invokes the actual atomic publisher
and binds its frozen receipt to the selected destination, payload, held parent
and newly held final-file descriptor. A failed call consumes the attempt; the
same scope cannot retry it, even if the failure happened before a write.
The scope belongs to its creating process; a forked child cannot publish through
an inherited witness. Any publication or public seal-check failure permanently
poisons the context, including when a caller catches that exception.

The bounded event language permits anonymous-name MODIFY events, exactly one
fixed-name CREATE, then the original anonymous write descriptor's CLOSE_WRITE.
The anonymous name comes from the atomic receipt's actual held procfd observation;
it is not guessed from an arbitrary queued event. A wrong token, named-final
write, unexpected sibling, move/self event, overflow or exhausted event budget
refuses. Every phase validates its baseline; no event queue is reset.

The final file is watched before admitting the queued publication events. Later
mutations refuse, including equal-byte writes. Owned parent membership/metadata
becomes immutable after its one expected transition. The shared runtime parent
retains the source-defined stable-five/projected-sibling policy. This requires
cooperating controllers and a separately qualified managed kernel/filesystem
event profile; it is not protection against hostile root or FD theft.

Marker publication also holds and authenticates the stored H0. Completion holds
the stored H0 and marker, including the exact descriptors in its payload. Missing,
changed or stale dependencies refuse before writing a new fixed record.

`receipt` remains a candidate until the context and all outer resource/lease exits
succeed. `seal` provides `check_memberships()`, `close_named()` and `check_events()`
for joined closing stages. When the caller performs the final joined membership
scan, context exit performs only named/memory/event closure; it adds no late scan.
All readers release on failure. An unknown publisher result can leave a complete
unaccepted file; the witness never reconstructs a receipt from that file.
Repeated cleanup is idempotent and cannot close a reused descriptor belonging to
an unrelated resource. Ambiguous failed descriptor closes are not retried.

This witness's completion validation still uses the existing os-quiesced
semantic format for local fixtures. The separate
[phase-aware codecs](owner-phase-aware-completion.md) implement version-2
contracts, completion and plans. Their integration with this witness, fresh
current admission and reconciliation must pass qualification before managed
handoff publication is accepted.

Tests use disposable metadata and actual local inotify, procfd linking and file
descriptors. They cover all four payloads, single-use/failure behavior, immutable
inputs/dependencies, transient extra names, wrong tokens, equal-byte mutations
and unknown results. They establish no live current, native, physical power-loss
or disaster-recovery acceptance.
