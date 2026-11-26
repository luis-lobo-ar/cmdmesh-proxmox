# Native lifecycle v4 integration

The native lifecycle integration is under development. The historical handoff
selector is available as an internal SDK component. It does not initialize a
journal, acquire locks, inspect a host or authorize a native operation.

## Keep historical completion separate from executing code

A completion record belongs to the publication contract that created it. Updating
the executing source manifest does not rewrite that record or its original
contract. `select_native_handoff` takes a current semantic selection and three
externally selected raw-byte/hash pairs:

- The original publication contract.
- The retained schema-2 completion record.
- A complete schema-2 capture containing those exact completion bytes.

The selector validates both contracts against the same checkpoint, intent and
guest binding. It validates the retained completion and capture under the
original contract. Schema-1 completion is refused instead of being upgraded.
Inputs and protocol configuration are revalidated when the result is used.

Its `journal_binding` identifies a separate version-4 request journal. The lineage
digest includes the journal profile, checkpoint, intent, original contract and
completion. A new executing source manifest does not change that lineage.
Executing-source authentication remains a separate per-operation requirement.

The binding is metadata identity, not native admission. `describe()` explicitly
reports that producer authentication, filesystem qualification, live leases,
native authorization, dispatch and acknowledgment recovery have not occurred.

## Remaining executor requirements

The v4 executor must acquire its own pair/configuration/application locks and
validate fresh running or stopped observations. Immutable historical observers
must remain held across separately closed before/after phase observations.
It must qualify journal storage, serialize namespace bootstrap and refuse
partial or foreign state.

For each consumed operation it must issue at most one native request. The
privacy-safe response observation must be durably recorded as `ack-observed`
before acknowledgment qualification. Uncertain responses or failed final checks
must remain unqualified without replaying the native request. The legacy v3
journal and any pending operation remain unchanged.

Local tests use synthetic metadata and disposable local resources. They do not
qualify a managed producer, filesystem, native lifecycle or independent restore.
