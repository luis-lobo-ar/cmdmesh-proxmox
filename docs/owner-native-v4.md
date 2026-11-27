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

The private v4 coordinator now has its own pair/configuration/application lock
scope and separately closed running/stopped current contexts. Its single-use
worker window releases only the target configuration lock and reacquires it on
exit. The original entry remains unchanged; the final phase has a separate entry.
Failed current checks poison the scope. Failure reporting uses only the v4 journal
and retains the pair lock until the failure-record attempt finishes.
An operation error remains the primary error even when a subsequent lock-close
fails; cleanup still attempts every owned lease exit.

These are private lease helpers, not an admitted operation API. Their local tests
exercise real flocks with explicitly modeled current/native providers. The
admitted initializer, preparation, request dispatch, task polling and status API
are still unfinished.

The complete executor must also authenticate its executing source and qualified
storage before native work. Immutable historical observers
must remain held across separately closed before/after phase observations.
It must qualify journal storage, serialize namespace bootstrap and refuse
partial or foreign state.

## Storage bootstrap and diagnostic

The private storage helper uses a separate owner-neutral v4 bootstrap mutex.
It serializes only short namespace initialization. Read-only inspection accepts
an absent namespace or an exact unused genesis; partial, foreign and used state
is preserved and refused. Initializing an unused v4 namespace does not migrate
or reset either historical namespace and does not authorize a native action.

`probe_protocol` is an explicit mutation diagnostic. It creates a unique sibling
under the fixed runtime parent, exercises named exclusive writes, replacement and
directory fsync, and checks the common mount, host epoch and kernel release.
It binds the created directory's held/named identity before the first sync.
Success removes only its verified scratch. Unknown children, replacement or IO
failure refuse a result and preserve the remaining evidence.

The returned candidate has `filesystem_qualified=false` and
`native_action_dispatched=false`. A source-authenticated controller must accept
the closed result and construct a separate native filesystem qualification.
The existing metadata-publisher qualification alone is insufficient.

## Native execution assertions

The pure admission loader reuses a metadata Admission selected for read-only
handoff requalification. It additionally requires the native SDK source roles,
an exact review of the original H1/capture/contract, and a separate native
filesystem qualification. The protocol probe must match the selected common
parent, mount, host epoch, kernel, payloads, file ownership and executing source.

These are externally selected assertions. Loading them performs no IO and does
not authenticate the installed producer, verify a live filesystem, acquire a
lease or authorize a native request. `describe()` keeps those authority claims
false. The coordinator still needs actual held historical/source controls and
fresh intrinsic filesystem/current checks before it can dispatch work.

For each consumed operation it must issue at most one native request. The
privacy-safe response observation must be durably recorded as `ack-observed`
before acknowledgment qualification. Uncertain responses or failed final checks
must remain unqualified without replaying the native request. The legacy v3
journal and any pending operation remain unchanged.

Local tests use synthetic metadata and disposable local resources. They do not
qualify a managed producer, filesystem, native lifecycle or independent restore.
