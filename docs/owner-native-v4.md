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

The coordinator now exposes admitted initialization and read-only initialization
inspection. Lifecycle preparation, request dispatch, task polling and status
remain unfinished. Local tests exercise real flocks and journal files with
explicitly modeled current/kernel and producer/actor providers.

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

## Inspect or initialize unused v4 metadata

The internal SDK entry points are `genesis_sha256(admission)`,
`inspect_initialization(admission=..., expected_head_sha256=..., check_mode=...)`
and `initialize(admission=..., expected_head_sha256=...,
allow_mutation=True, check_mode=False)`.

The caller supplies a `NativeAdmission` and authenticates the installed producer.
An externally selected head must match the derived genesis. Inspection creates
neither a mutex nor journal metadata and supports check mode. Initialization
requires exact boolean permission in normal mode; it accepts absent or complete
unused metadata only. A foreign, partial or used namespace is preserved and
refused. Repeated explicit initialization of an unused genesis is idempotent.

Both operations acquire their own pair/configuration/application locks. Original
completion forensics, immutable resources, actor/source controls and matched live
filesystem facts remain held across two separately closed current observations.
Initialization's short native bootstrap lock is held between those current
workers, never during SQL. Database and joined observer checks run before the
write and after the final worker. Every resource and lease exit precedes return.

Actual native directory and file descriptors must belong to the same qualified
mount as the fixed common parent. A separate submount or bind mount is refused,
even if its device/inode happens to match. Existing native parents remain held
through initialization. Afterwards, an immutable unused-namespace observer joins
the final membership, named-file and event checks and remains active through all
outer exits. That includes absence observations during readonly inspection and
same-byte writes to the newly initialized HEAD. Other valid sibling owner pairs
may change without invalidating this owner's observation.

The result is a canonical candidate with the selected head, before/after current
evidence, initialized/would-change/changed fields and an explicit write-attempt
flag. A late current, observer or lease-exit failure suppresses it. Existing
partial or complete metadata remains for explicit inspection after a failure;
the initializer does not remove evidence, compensate or retry. It does not
reinterpret the metadata Admission's readonly action as a metadata-publication
grant: native initialization has a distinct nominal admission and permission
boundary, and the live filesystem is matched through fixed observation primitives.

An initialized genesis supplies no native or successor permission. No native
request, ACK recovery or legacy journal mutation occurs. Managed producer
qualification and independent acceptance of the returned candidate are still
caller responsibilities. The lifecycle and recovery requirements below remain.

For each consumed operation it must issue at most one native request. The
privacy-safe response observation must be durably recorded as `ack-observed`
before acknowledgment qualification. Uncertain responses or failed final checks
must remain unqualified without replaying the native request. The legacy v3
journal and any pending operation remain unchanged.

Local tests use synthetic metadata and disposable local resources. They do not
qualify a managed producer, filesystem, native lifecycle or independent restore.
