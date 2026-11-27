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

The coordinator now implements admitted initialization, read-only initialization
inspection, lifecycle preparation/reinspection, one observed native operation,
captured-result validation and read-only status. The new operation path remains
under qualification. Local tests use real flocks and journal files with explicitly
modeled current/kernel and producer/actor providers. Managed execution and
recovery acceptance remain separate requirements.

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

## Prepare and inspect a lifecycle action

`prepare(admission=..., kind="shutdown"|"resume", accepted_head_sha256=...,
prior_runtime_raw=..., prior_runtime_sha256=..., check_mode=...)` observes an
externally selected ready predecessor. It creates no slot or phase record and
sends no native request. Shutdown requires a running, quiesced guest and no
prior override. Resume requires an explicit valid running prior and a stopped
guest. Both support read-only check mode.

Original history, application/resource/actor controls, qualified native parents
and an immutable ready-chain observer remain held across two separately closed
current workers. The ready observer covers runtime/profile/genesis/HEAD and all
accepted prior operation files. A pending or stale head refuses preparation;
filesystem identity, content metadata, membership, transient events and final
resource exits can also suppress the candidate.

The canonical prepared record binds the native admission and producer, exact
predecessor, kind, stable entry, init identity, uptime floor, backup mount and
explicit prior. Its current observation is historical evidence, not an active
lease or dispatch permission. The caller independently selects the returned raw
bytes and hash.

`inspect_transition(admission=..., prepared_raw=..., prepared_sha256=...,
check_mode=...)` reobserves those assumptions under its own complete lease and
observer interval. Stable assumptions must match and uptime may advance but not
decrease. The inspection reports the original selected preparation and a fresh
observation; it does not replace the preparation or advance journal authority.

The internal journal adapter now implements a source-fixed begin, four append
phases and completion over the unchanged v4 primitives. It retains immutable
runtime/profile/genesis and accepted prior slots across each intended write.
New phase files are added to the retained observer monotonically. A separate
exact-chain observer covers each quiet boundary, including the final candidate.
Only the affected HEAD/current-slot boundary guard is retired for a write;
the immutable observer and its event queue are never reset.

Each adapter instance can consume only one operation. Wrong phases and duplicate
begin calls refuse before publication. Once publication starts, any failure
poisons that adapter, including a primitive that writes and then fails before
returning. The latest returned Pending remains available to the coordinator's
failure path. An observed response survives failed ACK qualification without an
ACK or result being published. The adapter itself sends no request, acquires no
pair lease and grants no native authority.

The coordinator owns real pair exclusion, closes current workers before its
single POST, records the response before ACK qualification, polls only the
acknowledged task and includes both journal readers in its final joined closure.
This scope does
not claim continuous absence of an unrelated transient child inside a newly
created directory before a watcher can be armed, or an arbitrary-root syscall
sandbox. Such a transient changes no accepted record or operation authority;
persistent unknown state remains refused. Existing journal primitives and their
qualified protocol are preserved.

Local tests use synthetic metadata and disposable local resources. They do not
qualify a managed producer, filesystem, native lifecycle or independent restore.

## Execute one prepared action

`operate(admission=..., prepared_raw=..., prepared_sha256=...,
allow_mutation=True, check_mode=False, timeout_seconds=240)` is an internal SDK
entry point. It requires explicit boolean mutation permission and refuses check
mode. The timeout must be an integer from 1 through 600 seconds and bounds native
task polling; it is not a total preparation or operation deadline.

The coordinator acquires its own pair, retired/target configuration and
application leases. It matches the saved target, init identity, uptime floor and
backup mount against fresh observations. It consumes one ready slot and records
dispatch while the before-phase current worker is active, then fully closes that
worker before releasing the target configuration lease for the native request.
The other leases and immutable historical observers remain held.

The HTTPS provider records actual send/receive clocks, TLS and a privacy-safe
response. The coordinator durably appends `ack-observed` before qualifying the ACK
and polls only that ACK's exact task. A delayed closing worker does not make the
old dispatch timestamp an ACK deadline. An accepted terminal task is followed by
target-lease reacquisition and a separately observed final guest phase. Final
database, membership, named-file, memory and event checks use that phase's entry;
the original before-phase entry is never repurposed.

The returned dictionary contains canonical operation records and their hashes,
before/final current evidence and the native outcome. It remains a candidate for
independent acceptance. Application writes, backups, rebuilds, restore and
successor permission are explicitly unverified. The application remains quiesced.

`validate_result(admission=..., prepared_raw=..., prepared_sha256=...,
result=...)` checks a captured return without IO. It reconstructs only v4
documents and checks the recorded response/ACK/task chain against the prepared
target and current evidence. It bounds expanded JSON before encoding, validates
a private snapshot and rechecks the original caller-owned input before returning.
It does not inspect a live host or accept the
result's head on the controller's behalf.

After slot consumption, lost responses, invalid ACKs, timeouts and failed final
checks leave unqualified evidence. A best-effort v4 failure record is attempted
while pair exclusion is still held. It can also block a candidate published
before a late closing failure. The coordinator never retries a native POST,
removes a failure barrier, adopts ambient HEAD or resets either historical
namespace. Preserve the evidence and use an independently reviewed recovery
procedure after an uncertain outcome.

## Recheck an accepted action

`status(admission=..., prepared_raw=..., prepared_sha256=...,
accepted_head_sha256=..., prior_runtime_raw=..., prior_runtime_sha256=...,
check_mode=False)` reads an externally accepted ready head. It checks that the
recorded operation belongs to the selected preparation, rechecks its exact task
and observes current state under its own leases. It creates no files and sends
no POST.

After shutdown, supply the explicit running prior from the accepted result's
`before.observation`, encoded canonically with its SHA256. Status requires it to
match the recorded prior exactly. After resume, omit the prior override. A stale,
pending, foreign or failed head refuses status; status cannot turn an uncertain
operation into an accepted one.
