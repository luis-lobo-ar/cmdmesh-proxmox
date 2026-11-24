# Fixed reference persistence profile — implementation contract

This profile is under development. It does not yet qualify backup, rebuild or
restore on a real host. The existing memory profile keeps its current semantics.

## Local manifest contract

The first implemented layer is `plugins/module_utils/persistence_state.py` in
the collection. It validates the fixed reference-ledger backup description and
derives the operation-lock identity from retained dataset GUIDs, independently
of any CT VMID. It performs no native command, file write or restore.

A manifest carries source lineage, one atomic sibling snapshot pair, meaningful
record/configuration hashes, the explicit supported UID mapping and the two
ciphertext artifact names, sizes and hashes. Loading requires the manifest hash
from a separately retained trusted completion receipt. A hash taken from the
same untrusted backup store is not that trust source. Schema validity alone
cannot authenticate a sender or prove a live backup.

Eight local cases cover canonical loading, changed lineage, mixed snapshot
generations/GUIDs, foreign siblings, extra secret fields, path traversal, boolean
sizes, unsupported mapping, missing meaningful records and duplicate/version
errors, floating-point mappings and deeply nested inputs. Recipient syntax is
checked here; the standard age implementation must validate its checksum during
preparation. Native phase collection/dispatch and actual backup/rebuild/restore
evidence are still pending.

## Local encrypted stream component

`persistence_stream.encrypt_snapshot` runs a fixed full `zfs send -p` through
standard age encryption. It accepts pinned executable references and existing
exclusive ciphertext/journal descriptors; it cannot execute a supplied shell
command or application hook. The caller still owns target identity, snapshot
creation, exact NFS backing, private prefix creation and independent readback.
The caller must also publish and fsync the containing directories before
dispatch; descriptor-only code cannot establish directory-entry durability.
This component requires Linux pidfds/procfs and the default child reaper.

The isolated worker starts behind a pipe gate. Its PID, start ticks, code hash,
parameters and output identity are written and fsynced to a private armed record
before the parent releases either tool. Parent loss before release closes the
gate without launching them. The worker hashes ciphertext as it is produced,
handles short writes, waits for both producer and encryptor, fsyncs output, then
reports the result. Independent readback must match that produced digest; a hash
calculated only from mutable NAS bytes is not sufficient.

The parent bounds diagnostic bytes, ciphertext bytes and the command deadline.
It retains its child anchor until the session group is closed. A hard-NFS write
can resist termination: the result stays uncertain and no accepted manifest may
be written. Partial ciphertext and its consumed operation evidence stay available
for reconciliation. Never infer backup success from age accepting a truncated
producer stream or from the final process exit alone.

Sixteen local cases use real age1.2.1 with a synthetic producer, never live ZFS:
roundtrip/decrypt, producer failure despite successful encryption, bad recipient,
file cap, timeout with a forked child, changed tools, nonzero offset, stderr flood,
failed consumer with a sleeping producer, missing worker result, failed arming
fsync, durable-before-dispatch ordering, partial writes, a hidden live descendant
parent death before gate release and malformed deep result frames. CI builds the pinned
standard tools in private project scratch so these tests do not silently skip.
These component tests do not qualify a real snapshot, NAS write, restore or reboot.

## Source-state observer

`persistence_observe.observe(request)` is the read-only native source observer.
It checks host machine/certificate fingerprints, exact expected installed
versions, mount namespace and early guest ownership/isolation/bind mounts before
reading the declared retained application files. A second observation must match
before the result is returned. The source's inventory origin is a caller-provided
label; machine and certificate fingerprints establish native host identity.

The request has schema version 1, `source`, `policy`, `reference_guard`,
`backup_store` and `versions`. `source` uses the manifest source identity schema.
`policy` is the initialized reference pre-start policy schema 2.
`reference_guard` identifies an absolute non-symlink regular file by `path` and
`sha256`. Only guard SHA-256
`8a96f2ce9fcfce64221263f3fee70b399449d5a66d2d6d938a493bcdcf9666e1`
is supported. Obtain it from `cmdmesh-recipes` commit
`879c157648bd7eb0de33412edfa002d1cb701e49`,
`examples/reference-ledger/prestart_guard.py`, and install it without group/other
write permission. This is a fixed shared reader, not a supplied executable hook.
It retains rootfs, generated LXC policy, idmap and ZFS GUID/ownership checks.

`backup_store` declares `mountpoint`, exact NFS `source`, and expected new-file
`file_uid`/`file_gid`. Observation proves one exact NFSv3 hard/TCP mount with
nodev/nosuid/noexec and explicit nolock/local_lock=all; it reports the export root's
actual metadata and never changes it. It does not yet prove creation permissions,
mapped ownership of new files or durability of future writes.

`versions` pins `pve-manager`, `pve-container` and `zfsutils-linux` to their actual
installed versions. The prototype accepts PVE 9, container 6 and ZFS 2.4 families
only, and still requires an exact request match. This is a conservative input
boundary, not certification of every combination in those families.

A running guest produces `quiesced: false`, `application: null` and
`backup_verified: false`; its live database metadata is not consistency evidence.
For a stopped guest, the observer takes a nonblocking exclusive flock on the
existing retained `application.json`, checks the exact private owner/mode,
schema/identity, SQLite integrity and meaningful records through a read-only,
immutable connection, then repeats hashes and state checks. It refuses SQLite
sidecars rather than silently ignoring a WAL or journal. Results contain record
counts and hashes, never credentials or record values. `source_state(request,
require_stopped=True)` holds that same lock across a caller's operation. It does
not stop/start guests, create files or repair data/ownership.

Thirteen local cases cover unsafe guest configuration, competing/unsafe locks,
real SQLite reads and corruption, sidecars/symlinks, exact backing, rejected guard
substitution, trust ordering, running-state limitations, changed state and the
actual pinned guard/request contract. Native API trials proved that PVE returns
`/pending` rows in varying order even when every value is identical. The observer
sorts those rows by their unique key and rejects malformed or duplicate keys;
it preserves every value, pending marker and deletion marker. Real changes still
refuse. Full native qualification remains pending.

The reference workload is a private SQLite ledger in an unprivileged, NIC-free
LXC. Its root filesystem contains replaceable program files. Separate sibling
ZFS datasets retain its database and configuration, including application
identity and authentication material. Initialization is a separate, explicit
bootstrap; recovery must never initialize empty data or repair ownership.

## Operations

| Action | Required evidence | Permitted changes | Independent acceptance |
| --- | --- | --- | --- |
| Backup | Exact host/guest ownership, dataset GUIDs and mounts; stopped guest; exclusive retained-config lock; real NFS backing; encryption recipient and tool hashes | One same-generation snapshot pair, encrypted full streams and manifest in a new owned backup directory, consumed-intent journal | Re-read snapshot identities, stream sizes/hashes, mounted backing and manifest; source data and permissions unchanged |
| Rebuild | Existing retained data/config identity; old guest stopped; fresh destination VMID/rootfs absent; qualified program/template | New owned rootfs and NIC-free, onboot-disabled guest, same retained bind mounts and startup guards | Authenticated original record/identity/credential and permission checks, plus an idempotent nonce write; original rootfs retained |
| Restore | Frozen trusted backup receipt and actual artifact hashes; fresh owned storage; safe destination config; recovery identity reference | Decrypt verified full streams into absent datasets, new isolated guest/rootfs, new destination guard policy | New dataset/storage identities with original application lineage, original record/credential/permissions and a new authenticated nonce |

Preparation observes actual state and freezes a versioned intent. Preflight
repeats its load-bearing checks immediately before execution. A consumed intent
cannot be replayed, including after an uncertain result. Verification reads actual
state independently; a successful command alone is not `verified`.

These are finite operations. Inputs do not contain shell commands, arbitrary
hooks or paths to executable recovery scripts. Unsupported shapes refuse. There
is no force receive, dataset adoption, automatic retry or destructive rollback.

## Application consistency and competing writers

The writer lock belongs to the retained configuration file, not a VMID. The ledger
holds an exclusive lock for its whole lifetime. A backup/rebuild action must
prove the old LXC is stopped and acquire that same lock before touching its
retained pair. A new guest must retain the existing lock behavior and both normal
and debug pre-start guards. Two different VMIDs cannot become simultaneous
application writers merely because their numeric IDs differ.

Backup snapshots both datasets in one ZFS transaction. Verify the actual snapshot
GUIDs and equal creation transaction groups; a shared name alone cannot prove
that independently created snapshots belong together. Preserve source dataset
GUIDs, application identity, config hash and the meaningful record evidence in
the manifest. The sender must not read an inconsistent live SQLite database as
a substitute for quiescence.

## Independent encrypted storage

The backup directory must be backed by the exact pre-mounted NFS export on the
managed host. A directory with the expected name on the root filesystem is a
refusal. Recheck mount identity before writes and final acceptance. Do not change
an export, physical-host mount or repository policy to make a trial pass.

Use the standard age implementation with an explicit public recipient. Keep its
private recovery identity outside the source VM. Never put a secret in command
arguments, plans, public examples or logs. Stream outputs are created exclusively
inside a newly owned directory; incomplete artifacts are retained as failed,
not renamed into accepted backups or overwritten on retry.

Record both send and encryption outcomes. Bind ciphertext byte counts and
SHA-256 hashes in the manifest, then retain its trusted hash in the controller's
completed receipt. Age encryption authenticates ciphertext integrity; it does
not authenticate who encrypted it. A manifest found on the backup store is not
trusted by itself. Restore must consume the separately retained completed receipt
and reject modified, mixed-generation or truncated artifacts before allocation.

## Recovery boundary

Restore must work with the source VM stopped and its disks unavailable to the
destination. It must not contact the source to satisfy a preflight check. Original
host/guest/dataset identities in the manifest describe lineage; destination
identities are freshly observed and recorded separately.

Receive only into absent owned storage; never overwrite an existing dataset.
Restored guests have no NIC, no automatic start, no HA membership and no foreign
hook. Retain original resources and failed partial allocations until reconciliation
establishes their ownership. Cleanup removes only explicitly owned outputs.

Actual qualification must cover missing mounts, wrong GUID/idmap, competing
VMIDs, mixed generations, invalid permissions/nonce, a full or unmounted backup
store, truncated ciphertext, unsafe restored networking/onboot/HA, unavailable
source, partial receive/allocation, replay and foreign cleanup. A nested trial
sharing one physical host does not certify recovery from that host's loss.
