# Fixed reference persistence profile — implementation contract

This profile is under development. It does not yet qualify backup, rebuild or
restore on a real host. The existing memory profile keeps its current semantics.

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
