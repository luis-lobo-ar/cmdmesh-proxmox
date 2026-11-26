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

`persistence_stream.encrypt_manifest` shares the same gated worker, limits,
durable arming and independent-readback requirement. The action layer must first
validate and construct the manifest; this component freezes up to1MiB of its
bytes in an anonymous, sealed Linux memfd. The worker verifies its length/hash
and seals before standard age reads it. Plaintext is not stored on the NAS or
placed in arguments/journals. Arming records retain its size and hash only.
There is no producer subprocess for this path: `source_kind` is `manifest` and
`producer_exit_code` is null. Snapshot results retain actual producer exit codes.
Eight additional cases cover real-age roundtrip/produced hash, seals before
dispatch, pre-dispatch input limits, encryption failure, incorrect producer
frames, missing seals, input-hash mismatch and ciphertext overflow. Semantic validation
and accepted-backup publication remain the action layer's responsibility.

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
refuse. A disposable running-source trial and independent retained-evidence audit
have passed the native observer/transport/application preservation checks. Its
result correctly remained unquiesced with no consistent application snapshot and
`backup_verified: false`. Stopped-state collection, snapshot/NAS writes, backup,
rootfs rebuild, restore and native maintenance/reboot remain unqualified.

## Fixed backup action API

`persistence_backup.prepare_backup(request)` is read-only. Its request contains
schema version1, a new64-hex `operation_id`, the full observer `source_request`,
the public age recipient, and `tools` references for age and ZFS. Each reference
has an exact SHA-256 and `path`; this prototype fixes those installed paths to
`/usr/bin/age` and `/usr/sbin/zfs`. A request cannot select another executable.
The source must already be stopped. Preparation checks the actual standard-age
recipient parser with empty nonsecret input and hashes the qualified observation.
The backup action never stops, starts or initializes an application itself.

Serialize the prepared value with `persistence_state.canonical`. Retain its hash
outside the managed host as the reviewed intent, and pass those exact bytes and
hash to `persistence_backup.execute_backup(raw, trusted_sha256)`. Reformatting
those bytes requires a fresh preparation. Execution repeats source/tool checks;
there is no force switch, automatic refresh of hashes, replay or state adoption.

The managed runtime is fixed at `/var/lib/cmdmesh/persistence`, with a private
profile marker, retained-GUID-pair flock and exclusive operation journals. The
parent and runtime must be owned/private; existing state is checked rather than
chmodded or initialized over. A consumed intent precedes one atomic sibling
snapshot command and any NAS prefix/write. An incomplete or failed operation
blocks a new operation for that pair until reconciliation. Partial snapshots,
ciphertext and journals are retained; this action performs no rollback deletion.

The new backup prefix includes the owner identity and operation ID. A foreign
prefix refuses before snapshot creation; a creation race still refuses without
overwriting it. Actual mapped ownership and0700/0600 modes are checked. The
shared export root is never chmodded or chowned. Both full streams and the
validated manifest are encrypted with standard age. Independent reopened reads
must match the worker-produced hashes and sizes. After the slower source/tool
closing checks, snapshot GUIDs/creation transaction groups are checked again.
The action then reopens the recorded NAS prefix by name and rechecks backing,
registry, all ciphertext/inodes and hashes immediately before completion.
This catches outputs renamed or modified during those closing checks. It does
not make a mutable backup store immutable; restore must verify the trusted hashes
again when consuming its artifacts. Snapshot command semantics follow the
[OpenZFS snapshot contract](https://openzfs.github.io/openzfs-docs/man/master/8/zfs-snapshot.8.html);
the exact installed CLI behavior still requires the native trial.

`complete.json` is created only after the stopped-source closing checks pass.
The returned receipt binds the manifest, its separately trusted hash, encrypted
manifest identity, snapshot pair, source, store and ciphertext identities. Its
`completion_sha256` hashes the exact private completion file before that extra
return field is added; it is not a recursive self-hash. Copy the receipt to the
trusted controller. A manifest or receipt found on the NAS alone cannot establish
trust. `backup_verified: true` describes this action's source/artifact checks;
it does not certify restoration, storage survival after a power loss or host-loss
recovery. Restore qualification is a separate gate.

Eighteen local action cases use real encryption, files and flocks with synthetic
ZFS/source/mount providers. They cover preparation, a complete synthetic backup,
replay, changed intent/source, sender failure, early/late ciphertext tampering,
changed snapshots, foreign prefixes, actual closing failure, malformed inputs,
incomplete completion, canonical bytes, fixed executables, pair locking,
mount drift, ENOSPC and late output changes during source/snapshot closure.
No native snapshot or NAS write has been qualified yet.
The Ansible module below exposes the action. Catalog/core procedure integration
and real stopped-source qualification remain pending.

## Ansible entry point

`cmdmesh.proxmox.lxc_persistence` is a thin boundary over these same helpers.
It accepts `inspect`, `prepare_backup` and `backup`. It adds no shell hooks,
alternate executable paths, guest shutdowns, implicit retries or repairs.

```yaml
- name: Observe one declared reference source
  cmdmesh.proxmox.lxc_persistence:
    action: inspect
    source_request: "{{ cmdmesh_persistence_source }}"

- name: Prepare the already stopped reference source
  cmdmesh.proxmox.lxc_persistence:
    action: prepare_backup
    backup_request: "{{ cmdmesh_persistence_backup }}"
  register: preparation

# Copy/review and retain the exact preparation on the trusted controller first.
- name: Assess the retained intent without snapshot or NAS writes
  cmdmesh.proxmox.lxc_persistence:
    action: backup
    prepared_json: "{{ cmdmesh_retained_prepared_json }}"
    prepared_sha256: "{{ cmdmesh_retained_prepared_sha256 }}"
  check_mode: true

- name: Execute the separately retained approved intent once
  cmdmesh.proxmox.lxc_persistence:
    action: backup
    prepared_json: "{{ cmdmesh_retained_prepared_json }}"
    prepared_sha256: "{{ cmdmesh_retained_prepared_sha256 }}"
    allow_changes: true
```

These variables contain the request schemas defined above, including host
fingerprints, initialized pre-start policy, actual tool pins and mounted store;
they are not fictional defaults to run against an arbitrary host. Select one
explicit inventory target. Stop the owned source through its verified lifecycle
procedure before preparation. The module never turns a running observation into
a consistent backup by itself.

Backup check mode reports `source-preflight-only`, `would_change: true` and
`mutation_attempted: false`. It repeats the frozen source/recipient checks but
does not create runtime state, consume an intent, check prospective NAS creation
permissions or prove all execution postconditions. A real backup defaults to
refusal unless `allow_changes` is explicitly true. On a permitted backup failure,
`effects_may_exist` is conservative: inspect the root-private journal before
further action. Request/preparation arguments are withheld from invocation
metadata. Framework argument validation uses Ansible's no-log handling; accepted
outputs retain their exact safe correlation hashes. The boundary suppresses
runtime tracebacks explicitly, including when error tracing is enabled, and
returns static errors for unexpected standard exceptions too. Cancellation and
process termination still require independent reconciliation.

Twelve boundary cases cover readonly inspection/preparation, disabled and check
modes, changed source, exact bytes/hash forwarding, failure sanitization, actual
Ansible argument rejection and an actual packaged-module/helper refusal before
accessing an unsupported guard path. Real Ansible renderer cases verify early
argument redaction, withheld failure invocations, suppressed OSError/RuntimeError/
TypeError text with tracing enabled, and uncensored successful canonical bytes
and hashes. The qualified development toolchain pins Ansible core2.19.4.
These tests do not qualify a native backup.

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

## Unmounted receive

The developing `cmdmesh.proxmox.lxc_persistence_receive` module implements only
the storage receive stage of restore. Its local tests exercise real private files,
sealed inputs, process deadlines and synthetic native commands. Native receive,
application recovery and source-unavailable recovery are **not yet qualified**.

Use `action: prepare` with a version-1 `restore_request` and `manifest_json`.
Retain the returned exact `prepared_json` and `prepared_sha256` on the trusted
controller. `action: receive` with those retained values repeats preflight in
check mode. Actual receive also requires `allow_changes: true`. See the module's
Ansible examples with `ansible-doc cmdmesh.proxmox.lxc_persistence_receive`.

The request contains these required fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer `1` |
| `operation_id` | New 64-character lowercase hexadecimal operation identity |
| `manifest_sha256` | Hash from the separately trusted completed-backup receipt |
| `target` | Explicit origin/node, host fingerprints, exact supported package versions, pool name/GUID, empty parent name/GUID and owner tag |
| `tools` | Exact `/usr/sbin/zfs` and `/usr/sbin/zpool` paths and independently qualified binary hashes |
| `streams` | `data` and `config` private plaintext files, each with absolute path, byte count and authenticated plaintext SHA256 |

The target host uses the source observer's three host fingerprints and package
keys. The current supported profile remains PVE9/container6/ZFS2.4. The target
parent must already exist, be a locally owned ZFS filesystem, have `canmount=off`
and `mountpoint=none`, and contain no child, snapshot or bookmark. Preparation
does not create it. A same-host target must not overlap the original datasets.
The module does not create a pool, change guest configuration or obtain access.

**Authenticate before preparation.** The controller must fetch ciphertexts,
compare them to its completed-backup receipt, authenticate decryption with the
original recovery identity, and verify the plaintext manifest against the
externally retained manifest hash. It then records the plaintext stream hashes
in the request. Those stream hashes are controller assertions; a hash supplied
by a backup store or a newly calculated hash of an untrusted file is insufficient.
The module never receives the recovery key. Inputs are full, single-filesystem
`zfs send -p` streams from this profile, not arbitrary replication packages.

Plaintext files and their containing directory must belong to the executing user,
with modes0600 and0700 respectively. Symlinks, multiple links, changed files and
shared data/config files refuse. Execution hashes and copies each input into a
sealed anonymous descriptor before dispatch; the receiver cannot consume later
changes to a path. Each stream is limited to64MiB. The original private files
remain in place for the operator's retention policy.

The parent GUID, pool GUID and host identity bind one permanent consumed claim.
A new operation ID or alias cannot bypass a previous attempt. Before each
receive, the module journals intent and rechecks the exact target. It invokes
`zfs receive -u` with explicit local overrides: `mountpoint=none`, `canmount=off`,
`readonly=on`, `exec=off`, `devices=off`, `setuid=off`, both shares off, and the
target's owner tag. It never uses force, rollback, resume, abort or name-rewrite
flags. The behavior follows the [OpenZFS receive contract](https://openzfs.github.io/openzfs-docs/man/8/zfs-receive.8.html).

The receiver requires Linux pidfds, sealed memfds, procfs and the default child
reaper. An incompatible reaper refuses during preparation. It is armed and
journaled before dispatch. A private PID descriptor
targets that exact process on timeout. Native output is bounded and retained in
private journal files; failures expose static codes rather than exception text.
An unkillable receiver remains explicitly uncertain. There is no automatic retry,
dataset deletion, ownership repair or cleanup of partial results.

Postchecks require exactly the two new filesystems and their expected snapshots,
the snapshot GUIDs in the trusted manifest, safe locally set properties, unchanged
parent/pool/host identity and unchanged input files. Successful output has
`received_verified: true`, but `restore_verified`, `application_verified` and
`source_unavailable_verified` all remain false. A completed receive does not prove
that SQLite records, credentials or application permissions work. Those require
separate mounted-data and authenticated application tests in the isolated guest.

Twenty-three focused cases cover the receive state transitions and native-output
parsers, including existing or foreign parents/children, mounted or writable
results, wrong pool/snapshot GUIDs, changed private inputs, timeout, failed arming,
failed completion publication, replay with a new operation ID, check/disabled
modes and actual Ansible redaction/traceback handling. They use synthetic platform
observations and do not qualify a native receive.

## Stopped rebuild recipient

The developing `cmdmesh.proxmox.lxc_persistence_recipient` module provisions only
the replaceable rootfs and stopped guest. It does **not** finish a rebuild.
Local tests include a real loopback TLS create request; native provisioning is
not yet qualified.

Its `prepare` action takes `recipient_request` with schema version1, an operation
ID, the existing `source_request`, `target`, `template` and `storage_id`.
`target` has an absent integer `vmid`, hostname and new generation tag. `template`
has its volume ID, exact byte count and independently qualified SHA256. Retain the
returned canonical `prepared_json` and `prepared_sha256` on the controller.
`provision` repeats those checks in check mode; an actual create additionally
requires `allow_changes: true`. `status` reads the same consumed attempt and never
reposts, including after an acknowledgement is lost. The module includes copyable
Ansible examples through `ansible-doc cmdmesh.proxmox.lxc_persistence_recipient`.

This first profile supports one standalone PVE9/container6/ZFS2.4 node, local
directory storage at `/var/lib/vz`, at least3GiB available, and an already qualified
Ubuntu24.04 amd64 standard template. Preparation refuses existing cluster IDs,
configs, rootfs directories, pending target state, or different backing/template
identities. Template bytes and source facts are rechecked during execution.
The original stopped source's retained configuration lock stays held throughout;
the source observer checks its record, credentials, mounts and rootfs unchanged.

Creation uses one pinned, hostname/CA-verified HTTPS request to the local PVE API.
It requires root on that already verified node. Native PAM authentication is
assembled in memory by the installed PVE library; tickets are never request
inputs, plans or journal fields. No account, API token or access configuration is
created or repaired. HTTP redirects and retries are not followed.

The new guest is unprivileged, protected, no NIC, no HA, no features/hooks/raw LXC
directives, one core, 512MiB memory, zero swap, a fresh2GiB rootfs, and start/onboot
OFF. It has normal PVE `cpulimit=1`, an aggregate CPU-time limit, not an assertion
of instantaneous single-core execution. **No retained bind mount is supplied to
CREATE.** PVE can mount supplied bind paths writable during template extraction,
even with their `ro` flag; attach retained data only in a subsequent stopped
configuration stage after setup. This module neither attaches nor initializes it.

A permanent claim keyed by host identity and destination VMID precedes dispatch.
It records the exact native UPID, complete bounded task log and result. The known
systemd255/nesting warning is explicitly recognized without enabling nesting;
unknown warnings, incomplete logs and errors prevent acceptance. Postchecks read
the actual stopped state, no pending settings, exact isolation/configuration and
new rootfs path/size/inode/ext4 UUID, then close status, pending, native task/log
and source checks again. The original guest/rootfs remain intact.

PVE returns storage `content` members in per-process Perl hash order. Preparation
canonicalizes only that comma-separated set, preserving every member and all
other storage fields. Reordered members are equivalent; additions, removals,
duplicates, malformed values and other storage changes do not bypass drift checks.
PVE pending rows are also compared in key order while retaining every value;
duplicate rows and pending/deleted settings refuse. The config parser's optional
single trailing description newline is accepted without trimming or changing
the description text. Other description changes remain a mismatch.
The fixed CPU limit accepts numeric1 or PVE's exact JSON string`"1"`; booleans,
zero, other strings and other limits refuse. This reads the configured aggregate
limit; it does not establish runtime enforcement while the guest is stopped.

Success reports `provisioned_verified` only; `rebuild_verified` and
`restore_verified` stay false. A failed/uncertain create preserves its claim and
partial outputs for status/reconciliation. Changing the operation ID cannot retry
the same target. There is no automatic deletion, adoption, start, ownership repair
or credentials reset. Fresh first-boot guard policy, program/account installation,
retained bind attachment and authenticated original-record tests remain later
explicit stages.

The internal verified-HTTPS transport now shares the same CA, leaf, hostname and
ephemeral authentication checks for finite guest start/shutdown actions. It accepts
no custom URL, body, user or lifecycle operation. Each acknowledgement must carry
the exact node, VMID, user and corresponding `vzstart`/`vzshutdown` native task type.
Shutdown fixes `timeout=60` and `forceStop=0`: no fallback to the abrupt kill
performed by Proxmox's separate stop endpoint. A timeout must stay unqualified.
Create remains the default task-reading behavior and retains its fixed payload.
These helpers are not agent-facing operations or permission to start a guest.
A later bootstrap caller must supply stopped-source and recipient qualification,
once-only dispatch journaling, runtime/isolation checks and read-only reconciliation.
This transport change alone performs no boot, bootstrap, stop, bind or recovery.

### Blank OS start guard (developing)

`plugins/module_utils/persistence_blank_guard.py` is also a standalone read-only
program. A future staged profile will install the same invocation in both normal
and debug instance units. It requires an exact NIC-free/bind-free template config,
host and VM identity, a distinct stopped original source, no HA/pending changes,
and the new rootfs inode/size/ownership/UUID. It does not allow an application start.

The policy also pins the entire generated LXC config, normalizing only the
generator-managed CPU selection. A single selected approved CPU or an explicitly
empty inherited selection is allowed only with exactly one native CPU quota of
100000/100000. The actual parent effective CPUs must be a nonempty ordered subset
of the reviewed allowed CPUs. This bounds aggregate CPU time during blank OS boot;
it is not instantaneous single-CPU pinning. A later runtime observer must establish
one effective CPU before accepting the boot. Other generated-byte changes refuse,
including extra mounts or networking. Existing reference application guards remain
unchanged. Direct administrative `lxc-start` bypassing systemd remains outside
managed-start coverage.

The guard closes its root image, UUID, generated bytes and parent CPU observations
after slow API reads. It also asks `pvesm path` where the configured root volume
actually resolves, before probing and at closure; a leftover image at an old
storage location cannot authorize a start. Managed native API starts hold the PVE
config lock across this boundary. This is point-in-time evidence, not protection
from an administrator changing root-owned state outside that protocol.

### Denied configuration generation (developing)

`lxc_persistence_blank_stage` supplies finite `prepare`, `stage` and read-only
`status` actions through Ansible. It requires the original canonical recipient
preparation and a currently qualified stopped recipient. Both instance drop-in
directories and the generated config must be absent. Check mode repeats those
facts and compares the whole frozen preparation without writing.

Real staging consumes a permanent host/VMID claim before writes, publishes false
pre-start commands to both instance units, reloads systemd, verifies both inactive
deny configurations, then requests the same existing cores1/cpulimit1 values
through the local PVE API. It retains the generated file identity/full hash,
stable CPU-normalized hash, native mapping/hostname/rootfs lines and command
outcome. Original source, new image and all guest config remain unchanged.
Status rechecks the retained generated proof; it cannot accept changed bytes as a
new baseline or rewrite journals. Failures preserve partial denials/config and a
consumed intent. There is no automatic retry, deletion, adoption or forced stop.

`denied_generation_verified` means configuration postchecks passed. It does not
mean an actual normal/debug start-denial trial passed. `boot_verified`,
`rebuild_verified` and `restore_verified` remain false. This component does not
publish an allowing guard, start/shut down the guest, install the application,
attach retained binds, initialize data or reset credentials. A separate frozen
boot policy must bind the now-observed generated config before replacing denials.
No native stage or first boot is qualified by the local tests.

### Blank OS runtime proof (developing)

The next component separates stopped pre-start facts from running kernel facts.
`persistence_blank_runtime` preserves root image inode/size/ownership/UUID and
current storage resolution while allowing OS writes to change mtime/ctime. It
reuses the existing PID/birth, namespace and effective-memory readers, and checks
actual loop backing, UID/GID maps, enforced AppArmor, separate network namespace,
loopback-only guest interfaces, one approved effective CPU, the fixed CPU quota,
512MiB memory and zero swap. The reference program, account, unit and retained
data/config paths must still be absent. The original source stays stopped.

The running observer holds the existing native PVE configuration lock shared and
read-only; it never creates a lock file. This excludes managed configuration/
stop writers during its protected reads. Do not hold this observer across a
native start POST or call it from the pre-start guard, whose native worker already
holds the exclusive configuration lock. API projections omit advancing counters
and uptime. Initial API facts are validated before kernel reads, and initial
kernel facts are validated before any guest execution. Repeated protected facts
close around the guest probe; named root/generated files, storage resolution and
kernel identity are rechecked after slow commands before returning a proof.

`systemd_exec` reads only the typed `ExecStartPre` D-Bus property through busctl.
It preserves exact program, argv, ignore-errors flag, PID, exit status and clocks.
Command declaration and observed successful execution are distinct. Cleared
execution history is not a durable audit trail; a future boot caller must also
bind its native task and newly observed kernel process identity. These local
helpers do not publish guards, boot a guest or qualify recovery. Native runtime
and first-boot qualification remain pending.

### One blank OS start (developing)

Native task acceptance uses the shared complete-log classifier. It accepts `OK`
or the exact known systemd255 nesting warning with `WARNINGS: 1`; unknown,
truncated, inconsistent or error logs refuse. No nesting setting is changed.
Either accepted task result still requires the full current guard, process,
rootfs, namespace, UID/GID map and resource-limit proof. A native success or a
running status alone cannot establish a verified boot.

For a running CT, native PVE derives `status.maxdisk` from filesystem capacity;
for a stopped CT it uses configured image bytes. Filesystem overhead makes those
different values. The running observer requires a positive integral filesystem
capacity bounded by the raw image size, while the kernel proof independently
pins the exact raw size, inode, backing loop, storage resolution and filesystem
UUID. It does not resize or repair either layer.

An older checker could reject that known warning after the guest started.
Use read-only `status` against the original consumed preparation to qualify the
current runtime. Retain the failed journal and original result; status does not
publish completion, reload units, alter guard files or issue another start.

The internal `persistence_blank_boot` backend prepares from the exact previous
stage preparation and a separately trusted completion hash. It freezes the whole
current stopped recipient, generated policy, both deny-file identities and the
pinned standalone guard source. Opaque or rehashed missing unit/generated proofs
refuse before use. No allowing file or boot journal is written during preparation.

A real boot consumes a permanent target claim before writes. It publishes both
allowing drop-ins while the false commands remain, reloads/verifies both command
chains and runs the guard against the stopped guest. Only then does it remove the
exact owned false files, reload/recheck, and submit one verified-HTTPS native start.
It retains the acknowledgement/UPID, verifies native task/log success and actual
kernel/guest readiness, closes the original stopped-source context and repeats
protected runtime/guard/unit/task checks before completion. It never installs the
reference application, attaches retained binds, initializes data or changes
credentials. The source data lock stays held only because this is an app-free OS.

Unknown dispatch or publication failures retain the consumed attempt and partial
outputs; status never republishes/reloads/reposts or writes a new completion. A
new status observation can qualify current owned state without changing the
original failure. If a completion exists, current PID/birth/root image and unit
process identity must still match it. Approved CPU rebalancing may change the one
effective CPU within policy; it cannot change the quota or cardinality. Cleared
execution history is reported explicitly and does not invent a positive history
record. Native task, configured guard and current kernel process checks still
apply. The module `lxc_persistence_blank_boot` supplies prepare, check-mode boot,
once-only boot and read-only status through the ordinary Ansible boundary. Its
stage completion hash must come from a successful trusted controller result.
A failed attempt can leave a candidate completion record followed by failure;
that node file alone is never authority. The backend closes artifacts after slow
runtime work and closes the complete proof again after publishing/reading the
completion candidate before any positive return. It preserves late failures.

Eleven local modeled backend cases pass, including partial publication, unknown
acknowledgement, opaque proof, late process and late artifact changes. Five
boundary cases cover permission/privacy/hash behavior and a real localhost
AnsiballZ check proving that packaged standalone guard source retains its exact
pin. The private normal-executor trial and actual first boot remain pending.

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
## Shared pair lock

`persistence_pair_lock.locked_pair(datasets, initialize=False)` is an internal
collection API for workflow authors. It uses the existing backup mutex at
`/var/lib/cmdmesh/persistence/locks/<pair-key>.json`. The key is the SHA-256 of
the canonical sorted retained dataset GUIDs. It is independent of the guest
VMID and the roles' iteration order.

The default opens an existing private runtime and marker without creating files.
An operation controller can explicitly set `initialize=True` behind its mutation
gate to create the runtime and marker. The marker uses the existing schema1
`cmdmesh.proxmox.persistence.pair-lock` document. It stays on disk and is reused
through the same file identity.

The context holds a nonblocking exclusive file lock and yields the pair key and
marker path. Another backup or pair-lock user receives a named busy refusal.
Each operation owns its context. Invoke a backup outside an already held pair
context, since the existing backup journal acquires the same exclusive mutex.
The context closes its descriptor on success or failure. It verifies the marker's
bytes and identity after successful work. Foreign files, permissions, symlinks,
or replacement refuse without automatic repair or deletion.

Operation controllers must separately validate target identity, ownership,
source state, and incomplete persistent claims before mutation. A mutex does
not establish those facts. Keep this pair lock through a later application
writer's startup while releasing the separate application-file lock first.
Using a different handoff lock path would allow backups to race that startup.

Local tests use real cross-process locks, including both directions against the
unchanged backup journal. They also cover marker reuse, independent pairs,
read-only missing-runtime refusal, failure release, and foreign or replaced
markers. They qualify this mutex component. Native handoff remains pending.
## Native guest configuration leases

`persistence_config_lock.read_guest(vmid)` acquires the guest's existing native
shared configuration lock. It validates the lock directory, target ID, regular
file, owner, permissions, link count, and unchanged file identity. It creates no
files by default and refuses immediately when an exclusive writer holds the lock.
The reference profile supports integer guest IDs from 100 through 999999.

An operation controller may use `initialize=True` behind its mutation gate when
a volatile lock file is absent after a reboot. Initialization creates only the
absent empty file and syncs it. It preserves existing bytes and permissions and
requires the native lock directory to exist. It never repairs a foreign file.

Keep the retained source's shared lease while publishing its managed start
denials. Release the replacement's lease before invoking its native configuration
writer. `require_write_available(vmid)` provides an early nonblocking exclusive
probe, then releases it. The probe does not reserve a later write. The native
writer must still check the approved digest and acquire its own exclusive lock.

The existing blank-runtime wrapper still validates its blank-only policy before
using this primitive and preserves its named error family. Retained-source
controllers use the shared primitive directly after their own source admission.
They must not fabricate a blank policy merely to obtain a native lock.

## Stopped retained attachment (developing)

`cmdmesh.proxmox.lxc_persistence_attach` is a finite configuration operation for
the reference rebuild workflow. It consumes the separately trusted preparation
of an already provisioned recipient. It requires the original stopped source,
unchanged retained application facts, a matching closed backup, and an isolated
stopped replacement with the fixed one-core, 512 MiB, unprivileged profile.

Use `action: prepare` to capture the current recipient, existing managed pre-start
files and closed backup history. Retain and review the exact canonical preparation
and its separately trusted hash. `action: attach` in check mode repeats that
read-only admission. Real attachment also requires `allow_changes: true`.
Preparation/check creates no claims, lock files, unit drop-ins or native changes.

The operation holds the existing backup-compatible pair mutex and the original
guest's native configuration read lease. The source observer also locks the
retained application file while checking SQL and storage. Both guests must have
only their previously managed `50-...` drop-in in the normal and debug instance
units. The operation preserves those files and installs
`99-cmdmesh-retired-prestart.conf` in all four unit directories:

```ini
[Service]
ExecStartPre=
ExecStartPre=/usr/bin/false
```

The empty assignment resets earlier pre-start commands. Loaded unit paths and
typed D-Bus command facts must show exactly the non-ignored false command before
any native guest update. Foreign files, active units, missing files, changed
original files or ignored/extra commands refuse.

Proxmox rejects mount changes on a protected guest. Under those denials, the
operation performs exactly three native `pvesh set` calls with fresh configuration
digests: `protection=0`, the following two binds plus the existing `cores=1` and
`cpulimit=1`, then `protection=1`:

```text
mp0: <data dataset mountpoint>,mp=/var/lib/reference-ledger,backup=0
mp1: <config dataset mountpoint>,mp=/etc/reference-ledger,backup=0
```

Each call has a synced dispatch record before execution and a separate result and
observed-state record. The replacement read lease closes before each native write
and is reacquired for its phase check. The original's lease and shared pair mutex
remain held. The phase validator admits only these exact bind fields and the
explicit temporary protection state. All original isolation, limits, root image
identity and stopped-state requirements still apply. Every native update can
regenerate the LXC configuration, even a protection-only change; API configuration
is the authority for the exact binds.

The existing finite generated-config reader captures the admitted initial file
and the file produced by each phase. It checks the root path, hostname, ID maps,
CPU quota and bounded CPU selection and refuses network or raw mount entries.
The native pre-start hook consumes these fixed bind mounts later; they are not
emitted as raw mount entries by the stopped configuration generator. Final and
status results retain the actual generated bytes, fingerprint and file identity.
This is evidence of stopped generation, not permission to boot with retained data.

The claim is keyed by retained dataset GUID pair, not a new request ID. Successful
or uncertain claims cannot be replayed by changing operation IDs or recipient
identity. An unfinished same-pair backup blocks mutation; a completed backup must
match source, application contents and each role's dataset name and GUID. This
checks retained backup receipts, not fresh decryption or independent restoration.

On success, `attachment_verified` means only that the protected stopped replacement
has the two exact bindings, all four managed start denials remain effective and
source closure passed. `boot_verified`, `rebuild_verified` and `restore_verified`
remain false. The operation does not mount/start a guest, initialize application
data, change ownership or credentials, publish an allowing guard or owner record,
or verify guest program contents after shutdown.

On failure, keep the consumed claim, phase records and installed denials. Protection
may be off and binds may be partially applied. Do not retry, remove the claim,
change IDs, start either guest or automatically issue compensating writes after
an uncertain native result. Inspect the same journal and actual configuration;
reconcile through a separately reviewed operation. `action: status` observes a
completed attachment without dispatching writes; uncertain work is a refusal.
Status validates the entire finite dispatch/result/observed-state chain against
the completion's recorded journal hash. Missing phase files refuse. It closes the
source observation before the final replacement, generated-file and denial checks.
Apply also rechecks those facts after writing completion; a later refusal retains
the completion together with a failure marker and does not qualify as success.

Later allowing-guard publication and startup must retain the original guest's
retirement denials and validate the replacement's actual bound profile. Application
writer startup must release the application-file lock before launching the writer
while retaining the shared pair mutex. A strict pre-start guard is not a running
observer: normal operating-system and database writes change timestamps and data.
Live verification needs an explicit phase-aware observer and never substitutes
metadata checks for consistent SQL observations. Native attachment qualification
is still pending.

## Stopped successor source observation (developing)

The source observer accepts three content-addressed standalone guards: legacy
schema-two `8a96f2ce...`, owner-aware schema-three `68a40e2c...`, and corrected
schema-three `1063b39c...`. The selected
program's validator enforces its policy schema. Unsupported hashes or changed
bytes refuse before execution; an operator cannot supply an arbitrary hook.
The existing request, host identity, guest isolation, exact bind layout, backup
mount and application-file/SQL consistency checks remain in force.

Schema-three observations require the successor to be stopped even for ordinary
inspection. The observer holds its existing native shared configuration lease
through collection, caller work, application SQL closure and the final guard-file
recheck. Managed native starts/writes cannot overlap that interval. A missing or
busy lock refuses without initialization. The early stopped-state gate precedes
the strict guard collector, backup-mount collection and application reads.
Its guest facts retain the native VM ID, PID and uptime. They must be integers
with the exact selected VM ID; a stopped source requires PID0 and uptime0.
A stopped label with a foreign ID, nonzero runtime or boolean counters refuses.
Legacy schema-two observation fields remain unchanged.

The owner guard validates the active owner record and both retired managed start
denials. Missing/mismatched ownership is a refusal, not permission to select an
older descriptor. A successful stopped observation may report consistent SQL
facts under the application lock; it does not claim a completed backup or restore.

Running schema-three collection is deliberately unsupported here. Its strict
pre-start collector seals timestamps and database metadata that normal operating
system and application writes change. A separate phase-aware running observer
must qualify those permitted changes before startup workflows use it. Never
remove drift checks or reuse the retired guest's source identity to hide them.

Both schemas re-read the pinned reference bytes after application closure. A
changed reference or program prevents success. An intentional installed legacy
reference retirement must occur outside its old observation context, under the
operation's pair/configuration leases and managed start denials, then receive an
explicit successor observation. Preserve immutable original code and history.
These local contracts do not publish owner records/guards, retire a legacy
reference, start a guest/writer or qualify native ownership handoff.

The corrected guard records either the explicit storage configuration or its
observed absence when Proxmox uses default local storage. It does not create the
file. The parent identity and file presence are checked through a held directory
descriptor, with full file sealing when present. Schema-three still requires the
same owner/retirement facts, stopped-state gate, native lease and SQL closure.
Admitting this known program hash does not reconcile an earlier failed operation
or authorize overwriting its files. CI retains separate immutable old and fixed
guard fixtures, so both contracts remain exercised.

## Initial stopped owner publication (developing)

`cmdmesh.proxmox.lxc_persistence_owner_publish` handles one initial schema-two to
schema-three reference handoff. Its inputs are the exact completed attachment
preparation, separately trusted preparation and completion hashes, and the pinned
standalone owner guard. It derives the successor's actual root identity, generated
configuration, retained dataset pair and original application facts. It preserves
the old descriptor rather than rewriting historical evidence.

Use `action: prepare`, retain its exact canonical result and hash, then use
`action: publish` in check mode to repeat the admission. Neither creates an owner
record, publication claim or unit file. Real publication requires
`allow_changes: true`. `action: status` inspects the same completed publication;
it cannot reconcile a partial attempt.

Publication holds the backup-compatible pair mutex and both native configuration
read leases. All four existing resetting false drop-ins remain unchanged. The
replacement's two blank drop-ins are archived outside the unit directories before
being replaced with owner-aware reference drop-ins. The fixed guard program,
policy and private owner record are installed and the loaded false commands are
checked. No native guest configuration or application data is written.

The original stopped source context and its exclusive application-file lock close
fully before the old installed guard is archived and replaced by an immediate
refusal stub. A genuine stopped schema-three source context then checks the same
application tuple. An old descriptor must fail the original code-hash check before
host, SQL or backup work. Historical immutable guard code remains unchanged.
After retirement, status uses the publication journal and new source descriptor;
the old attachment status correctly refuses its retired reference.

The durable claim is keyed by the retained dataset pair. Dispatch/result records,
original guard archives, exact guard/policy bytes and the completion are retained.
Completion binds their raw-byte hash map. Missing, modified or uncertain phase
evidence refuses, as do changed owners, denial files, unit membership or native
facts. Files are checked again after slow queries and completion publication.
The application lock is never nested across old/new source contexts.

On failure, preserve the claim, archives, owner and all denials. A partial attempt
can leave only some new metadata, or an archived old guard without its stub. Do
not retry, erase the claim, change IDs or start either guest. Diagnose the actual
files and journal before a separately qualified reconciliation. A completion
beside a failure marker is not success. No automatic rollback is attempted.

`owner_publication_verified` means only that this stopped handoff passed its
checks. `boot_verified`, `rebuild_verified` and `restore_verified` remain false.
Native qualification is pending. This is not a general repeated-generation
handoff, a tombstone protocol or a source-unavailable restore. It requires the
retired guest to remain present. A separate phase-aware live observer and startup
workflow must qualify OS/application writes before any denial is removed.

## Explicit kernel evidence (developing)

`persistence_kernel.KernelBinding` names the host, guest, exact root image,
filesystem UUID, stable generated configuration and permitted CPUs. Its immutable
values describe the current reference profile: local 2 GiB ext4 image, 512 MiB
memory, no swap, one CPU, and the unprivileged UID/GID mapping. Other resource or
storage profiles are unsupported.

`collect(binding)` checks the host before and after the existing read-only kernel
reader. `validate(binding, evidence)` checks process birth and namespaces, actual
root-loop backing, image identity, mappings, cgroups, AppArmor and generated
configuration. Image mtime/ctime are excluded because the OS can write its root;
device, inode, type, ownership, link count and image size remain bound.

The adapter passes a minimal field projection to shared kernel primitives. It
does not construct or validate a blank-container policy. It executes no guest
command, reads no application data and creates no file. The outer operation must
admit ownership, hold native configuration leases, and verify guest bind mounts
and application state. Kernel evidence alone does not establish those facts or
qualify boot, rebuild or recovery. Native retained-runtime qualification is pending.

`persistence_retained_runtime.collect_bindings(binding, kernel, datasets)` checks
the running guest's data and configuration paths. It requires one writable ZFS
mount per expected path, with the correct dataset source, filesystem root and
device. It opens each guest path relative to the admitted init process's root,
refuses symlinks, and compares the open directory's device/inode with the host
retained directory. It repeats the selected mount, process and directory checks
before closing its descriptors. Process identity is checked after the last root
descriptor check. Unrelated mount-table changes are excluded.

These primitives create no files and execute no guest command. The caller must
validate actual dataset GUIDs/ownership and hold native configuration leases.
The bind helper alone does not qualify boot, application health or restore.

## Running OS with a quiesced application (developing)

`lxc_persistence_runtime` exposes read-only inspection for `phase: os_quiesced`.
The matching library is `persistence_retained_runtime.collect(request, profile,
phase="os_quiesced")`. The old source observer remains stopped-only. The new API
does not start or stop a guest, remove a denial, enable a service, repair state or
write an application record. Check mode runs the same observations.

The caller supplies the corrected schema-three source request and an image
profile derived from its qualified stopped-owner and image checkpoints. The
profile has these exact fields:

| Field | Required value |
| --- | --- |
| `schema_version` | Integer `1` |
| `guard_python` | Exact supported corrected standalone guard source |
| `image_python` | Exact supported standalone image helper source |
| `config` | Expected retained guest configuration, including both binds |
| `rootfs` | `path`, `volume`, `uuid`, and the first seven stopped-image `identity` fields |
| `accounts.base` | Original image's account database hashes excluding the managed account |
| `accounts.subids` | Original image's subordinate-ID file hashes or explicit absence |

Only guard1063 and image helper21bd are executable inputs. The profile supports
the reference Ubuntu/amd64, local2GiB, memory512MiB, oneCPU/no-swap configuration.
Unknown sources and unsupported profiles refuse before collection. The direct
quiesced collector rejects `active_writer`. The Ansible boundary dispatches that
phase to the separate active observer described below.

The collector admits the host and API identity before retained-file access or
guest execution. It holds the existing retained-pair EX mutex and both old/current
native config SH leases. After API admission, it takes the real application
configuration EX. It checks actual kernel identity, target references, guest bind
backing, and the image/account and inactive, disabled application unit. Lower
retained-state checks and consistent SQLite inspection use the same EX. It does
not call the stopped collector or the image helper's retained-path-absence checks.

Closing observations repeat image, API, kernel, binds, ownership, references and
SQL. Only nondecreasing typed uptime and the root image's normal mtime/ctime are
excluded from equality. Image, bind and kernel evidence refresh after the last
SQL query. A final database byte/hash/metadata seal rejects changed content and
SQLite sidecars without another slow SQL query. Owner/reference-file and init
identity checks close afterwards. Normal and debug target units must contain only the
corrected reference. The normal unit must be active with a successful typed
pre-start result; the debug unit remains inactive. Application artifacts, account
baselines, permissions and credential identity must remain exact.

`validate(request, profile, phase, evidence)` checks the same frame without native
commands or local source-path access. The guest probe executes the pinned lower
image helpers and returns hashes and metadata, never shadow contents or tokens.
It rescans the account/process state after its closing environment and unit reads.
The Ansible boundary redacts input invocation and unexpected errors.

The public collector acquires the pair mutex, both native guest read leases, and
the application configuration EX before runtime inspection. Internal lifecycle
controllers can use the private `_collect_leased` worker while retaining those
same leases across startup. The worker never acquires or releases the caller's
locks. It verifies the configuration bytes and guest binding before inspection.
The public collector closes every lock context after the worker returns, so late
configuration or lease changes still refuse the result. No CLI, MCP, or Ansible
argument can bypass lock acquisition. Real file-lock and SQLite tests cover the
worker contract. Native startup qualification remains separate.

`os_runtime_verified` and `application_quiesced` describe this observation only.
Mutation, boot-operation, rebuild, restore and backup flags remain false. Native
retained-runtime qualification is pending. This component does not yet release a
writer or test its authenticated socket API. A complete rebuild/restore needs
those later phases and their independent application-level acceptance.

## Known failed-guard reconciliation (developing)

The `persistence_owner_reconcile` library admits one specific forward
transition: the original owner publisher staged all metadata, then its direct
guard refused before any reference retirement. The original pair claim remains
failed and immutable. Other failure phases are unsupported.

Preparation accepts the exact original preparation/hash, a separately trusted
hash of its six raw phase records and the pinned corrected guard1063. It requires
the expected original runtime profile, exact claim membership, five absent later
markers, unchanged source/owner/unit metadata and matching backup/attachment
history. The existing pair mutex and both native read leases remain held while
the stopped source's application lock and consistent SQL facts are checked.

The corrected guard runs only in memory against the existing policy. Preparation
closes source, parent history, controls and the original installed reference again
after slow observations. It returns a canonical proposed reconciliation containing
the original facts and a new reference path. It creates no new runtime profile,
claim, owner or unit file and does not retire or start anything.

`lxc_persistence_owner_reconcile` exposes `prepare`, `reconcile` and `status`.
Check mode reobserves the exact preparation without creating files. Execution
also requires `allow_changes: true`. It consumes a new permanent GUID-pair claim,
stores the corrected guard and policy there, and archives both previous target
references before replacing them. The owner record and all four start denials
remain unchanged. The old failed journal stays in its original directory.

The controller validates the installed observer's support and records the direct
guard result before retiring the legacy reference. Guard refusals, timeouts and
process-spawn failures produce bounded results without private exception text.
It closes the original source/application lock before retirement and observes
the stopped successor through the new schema-three descriptor. Completion and
status verify the new profile, phase records, archives, old failure records,
current controls and original application facts. Status uses the new descriptor;
it does not replay the failed publisher or call its historical current-state checks.

A partial reconciliation retains its new claim and failure marker. Do not replay
either operation, remove a denial or infer success from a completion beside a
failure marker. No automatic rollback is attempted. The verified result covers
metadata only; boot, rebuild and restore remain false. Native reconciliation is
not yet qualified. The initial bootstrap's legacy guard behavior remains unchanged
here; fresh defaults require their own corrected-guard qualification before release.

## Current-guest lifecycle transport (developing)

`persistence_guest_api.GuestBinding` binds one current LXC to its node, numeric
guest ID, machine fingerprint, CA fingerprint, and leaf fingerprint. A lifecycle
controller can construct this binding directly from an admitted source. It does
not need a historical source-to-recipient request.

`post_guest_action(binding, action)` accepts only `start` and graceful `shutdown`.
It checks the local root identity, node, and machine before authentication. It
uses the existing verified TLS transport to the fixed local PVE endpoint. Shutdown
has a fixed timeout and disables forced stopping. No caller supplies an endpoint,
extra parameters, or a retry policy. Task parsing binds the operation, node,
guest ID, and native process identity. Task inspection retains the qualified
systemd255 warning outcome and refuses unknown warnings or incomplete logs.

The original recipient API delegates to this shared transport after its existing
admission checks. Its private create path accepts only the fixed stopped,
isolated recipient parameters. This extraction does not add a lifecycle command
to the CLI or MCP interface. Controllers still own durable dispatch claims,
configuration lock handoff, runtime checks, and uncertainty after a lost reply.
Transport tests establish neither native start nor application recovery.

## Local process authentication (developing)

`unix_peer` performs one bounded AF_UNIX request to an admitted Linux process.
The caller supplies an admitted socket-directory FD and `ProcessIdentity`.
The process identity includes PID, birth time, PID and mount namespaces, numeric
credentials, namespace PID mapping, root, executable, arguments and cgroup.
This identity is evidence about a process. The caller must still verify its
host, guest, service, program, retained mounts and socket-directory backing.

`exchange` opens a pidfd and a process-directory FD. It requires a private
directory and socket, then checks actual `SO_PEERCRED` before calling the
credential supplier. It repeats process and socket checks before sending and
after receiving. An exec or process exit invalidates the exchange. Supplier
exceptions return a static error without private exception text.

The protocol permits one newline-terminated request and one response. Request
size, response size and total network duration are bounded. The client never
retries. A lost or invalid response after sending leaves the operation outcome
unknown. A caller must retain its dispatch claim and reconcile that outcome.
The client cannot make an application write and its completion record atomic.

`persistence_ledger_api` uses this transport for the reference application's
authenticated read and idempotent append. It reads the original configuration
through a caller-admitted directory FD after peer admission. It verifies the
configuration hash, identity, permissions and file identity again after the
response. The token remains inside the process and is excluded from results.
The client takes no application EX lock and reads no host SQLite state.
Read results include a records hash compatible with the stopped SQL observer.
Invalid, uncertain or conflicting responses refuse without automatic retries.
The decoded response must not contain the original token, including a token
encoded with JSON escapes. Such a response refuses without returning its data.

The existing image validator and guest probe accept an explicit `writer_pid`
for the later active-writer controller. This requires an active, running unit
with exactly that MainPID and exactly that UID/GID process. All artifact,
account, mapping, environment and disabled-at-startup checks still apply.
The default quiesced collector supplies no writer PID and still refuses active
frames. An active image frame alone does not qualify a socket peer or rebuild.

Local tests use real AF_UNIX processes, a real exec, actual peer credentials and
the pinned reference application. They prove protocol and error behavior only.
There is no active-writer lifecycle command or native rebuild acceptance yet.
The reference application must remain stopped until its separate lifecycle
controller, process admission, claims and stopping behavior are qualified.

## Active-writer observation (developing)

`lxc_persistence_runtime` accepts `phase: active_writer` for an already running
reference service. It never starts or enables the service. Check mode performs
the same observations. The matching library is
`persistence_writer_runtime.collect(request, image_profile)`.

The observer holds the existing pair EX and both native guest SH leases. It
verifies current host/API/kernel, the retired owner and its denials, target
references, ZFS GUIDs, mount sources, directory permissions and actual guest
bind backing. The active image must still use the disabled service, known
program and account baseline. Exactly one application UID/GID process is allowed.

The socket peer must match the guest service's MainPID through the supported
two-level namespace PID mapping. Its birth, PID and mount namespaces, root,
mapped credentials, Python executable, arguments and systemd cgroup must match
the admitted guest and service. Guest-root file access uses held directory FDs
and no-follow directory traversal. The supported Python symlink is a relative
`python3.<minor>` name inside the admitted `usr/bin` directory. Program bytes
must match the qualified reference program.

The held configuration and data directories must match their actual retained
host directories. The named run directory and its private socket must still
match the client endpoint. An actual FLOCK WRITE record and the peer's matching
locked FD are required. `/proc/locks` alone retains the acquisition PID after
an inherited descriptor transfer, so it cannot establish the current holder.
The observer checks `fdinfo` and FD-backed file identity without opening or
duplicating the actor's open file description.

Each authenticated request repeats the full active frame before and after use.
Only nondecreasing uptime and legitimate data-directory timestamp and size
changes are excluded from equality. Directory backing, numeric ownership,
permissions, service identity and the configuration file remain fixed.
Closing file checks precede a final fast process check. A client refuses use
after its lease context closes. No application EX or host database bytes,
SQLite header or SQL are read while the actor runs.

Results contain the authenticated instance identity, record count and records
hash. They omit record values and credentials. `application_read_verified`
describes this read; `application_quiesced` is false. All lifecycle, mutation,
rebuild, restore and backup flags remain false. A successful read does not
qualify write acceptance or application rebuild.

Internal lifecycle code can use `_session_leased` while retaining the real pair
EX and both native SH scopes. Its explicit append method is unavailable through
the read-only Ansible boundary. A lifecycle controller must own a permanent
dispatch claim before calling it. After sending, failures are unknown outcomes,
not permission to replay. No native writer lifecycle has been qualified yet.

Local tests separate modeled native/process admission from real directory,
program, socket and lock observations. They reproduce endpoint replacement,
late process changes and inherited-descriptor errors. Native activation and the
claimed write/read-back/stop/SQL sequence remain separate acceptance work.

## Retained OS startup controller (developing)

`persistence_retained_boot` prepares and controls one OS-only start after the
corrected stopped-owner handoff. The reference application must remain disabled
and inactive. This library does not start a writer, qualify an application
rebuild, recover an independent backup, or change the retired guest.

`prepare(reconciliation_raw, reconciliation_sha256, completion_sha256,
source_sha256, image_profile)` requires separately trusted hashes of the accepted
reconciliation preparation, completion, and full stopped Source3 observation.
The image profile uses the same known helpers and resource limits as the runtime
inspector. Preparation validates the existing reconciliation, then repeats the
stopped source under pair EX and both native SH leases. It binds the image,
controls, and raw owner journals without creating files or claims. All source
contexts finish before preparation returns. Its final history closure checks
file identity, timestamps, permissions, directory identity, and membership after
slow reads and probes. A decoder alone does not admit execution.

`boot(prepared_bytes, trusted_sha256, timeout_seconds=240)` repeats preparation
and requires canonical equality before it consumes a permanent GUID-pair claim.
It finishes another stopped-source context before taking the real application
configuration EX. The application EX and pair EX remain held through startup and
verification. The direct guard result is durable before qualification or refusal.

The controller archives and fsyncs only the current target's two
`99-cmdmesh-retired-prestart.conf` files, then removes those files. It preserves
the retired guest's denials and both guests' `50-cmdmesh-reference.conf` files,
the owner record, policies, and prior journals. It
checks the loaded target declaration before dispatch. Every target native SH
lease is closed before POST and task polling. The retired native SH remains held.
The controller reacquires target SH after terminal native success and inspects
runtime through the private worker without acquiring pair or application locks
again. The start request uses the fixed verified current-guest transport once.

Success requires the qualified native outcome, task identity and dispatch time,
actual successful pre-start execution in the operation's time range, runtime
identity, inactive application, exact original credentials, and consistent
original SQLite facts. Unknown warnings, timeouts, lost replies, changed history,
and failed runtime proofs leave the claim consumed. Completion is fsynced, its
bytes are verified, and a second runtime observation closes changes during that
write. Final file and directory checks also bind the new runtime profile. No
automatic rollback, repeat POST, or claim deletion is performed.

The result's `journal_files` maps each claimed record to its native path, raw-byte
hash, and file identity. Its canonical hash is `phase_journal_sha256`. A consumer
can recompute that digest and compare separately captured raw bytes with every
recorded hash. Status requires the recorded descriptor to match fresh native
metadata. The descriptor contains no credential contents.

`status(prepared_bytes, trusted_sha256)` requalifies an existing completed start.
It checks journal semantics, hashes, task state, application facts, and current
runtime. Only typed nondecreasing uptime can differ from the completed frame.
It creates no files, takes no lifecycle action, and never calls a stopped observer
after startup. Failed or uncertain claims refuse successful status. Keep their
evidence for a separate reconciliation rather than rerunning `boot`.

These interfaces are under development. Native startup and the normal executor
trial still require qualification. Local tests
use real private files, locks, SQLite, and modeled native providers. They do not
establish disaster recovery or production readiness.

### Ansible startup boundary

`lxc_persistence_retained_boot` exposes `prepare`, `boot`, and `status`. The
preparation inputs are the canonical reconciliation document, its trusted hash,
the trusted completion and Source3 hashes, and `image_profile`. Boot and status
take only the canonical startup preparation and its separately trusted hash.
Use `ansible-doc cmdmesh.proxmox.lxc_persistence_retained_boot` for the complete
argument reference and read-only examples.

An actual boot requires `allow_changes: true`. In check mode, boot repeats the
exact preparation and reports a proposed change without creating a claim,
removing a denial, dispatching a task, or claiming runtime success. Status remains
read-only in either mode. Input invocation and unexpected exceptions are withheld;
safe preparation hashes remain exact. Failure reports possible effects for an
allowed boot and clears every verified flag. Preserve consumed claims and partial
journals rather than retrying an uncertain start. Native normal-executor
qualification remains pending.

## Claimed application-test preparation (developing)

`persistence_writer_trial.prepare(boot_raw, boot_sha256,
boot_completion_sha256, nonce)` prepares the later retained application test.
It requires the canonical accepted OS-start preparation, its separately trusted
hash, the trusted completed-start hash and a predeclared 32-character hexadecimal
nonce. The future test value is a fixed reference marker derived from that nonce.
Preparation creates no runtime directory or claim and performs no service action.

The function finishes the original OS status check before acquiring its own pair
EX and both native SH scopes. It takes the real application EX for consistent SQL
and retains it through closing history reads and a second quiesced observation.
Original credentials, records, image and controls must still match the accepted
start. All raw parent journals, the completed boot journal and its runtime profile
are included in the immutable history. Missing, unexpected or changed records
refuse. Existing claims and unknown or symbolic runtime paths refuse reuse.

The prepared runtime identity excludes changing uptime. Its floor comes from the
immutable completed-start document; each fresh observation must remain at or
above that floor and increase monotonically within the observation. This keeps
prepared bytes stable when only uptime increases. A later APPLY must still repeat
preparation and compare its exact canonical bytes before creating a claim.

`decode_prepared(raw, trusted_sha256)` is a pure loader. It validates the complete
parent relationship, required history membership, profile, completed-start hash,
original application tuple and uptime floor. A matching self-hash alone does not
authorize an action or establish current runtime state.

Preparation does not perform the claimed lifecycle described below. Neither
preparation nor a successful active read qualifies application rebuild or
independent restore. After an intentional append, later status uses its new
application checkpoint rather than the original OS status bound to the old tuple.

## Claimed application lifecycle (developing)

`lxc_persistence_writer_trial` exposes `prepare`, `run` and `status` for the fixed
reference application. The SDK execution functions are
`persistence_writer_execution.preflight(raw, trusted_sha256)`, `run(raw,
trusted_sha256)` and `status(raw, trusted_sha256, completion_sha256)`.
See `ansible-doc cmdmesh.proxmox.lxc_persistence_writer_trial` for arguments.
These are component-qualified interfaces. A native trial remains required.

An actual run requires `allow_changes: true`. Check mode performs the same fresh
read-only preflight, compares exact canonical preparation bytes and reports a
proposed change. It creates no runtime directory or claim and sends no start,
application request or stop. A consumed claim refuses another run or preflight.
Use read-only status with the trusted successful receipt instead of replaying it.

The allowed lifecycle performs these steps:

1. Take the pair EX and both native SH leases. Recheck the original quiesced SQL
   tuple under the real application EX and create a permanent GUID-pair claim.
2. Close application EX, then journal and attempt one fixed service start. The
   service remains disabled for automatic startup. Missing-socket readiness can
   repeat read-only admission within a bounded deadline. It never repeats start
   or retries an application request.
3. Authenticate with the original credential and require the exact prior record
   hash/count. The declared nonce must be absent. Journal one append dispatch and
   require `committed` with the previous maximum sequence plus one. `unchanged`
   does not qualify this first attempt.
4. Read back exactly the old rows plus the declared nonce and fixed marker.
   Close the active session. Freshly admit the owned service's root, program,
   current MainPID and birth before one separately journaled stop.
5. After stop, admit host/API/kernel before configuration access. Take real
   application EX for inactive/no-writer and SQL proof. Require the same original
   credential, original data plus the new record and compatible runtime state.
6. Write the candidate completion and check raw parent/current journals and
   profiles while EX remains held. Repeat the actual SQL/runtime worker after all
   slow content reads. Only fast metadata/membership closure follows it, including
   the private claim-directory identity and completion file.

Pair/native leases span the full operation. Application EX never overlaps the
live writer. No old stopped-source observation or old boot status runs after the
intentional append. Original source controls, parent claims, credentials and
unrelated services are preserved. The new record remains in the database.

An uncertain start, write or stop consumes the claim. Following a possible start,
failure handling can attempt one independently admitted containment stop without
requiring successful API authentication. It refuses a replaced/unadmitted actor
and never sends another stop after stop dispatch. It preserves the original
failure, possible write and available evidence. Containment never creates normal
success or removes the test record. A failed/uncertain result cannot be retried
using another request ID or nonce.

Successful status takes the separately trusted completion hash returned to the
controller. Do not derive that trust from a candidate file on a failed target.
Status checks the new stopped tuple, complete journal contract and raw historical
boot records. It performs no lifecycle action. A failed or containment journal
refuses. A candidate `complete.json` alone does not establish successful execution;
a closing failure can leave that file without a returned accepted receipt.

Results omit credentials and row values. `application_write_verified` and
`rebuild_verified` require the complete successful sequence. `boot_verified`,
`restore_verified` and `backup_verified` remain false for this operation.
Unknown failures clear verified flags at the Ansible boundary, suppress private
exception text and retain possible effects for an allowed run. Independent
source-unavailable restore and native application qualification remain separate.

Controllers that capture the raw journal can reuse
`persistence_writer_execution.validate_records(prepared, trusted_sha256,
records, result)`. It checks decoded journal content using the same contract as
run and status, without filesystem or native access. Callers must separately
verify canonical raw bytes, exact membership, metadata, preparation and the
completion hash returned by a successful run. This content check does not prove
freshness or turn a candidate completion from a failed run into success.

### Accepted writer checkpoint (developing)

`persistence_owner_checkpoint.load_writer_checkpoint` decodes an already accepted
writer trial into versioned historical evidence. A workflow can retain that
evidence across a manager reboot without calling an old current-status operation
against a different boot epoch.

```python
from ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_checkpoint import (
    load_writer_checkpoint,
)

checkpoint = load_writer_checkpoint(
    prepared_raw=accepted_preparation_bytes,
    prepared_sha256=trusted_preparation_sha256,
    completion_raw=accepted_completion_bytes,
    completion_sha256=trusted_successful_completion_sha256,
    records=raw_journal_records,
)
expected_application = checkpoint["completion"]["runtime"]["application"]
```

`records` must contain exactly the 12 journal records and `complete.json`, as raw
bytes. Completion trust must come from a successful SDK return, not a candidate
file discovered after a failed or unknown run. The helper checks canonical
hashes, exact shapes, typed private root metadata, ancestor history, the phase
digest, the shared journal contract, original-data preservation and the committed
append. It also rejects contradictory exported actor identity, namespace,
mapping, unit, argv, root-device and cgroup facts. It does not invent unexported
init mount-namespace or executable-inode comparisons.

The returned document has type
`cmdmesh.proxmox.persistence.owner-checkpoint`, schema version 1, the decoded
`prepared` and `completion` documents, and their two trusted hashes. Historical
boot/process/device facts remain in the evidence. They are not current bindings.

This helper does not read files, inspect a process, call status, acquire a lock,
initialize an operation head or perform a lifecycle action. It does not prove
that a directory still has the recorded membership. A consumer must obtain and
close current evidence separately before any operation. A new host boot, init,
loop device, approved CPU placement or ZFS device requires fresh intrinsic
validation; deleting those facts from an old frame is not current admission.

The owned native application trial qualified the preceding writer sequence.
This decoder has synthetic and accepted-receipt component tests. Reusable OS
shutdown/resume, manager reboot and source-unavailable restore remain separate
qualification work.

### Caller-leased stopped inspection (developing)

`persistence_observe._stopped_source_leased(request, guard, host, raw)` is a
private context manager for internal lifecycle controllers. The caller must hold
the real dataset-pair exclusive lease, both native guest read leases and the
application configuration exclusive lease. The worker neither acquires nor
releases those leases. There is no public option to skip locking.

The worker accepts only a schema-three owner policy and config bytes matching
the policy's credential-file hash. It validates current guest ownership,
configuration, HA membership and pending state before any retained read.
The API must report the exact stopped guest with PID zero and uptime zero.
A running guest refuses before guard, backup mount or SQL collection.

Inside the context, the worker reports guarded retained facts, the backup mount
and a consistent application digest/count. On exit, it checks host epoch, guest,
mount and guard facts again, then reads SQL again under the caller's lock.
The caller must close the actual configuration lease and all remaining input
and control checks before accepting the result.

The existing public `source_state` and `locked_application` interfaces retain
their lock acquisition. This extraction does not admit a native shutdown or
resume, initialize operation metadata, change data or qualify recovery.

### Current owner admission (developing)

`persistence_owner_current` provides read-only admission for internal workflow
authors. Its checkpoint must come from `load_writer_checkpoint` using externally
trusted successful preparation and completion hashes. A candidate discovered on
a target after a failed return is not accepted authority.

```python
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_current,
)

# accepted_checkpoint comes from load_writer_checkpoint, as described above.
current = persistence_owner_current.collect(
    accepted_checkpoint,
    phase="os_quiesced",
)
assert current["guest_image_verified"] is True
```

`collect` supports exactly `os_quiesced` and `stopped`. It acquires the existing
dataset-pair exclusive lock, both guest configuration read locks and the
application exclusive lock. Missing lock metadata refuses. The function does
not initialize lock files, create claims or write operation heads.

Running admission reuses the kernel, image, account, resource-limit and mount
validators. It additionally requires the accepted application digest/count,
retained object metadata, owner/control identities and credential hash. A new
boot, init, loop device, mount namespace or retained device number must satisfy
the fresh intrinsic checks. Each observation closes against its own epoch.

Proxmox can rebalance the live CPU assignment without changing the generated
boot configuration. Admission verifies the live approved single CPU and guest
affinity separately from agreement between generated and retained boot-time
selection. It preserves the exact CPU quota, memory limit, swap limit and
generated stable fingerprint.

Stopped admission checks the exact API configuration and stopped PID/uptime
zero before retained reads. Both target management units must be loaded,
inactive and report MainPID zero. Their guard files, declarations and directory
membership must match. LXC must report `STOPPED`. The cgroup must be absent or
have no processes, under a verified cgroup-v2 mount. The kernel's
[`cgroup.events` populated field](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#un-populated-notification)
covers descendants. A missing LXC cgroup parent is permitted after the enclosing
kernel mount is verified.

In the same manager boot, only ENOENT or a valid changed process identity can
fence the known prior init. Permission, I/O and malformed-process errors refuse.
A newly admitted manager boot fences the old epoch explicitly. `prior_runtime`,
when supplied, must be the externally accepted last running frame for this
owner. It is validated against the same portable checkpoint.

Stopped collection reports `guest_image_verified=False`. It preserves the
accepted image profile and root identity, then verifies retained guard facts and
SQL. It does not execute guest commands or claim that stopped guest program,
account or unit contents have been freshly inspected. Running admission verifies
those contents after a separately authorized guarded boot.

Internal `_entry_leased` performs pre-data admission under caller-held pair and
native leases. `_current_leased` additionally borrows the actual application
exclusive lease. Its context permits slow journal/history work before a final
actual observation. Only fixed metadata/process identity checks follow that
observation. These helpers do not acquire or release the caller's leases.

`validate_current` is a pure portable-content validator. On its own, it neither
collects fresh evidence nor proves the native stopped-entry conditions. It does
not resolve an uncertain operation. Any lifecycle controller must independently
enforce the ordered operation journal, externally trusted predecessor and native
dispatch contract. OS shutdown/resume, reboot and recovery qualification remain
separate.

### Ansible current-owner entry point (developing)

`cmdmesh.proxmox.lxc_persistence_owner_current` reconstructs authority through
`load_writer_checkpoint` before collecting current state. Supply these inputs:

| Input | Required value |
| --- | --- |
| `prepared_json`, `prepared_sha256` | Original canonical writer preparation and its externally trusted hash. |
| `completion_json`, `completion_sha256` | Original canonical successful SDK completion and its externally trusted hash. |
| `journal` | Exactly 13 original filenames mapped to raw canonical JSON strings, including `complete.json`. |
| `phase` | `os_quiesced` or `stopped`. Defaults to `os_quiesced`. |
| `prior_runtime` | Optional externally accepted last running frame for prior-init fencing. |

Do not parse and serialize journal values to create these strings. Preserve the
original raw bytes and their hashes. A failed target's candidate completion is
not a substitute for successful controller output.

```yaml
- name: Inspect current retained data without starting or stopping the guest
  cmdmesh.proxmox.lxc_persistence_owner_current:
    prepared_json: "{{ accepted_writer_preparation_json }}"
    prepared_sha256: "{{ trusted_writer_preparation_sha256 }}"
    completion_json: "{{ accepted_writer_completion_json }}"
    completion_sha256: "{{ trusted_writer_completion_sha256 }}"
    journal: "{{ accepted_writer_raw_journal }}"
    phase: os_quiesced
  register: owner
```

Normal and check mode perform the same read-only collection. A successful
result contains `owner_current_verified=True`, `application_quiesced=True`, a
canonical `result_json`, its `result_sha256` and the validated
`checkpoint_sha256`. `guest_image_verified` is false for stopped guests.
`changed` and all mutation, boot, rebuild, backup and restore flags stay false.

The module bounds inputs and output, hides its invocation values and emits
static failure messages. It exposes no mutation permission or lifecycle action.
An accepted current observation does not resolve an uncertain operation or
advance the ordered owner journal. Packaged-module refusal and privacy tests
qualify this boundary separately from managed-infrastructure acceptance.

### Ordered owner journal (developing)

`persistence_owner_journal` is an internal filesystem component for workflow
implementers. It stores an ordered operation chain under the fixed manager path
`/var/lib/cmdmesh/owner-lifecycle`. It exposes no Ansible action or native
shutdown/resume command.

The namespace uses the retained dataset-pair key. `Binding` also requires the
hash of the fully validated owner checkpoint and the exact `GuestBinding`.
The checkpoint binds the owner, generation, guest and retained resources.
A new nonce or manager boot cannot select a different operation history for
that pair. Journal schema 3 pins the `owner-os-action-v2` profile, including
explicit metadata resolution. Schema 1 and 2 metadata refuse without an
automatic upgrade or reset.

The caller must hold the real pair-exclusive lease throughout each operation.
Constructing a `Binding`, `Pending` or `Candidate` does not acquire that lease or
admit a native action. Before dispatch, the caller must separately validate
current ownership, runtime, guest backing and application state.

| Internal helper | Behavior |
| --- | --- |
| `_initialize(binding)` | Creates private profile, genesis and head records. Repeating an exact unused initialization makes no changes. Used, partial or foreign state refuses. |
| `_inspect(binding, expected_head_sha256)` | Reads and validates the complete chain against an externally trusted head. It creates no directories or records. |
| `_begin(binding, predecessor, kind, prepared_sha256)` | Records and syncs one shutdown or resume intent, then publishes a pending head before returning. |
| `_append_phase(pending, stage, payload)` | Appends the next fixed phase, verifies its exact intended hash, and returns a fresh pending token. Older tokens refuse. |
| `_complete(pending, evidence)` | Requires all three phases and an accepted terminal task. Records caller-validated evidence and returns a candidate successor after closing the filesystem checks. |
| `_fail(pending, reason, outcome)` | Attempts to retain an immutable failure record. It does not reset, rewind or remove an attempt. |
| `validate_phase_capture(binding, intent, records, descriptors)` | Validates captured raw phase bytes, fixed paths, file metadata, and links without filesystem or network access. |

Each operation stores these phases in its existing sequence directory:

| Phase | Required payload |
| --- | --- |
| `dispatch.json` | Exact action, guest binding, preparation and entry hashes, host epoch, clock, and fixed native parameters. Shutdown uses a 60-second timeout with forced stop disabled. Resume uses start without parameters. |
| `ack.json` | A TLS-verified UPID for the bound guest, action, and dispatch clock interval. |
| `terminal.json` | Stopped task status for the acknowledged UPID, a complete bounded log, and the outcome recomputed by the shared native classifier. |

Each phase links to its predecessor's raw hash. Unknown fields, secret fields,
duplicate phases, skipped phases, and target or action mismatches refuse.
A rejected terminal task can remain as evidence but cannot complete an
operation. Recording a valid payload does not prove that a native action ran.

`View`, `Pending`, and `Candidate` expose a `PhaseChain` with decoded records,
native file descriptors, and the canonical descriptor-map hash. Each descriptor
contains the fixed path, raw-byte hash, and nine typed file-identity values.
The result record binds the actual descriptor map and its hash. Capture
validation permits an exact phase prefix for diagnostics. An incomplete prefix
cannot complete an operation or authorize a retry.

The controller must accept the fully verified return before using a candidate
as successor authority. A head found on disk after a failed or unknown return
does not establish success. The separate caller-supplied completion evidence
remains opaque to this component. The native workflow must validate current
ownership, runtime, application state, and native postconditions.

Ordinary native operations refuse pending attempts, orphan slots, unexpected
files, stale heads, changed file identities, and permissive metadata. There is
no automatic cleanup, reset, or adoption. A failure after candidate publication
retains the candidate and its failure barrier. The explicit metadata-resolution
variant below has a separate admission contract.

Files require mode `0600`, one link and the executing identity. Captured native
phase descriptors require root ownership. Directories
require mode `0700`. The component checks canonical content, strict schemas,
exact membership and file identities, then repeats the filesystem closure
before returning. Each chain permits at most 4,096 slots, including resolutions.

Synthetic filesystem tests cover repeated clean cycles, real lock handoff,
pending requests, stale predecessors, phase ordering, partial writes, valid
record substitution after a write, and late metadata changes. Pure capture
tests cover raw hashes, metadata, and incomplete prefixes. Run the journal tests
with `python -m unittest discover -s tests -p 'test_persistence_owner_journal*.py' -v`.
These tests qualify metadata ordering only. Native lifecycle integration,
manager reboot, and source-unavailable restore remain unqualified.

### Metadata-only owner resolution (developing)

The journal can record a new metadata baseline after an interrupted native or
metadata attempt. This internal component performs no native action. The
caller must independently qualify current application state and native-worker
fencing under the real pair-exclusive lease. A proof hash or journal token
does not establish that qualification.

| Internal function | Behavior |
| --- | --- |
| `capture_basis(binding)` | Reads the exact current head, slot membership, raw file hashes, and file identities. It writes nothing. |
| `prepare_resolution(binding, anchor_raw, anchor_sha256, expected_basis_sha256, proof)` | Requires the latest externally accepted ready anchor and the exact externally accepted blocked-basis hash. Returns a bound preparation without writes. |
| `begin_resolution(binding, raw, trusted)` | Rechecks the preparation and appends a distinct resolution intent in the next slot. It preserves old records and publishes a pending resolution head. |
| `complete_resolution(pending)` | Records the metadata result and returns a candidate ready head. The caller must accept the verified return before using that head. |

The proof contains the actual observed phase plus separately qualified current
and worker-fence hashes. This filesystem component checks their shape and
binding. It does not collect or validate native-worker safety. The fence
observer, a resolver Ansible action, and native resolution trials remain unqualified.

A stopped API, inactive units, an empty cgroup, elapsed time, or reacquired
target shared lock cannot exclude a delayed native worker queued behind that
lock. An unknown request requires genuine worker safety evidence or an
independently admitted manager-epoch fence before resolution.

Resolution preserves original intent, phases, results, failures, and orphaned
staging bytes. It never invents an ACK, fills an old missing phase, changes a
native outcome, or adopts a found target HEAD. Its result reports
`metadata_resolution_recorded: true` and `native_action_dispatched: false`.
A later resolution can bind an interrupted resolution too. A stale anchor or
changed immutable prefix refuses before a new slot is created.

Forensic capture allows bounded empty or partial private files in known slot
positions. It retains their exact hashes and metadata without repairing their
contents. Each file is at most 4 MiB. The cumulative 16 MiB capture bound acts
during reading, and a resolution preparation is at most 4 MiB. Foreign files,
symlinks, unsafe ownership, and permissive modes refuse. Cross-directory head
publication syncs both affected directories. Ordinary and resolution-aware
history use the same native-result validator and require canonical result bytes.

### Same-owner OS transitions (developing)

`persistence_owner_transition` is an internal SDK for a quiesced reference
application whose accepted writer checkpoint comes from `load_writer_checkpoint`.
The developing Ansible boundary below exposes its finite actions. Local SDK
tests use real filesystem locks and modeled PVE responses. Native shutdown and
restart remain unqualified.

The current ACK timing rule has a known qualification defect: it measures task
time against a dispatch record written before closing admission work. A fresh
task after 61 seconds of legitimate closing work can fail the 60-second bound,
after the native request already took effect. Slow-closing SDK integration is
still under development; do not use a wider bound to
retroactively certify an uncertain operation. Preserve its journal and qualify
worker fencing/current state before metadata-only resolution.

The developing `persistence_owner_ack` codec separates an observed response from
a certified ACK. It retains bounded size/hash evidence for arbitrary responses,
and raw response JSON only when the complete body contains exactly one
UPID-shaped `data` value. Tickets, CSRF values, headers, arbitrary JSON fields and
partial bodies are not copied into plaintext observations. Its pure
`validate_ack(binding, action, dispatch_sha256, expected_epoch, observation)` binds
the expected action, guest, dispatch, pinned TLS peer and manager epoch. It reads
no current clock, filesystem or native API.

Each recorded clock sample brackets a wall-clock read with two monotonic reads.
Qualification requires ordered samples, no more than 100 ms uncertainty within
either individual sample, and wall elapsed time inside the measured monotonic
elapsed bounds. Task timestamps have integer-second precision; that task-second
interval must overlap the recorded request interval. The 100 ms sample limit is
an explicit uncertainty policy, not a delay or a wider bound from early dispatch.
An uncertain or missing receive sample can remain forensic evidence, but cannot
certify the ACK.

`persistence_guest_api.post_owner_guest_action` uses the existing finite pinned
TLS/PAM transport for one start or graceful-shutdown request. It samples send
clocks after authentication and TLS setup, then receive clocks after the bounded
body read, before native semantic validation. Redirects, partial responses and
missing receive clocks return unqualified observations without a second POST.
The existing `post_guest_action` contract and its return fields remain unchanged.
Both transport paths now refuse a short declared Content-Length body. Complete
chunked bodies require the terminal chunk, and connection-close bodies require
EOF. A valid JSON prefix alone cannot certify a response.
This leaf API performs no journal writes, resolution or retry. It is not yet
integrated into a new ordered SDK/profile. SDK integration and explicit legacy
authority handoff remain unqualified. Do not call the leaf to bypass a pending
lifecycle operation.

| SDK function | Contract |
| --- | --- |
| `genesis_sha256(checkpoint)` | Computes the proposed initial head without filesystem or network access. |
| `initialize(checkpoint, expected_head_sha256)` | Explicitly creates unused journal metadata after current running-state admission. Performs no native action. Partial, foreign, or used metadata refuses. |
| `prepare(checkpoint, predecessor_sha256, kind, prior_runtime=None)` | Reads a ready journal and current state. Returns a preparation for `shutdown` or `resume` without writing metadata. |
| `operate(checkpoint, prepared_raw, prepared_sha256, timeout_seconds=240)` | Rechecks preparation, begins one operation, dispatches one fixed native request, and verifies its final state. A pending attempt cannot become another request. |
| `status(checkpoint, prepared_raw, prepared_sha256, accepted_head_sha256, prior_runtime=None)` | Reads a separately accepted transition, its exact native task, and current state. Writes nothing and never dispatches a request. |
| `validate_result(checkpoint, prepared_raw, prepared_sha256, result)` | Checks captured return fields, raw records, native task metadata, and application proofs without filesystem or network access. Does not establish fresh native truth. |
| `inspect_initialization(checkpoint, expected_head_sha256)` | Rechecks absent or exact unused metadata plus current state, without creating files. Partial, used, or foreign state refuses. |
| `inspect_transition(checkpoint, prepared_raw, prepared_sha256)` | Rechecks a pinned ready preparation and current state without an intent, dispatch, or native request. |

Preparation binds the accepted checkpoint, predecessor, action, current entry,
host epoch, and backup mount. For shutdown, it also binds init process birth and
namespace identity and a nondecreasing uptime floor. A reused API PID cannot
satisfy that preparation. Fresh current validation still admits approved live
CPU selection through its intrinsic joins.

The workflow holds the real dataset-pair exclusive lock, retired guest shared
lock, and application exclusive lock throughout the native request. The target
guest shared lock covers current-state workers. The workflow releases that lock
before POST and task polling, then reacquires it after the task is terminal.
The shared API supplies graceful shutdown parameters with forced stop disabled.

Before POST, the workflow writes intent and dispatch inside the current worker
context. The closing current worker and fast checks must pass before dispatch.
The workflow records ACK before polling and terminal evidence after the task.
It then admits the intended final state and publishes a candidate inside another
current worker context. Its closing worker and every lease closure must pass before
the caller receives the candidate hash. Slow history and journal reads precede
the final worker. Fast file, process, and membership checks follow it.

The workflow reads original writer and boot history as immutable raw evidence.
It never calls the old boot status validator against application data that has
since changed. It preserves the application credential, record hashes, owner,
retired controls, root image, and dataset roles. It starts no application worker
and writes no application record.

The return includes six canonical raw records: intent, dispatch, ACK, terminal,
result, and HEAD. Their bytes match the files recorded by the journal. The result
binds both current-state proofs and the actual dispatch entry. The pure return
validator recomputes phase descriptors, record and head hashes, preparation
bindings, and native outcome. Controllers can check the captured evidence with
this shared validator before accepting a successor hash.

Failures preserve the pending attempt, native phases, and any candidate result.
A best-effort failure record retains whether dispatch was unreachable, unknown,
failed, or refused by postconditions. No automatic compensation or retry occurs.
A found target HEAD is not external acceptance. Metadata-only resolution,
including worker fencing for unknown acknowledgements, remains a separate
developing operation. This SDK does not qualify manager reboot or recovery.

### Ansible owner OS boundary (developing)

`cmdmesh.proxmox.lxc_persistence_owner_os` reconstructs the accepted checkpoint
before current-state access. Every action requires the original writer
`prepared_json`, `prepared_sha256`, `completion_json`, `completion_sha256`, and
all thirteen raw `journal` strings. These are writer inputs. They are separate
from a later OS transition's preparation.

| Action | Additional inputs | Check mode |
| --- | --- | --- |
| `initialize` | `head_sha256` is the proposed genesis. Normal mode requires `allow_mutation: true`. | Validates current state and absent or exact unused metadata. Creates nothing. |
| `prepare` | `head_sha256` is the externally accepted predecessor. `kind` is `shutdown` or `resume`. Optional `prior_runtime` supplies the accepted running frame. | Same read-only operation as normal mode. |
| `transition` | `transition_prepared_json` and `transition_prepared_sha256` bind the OS preparation. Normal mode requires `allow_mutation: true`. | Rechecks the preparation and current state without a slot, dispatch, or POST. |
| `status` | The OS preparation pair, externally accepted returned `head_sha256`, and optional `prior_runtime`. | Same completed-only read-only operation as normal mode. |

Irrelevant arguments refuse. The transition action takes its predecessor from
the pinned preparation. It accepts no separate head, kind, or prior-runtime
override. Mutation permission defaults to false. No resolver action is exposed.

Preparation returns `transition_prepared_json` and its exact hash. Other
successful actions return `result_json` and `result_sha256`. Verify this outer
hash before decoding the JSON. A transition's nested `result_sha256` is the
journal-result hash. The outer hash covers the complete SDK return. Pass the
decoded return to `validate_result` before accepting its successor head.

A check-mode `changed: true` means the action would change state. Its
`mutation_attempted`, `metadata_initialized`, and `os_transition_verified`
flags remain false. `metadata_initialized` describes a successful initialization
call, not whether a later transition uses an existing journal. Mutator failures
report possible effects conservatively and clear verification flags. Raw inputs
and exception text are withheld from output, including argument-validation
failures. A failed or unknown return grants no retry or node-head adoption.

Local tests cover actual Ansible serialization, an installed collection, and
the exact module and owned-helper bytes in generated AnsiballZ archives.
Installed refusal tests use malformed authority and reach no host observation.
Modeled SDK tests cover successful receipt transfer and native lock handoff.
These checks do not qualify a managed initialization or lifecycle trial.
