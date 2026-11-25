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
