# Selecting executor inputs and checking the actual filesystem

These developing SDK components prepare the owner metadata executor. They do
not authenticate a producer, grant native permission, or qualify a managed
filesystem by themselves.

## Select records outside the managed node

`persistence_owner_execution_admission.load_execution_admission` takes an exact
semantic `Selection`, one fixed action, and five selected byte/hash pairs:

- The execution-admission statement.
- The historical authority.
- The historical causal capture.
- The portable executing-producer manifest.
- The filesystem-qualification record.

The loader replays the existing historical causal codec and checks the joins to
the selected checkpoint, H0 and publication contract. Original historical
decisions stay separate from the new executing-producer identity. The portable
manifest uses logical component paths and source bytes. A workstation's test
manifest is not an installed producer identity.

The returned frozen `Admission` retains exact bytes, hashes, action and the same
`selection` object. `validate()` checks those inputs again without filesystem or
network access. It does not return a decoded mutable dictionary or a permission
boolean. The trusted controller must authenticate and select these records.
Hashing a node's output cannot make that output accepted authority.

Admission statements are limited to 64 KiB. Producer and filesystem records are
limited to 1 MiB each. The historical codecs retain their existing byte limits.
Every record uses exact canonical JSON with duplicate keys and non-finite values
refused. The shared JSON validator enforces depth 64 and at most 200,000 nodes
before canonical encoding. JSON booleans cannot substitute for integer fields.
Mount options are bounded to 4,096 bytes each and 128 entries per option list.

## Observe the actual filesystem

`persistence_owner_filesystem.observe_subject(selection)` reads bounded Linux
mountinfo, descriptor mount IDs, statfs facts, boot/namespace identity and seven
source-derived destination roles. It retains the nearest existing ancestors and
the process's actual procfs descriptors. It writes nothing.

The returned bytes have explicit scope
`initial-nearest-ancestors-with-retained-identities`. A missing suffix describes
the initial observation. It is not a continuing absence watch. The actual
attempt, directory and publication witnesses must cover namespace changes.

`hold_qualified_subject(selection=..., admission=...)` compares those live facts
with the externally selected qualification before a metadata write. It refuses
stale boot, namespace, kernel, ancestor, mount-ID, mount-option or filesystem
identity facts. It permits only the five metadata-write actions. Read-only
inspection and full-candidate requalification use distinct executor paths.

Before each mkdir or publication, `assert_destination_parent` checks the actual
held witness descriptor against its fixed role. This includes newly created
private parents. The descriptor must match the named parent, private ownership,
selected mount, filesystem identity and current epoch. Callers must retain the
real directory/publication witness through the required closure. This assertion
does not replace its event checks or closed publication receipt.

These components are not mount-change event monitors. Their guarantee depends
on the declared cooperating-source scope and the executor's real leases and
overlapping witnesses. They do not exclude arbitrary root or CLI writers.

## Qualify before deployment

The first profile uses a disposable probe subtree outside both protocol roots.
The qualification binds actual atomic publication and event observations to the
same mount and primitive source bytes. Every real operation still checks its
own parent, receipt and events. A synthetic trace or a successful workstation
test cannot qualify the managed node.

The per-process `/proc/self/fd` inode is not reused as another process's identity.
Each invocation verifies its own held/named procfs binding. Successful fsync does
not establish power-loss durability. The full self-leased executor, installed
producer authentication and managed qualification remain required.

The [filesystem probe procedure](owner-filesystem-probe.md) produces an actual
sample for separate controller verification. It emits a candidate without
inventing the later closed-provenance reference.
