# Completion after a guest stops or the manager reboots

The developing `persistence_owner_completion` codec prepares and validates
version-2 publication contracts and completion records. It separates historical
handoff evidence from a fresh observation of the guest. It performs no file
publication, lifecycle action, database query or lease acquisition.

For example, a controller can prepare a handoff while a guest is running with
its application quiescent. If the manager subsequently reboots, recovery must
validate the guest's current state and the new manager epoch. Comparing that
epoch with the original handoff observation would incorrectly reject recovery.
Reusing the original observation would fail to check the current state.

The contract binds the externally selected checkpoint, H0 intent, historical
evidence and worker-fence reference, fresh source manifest, storage protocol and
required execution gates. Its canonical bytes and digest are review inputs.
An external acceptance decision must select that digest before an executor uses
the contract. Preparing or decoding the contract does not establish acceptance.
It contains no digest of a future completion or post-publication observation.

The version-2 completion preserves the existing H0 and marker bytes and records:

- Their exact file descriptors and hashes, plus the historical basis hash.
- The checkpoint, contract and historical evidence hashes.
- A fresh phase, manager epoch, complete current observation, admission entry
  and source-manifest hash.
- An explicit prior accepted running-OS observation for stopped admission.
- Metadata-only flags that leave the original native operation unqualified.

Contract and completion bytes must be canonical JSON and fit the existing
4 MiB bound. File descriptors preserve the exact private-file identity, size
and hash checks. Unknown fields, numeric substitutes for boolean flags and
changed checkpoint, marker or historical references refuse.

`persistence_owner_phase_admission.validate_phase_admission` joins that admission
entry to the existing intrinsic current validator. Both supported phases,
`os_quiesced` and `stopped`, preserve application identity and retained data.
Stopped evidence does not claim that a running guest image was verified.
The prior observation is selected by the controller; a node-side value is not
accepted authority merely because its fields validate.

The pure checks can validate a prior-process fence declaration's shape and its
consistency with the observed manager boot. Only the real producer can establish
that it observed a typed absence or different process identity under leases.
A new manager boot must not trigger a probe of a historical numeric PID.

Runtime schema 2 remains a storage declaration. The bootstrap mutex and its
canonical profile bytes do not change. Runtime schema 2 does not exclude every
older callable metadata writer; the admitted controller/source inventory must
exclude incompatible writers before any managed publication.

Legacy completion schema 1 retains its existing validator for explicit historical
review. The new codec rejects it. It must not be rewritten or promoted to fresh
authority. A lost callback, including after a complete version-2 file appears,
requires fresh post-publication observation and a separate accepted recovery
artifact. A partial completion remains blocked and must be preserved.

The companion `persistence_owner_continuation_v2` planner requires the selected
contract before preparing any of the four missing-record plans. It preserves
the original storage classifier and exact capture projection. It replaces
historical phase/epoch equality with the contract's fresh admission policy and
keeps the historical worker-fence reference separate. Its loader reconstructs
the complete canonical plan; a version-1 plan cannot pass that loader.
Unused namespaces and completed candidates use separate paths. A completion's
future bytes are not guessed while planning.

The [version-2 inspector/replay/witness interfaces](owner-semantic2-integration.md)
now carry the selected contract through metadata observation and one fixed
publication. The planner consumes their actual capture2 and refuses capture1.

These codecs are components of recovery. The executor, source and actor
qualification, post-publication database/reference closure and lost-callback
reconciliation still need integration. No successful
decode grants publication permission, native admission, reconstructed ACK or
proof that resource and lease exits succeeded. Local synthetic tests do not
qualify a managed filesystem, power-loss recovery or disaster recovery.
