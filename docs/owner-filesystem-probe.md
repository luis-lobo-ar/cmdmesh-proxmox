# Measuring a filesystem before owner metadata publication

`tools/qualify-owner-filesystem.py` runs a finite diagnostic on a disposable
sibling directory outside the legacy and handoff roots. Its CLI owns the actual
pair, native-configuration and application-configuration leases. It keeps the
original metadata, references and database inode observed. It does not run SQL,
start or stop a guest, publish handoff records, or retry an interrupted operation.

Use a source-staged collection on the owned disposable manager. The controller
must select the inputs and authenticate the program, source package and closed
transport result. This helper requires ordinary Python. Optimized Python refuses
before SDK or input loading.

Use Python 3.11 or newer on 64-bit Linux. The local procedure qualification used
Python 3.12.3 and does not qualify another machine's interpreter or filesystem.

## Run the diagnostic

The input JSON has these exact fields:

| Field | Value |
| --- | --- |
| `binding` | The binding derived from the accepted checkpoint. |
| `checkpoint`, `checkpoint_sha256` | The accepted checkpoint object and hash. |
| `intent_raw`, `intent_sha256` | Exact canonical H0 text and hash. |
| `contract_raw`, `contract_sha256` | Exact selected publication-contract text and hash. |
| `phase` | `os_quiesced` or `stopped`. |
| `prior_runtime_raw`, `prior_runtime_sha256` | Canonical last accepted running observation and hash, or both `null`. Required for `stopped`. |

The prior value is the observation frame, not an evidence envelope. The helper
validates its shape before opening leases. It does not discover an input hash
from managed files.

With selected inputs staged under a private `.generated` directory, run:

```sh
umask 077
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/ansible" python tools/qualify-owner-filesystem.py \
  --inputs .generated/owner-fs-probe-inputs.json \
  --allow-probe > .generated/owner-fs-probe-candidate.json
```

`--allow-probe` explicitly permits this diagnostic's test writes. Check mode
refuses the write procedure. A check-only result cannot qualify a filesystem.

## What the procedure measures

The helper derives the one common private parent and all metadata destinations
from the selected inputs. The first profile requires those destinations and the
probe to use the same actual mount. A separate mount without a permitted sibling
probe is unavailable under this profile.

The procedure creates a private `probe-<random identifier>` child under the fixed
diagnostic base. It measures:

- The real anonymous-file publication receipt and its inotify events.
- A second exclusive link attempt returning `EEXIST`, with the original final
  file unchanged and a bounded collision-event trace.
- Private directory creation and synchronization.
- A named same-byte write and its actual mutation events.
- Creation, writing and deletion of one transient test file.

The procedure checks the fixed event grammar and retains source-byte observations
for the publication primitives. It closes its descriptors and removes only the
test inodes it can identify. It leaves the diagnostic base available for later
samples. It never recursively deletes a directory.

Before its first synchronization, the helper opens and binds the newly created
probe directory. Cleanup requires that retained descriptor and the named entry
to identify the same directory. If opening fails or the entry is replaced, it
preserves the residue and any replacement rather than deleting an unbound name.

A failed post-link call can leave an unaccepted test file. The helper preserves
that residue instead of adopting or retrying it. Cleanup failures suppress a
positive candidate. If another failure already occurred, cleanup preserves that
first failure and records secondary errors as notes.

## Accept a result separately

A zero exit returns a canonical **candidate**, not a filesystem qualification.
The result records the actual sample, filesystem subject and unchanged namespace
projection. It keeps producer authentication, filesystem qualification and native
operation flags false.

The candidate has no fabricated closed-probe provenance reference. First the
controller verifies the completed procedure's source, input, receipt, resource
and transport closure. Then a separate builder can reference that accepted
evidence when constructing the qualification record. This order avoids a record
that must contain its own future receipt hash.

The executor must still match current boot, namespace, mount and parent facts
before publication and validate its real witness descriptors and events. A
successful sample proves neither power-loss durability nor exclusion of
arbitrary root or CLI writers. Local procedure tests do not qualify a managed
filesystem or the whole recovery workflow.
