# Observing resources during a handoff

These developing Python SDK components support the owner-handoff executor.
They are internal interfaces, not standalone commands or permission to recover
an interrupted operation. The managed executor remains under development.

## Keep resources observed before the first database check

`persistence_owner_resources.hold_owner_resources` takes a validated semantic2
selection, the actual leased entry observation, and one fixed action. It opens
and holds observers for:

- Original handoff files and directories, including the pending journal.
- Reference policy files, service references and ownership records.
- The fixed mapped data directory and its existing SQLite database inode.

The caller must acquire the real pair, native-configuration and application
leases first. Enter this context **before the first current-state SQL worker**;
arming an observer after a successful query leaves an unobserved interval.
The database observer checks ownership, identity and membership without reading
database contents. The current-state worker must still validate the real
database. A checkpoint's database metadata only selects what to observe.
The outer application lease and current-state worker retain responsibility for
the application configuration file. This resource context does not read it.

Read-only SQLite access is allowed. Writes, sidecar creation, replacement and
metadata changes cause refusal. A caught validation failure remains a failure;
releasing a context cannot turn it into a positive result.

For `publish-marker`, the original root may gain only the planned marker. This
projection alone does not detect every transient unknown root child. The caller
must overlap the full attempt inspector and planned marker-publication witness
before the first current worker, and retain the planned witness through the
final post-publication worker. Original files and slot directories stay exact.

## Create a fixed empty directory

`persistence_owner_directory.observe_directory_creation_v2` accepts the same
checkpoint, binding, H0 and contract inputs as other semantic2 entry points.
Its `role` is exactly `runtime-root` or `pair`; callers cannot supply a path.
It permits one `mkdir(0700)`, observes the expected parent event, validates and
watches the empty child, and fsyncs both directories. It refuses an existing
directory or symlink instead of adopting it.

The returned `DirectoryReceipt` is a candidate while the context is open.
`operation.completed` becomes true only after successful observer closure,
descriptor release and final input checks. A failure can leave the directory
present; the context never deletes or retries that prefix.

To hand observation to the file publisher, enter the matching version-2
publication witness while the empty-directory context remains open. Check that
the publisher's parent identity matches the directory receipt, close the
directory context, and only then publish the file. Publishing while the child
is still required to be empty correctly fails validation.

## Executor obligations

Neither component acquires leases, executes SQL, starts a guest, initializes a
bootstrap lock, or accepts a supplied publication receipt. Directory creation
requires qualified filesystem behavior and exclusive cooperating-writer
ownership: inotify cannot observe inside a child before it exists or identify
the process that wrote an event.

The complete executor must join every resource's membership scans before named
metadata and event checks, retain coverage through the final current worker,
and await every resource and lease exit before returning an accepted result.
These local components do not qualify the managed filesystem, authenticate a
producer, resolve a lost callback, or grant native-operation authority.

The developing [execution-admission and filesystem checks](owner-execution-admission.md)
separate externally selected records from live destination-parent observations.
Their initial ancestor facts do not replace the attempt and publication witnesses.
