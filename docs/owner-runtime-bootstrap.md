# Serializing the shared owner runtime

`persistence_owner_bootstrap.locked_runtime_bootstrap(initialize=False)` is a
developing internal context manager. It serializes cooperating runtime
initializers across owner pairs. It does not admit a handoff, validate current
state, fence workers or authorize a native action. The retirement workflow does
not use it yet.

Pair locks protect individual owners. They cannot prevent two different pairs
from initializing the same shared runtime. This context uses one fixed,
owner-neutral record named `owner-handoff-bootstrap-v2.lock.json` beside the
handoff runtime. It is outside both exact owner-runtime roots and takes no
pair key or caller-selected path.

The canonical record binds the runtime path, runtime-profile hash and publication
protocol. The parent must already be a private root-owned directory. An existing
record must be a private, single-link regular file with exact canonical bytes.
Partial, foreign, public, symlink, hardlink and special-file records refuse.

Initialization is an explicit write:

```python
with locked_runtime_bootstrap(initialize=True):
    # Only qualified runtime mkdir/profile publication belongs here.
    ...

# SQL, current-state and native workers run after this context has exited.
```

With `initialize=False`, a missing record refuses without creating anything.
Explicit initialization uses the selected anonymous-file atomic publisher and
never replaces an existing name. A simultaneous initializer can publish first;
the loser validates that complete record before attempting the mutex. A late
write-close event from the first initializer can conservatively refuse an
observation. The library performs no automatic retry or waiting loop.

The actual mutex is a nonblocking exclusive `flock` on the same read-only file
descriptor held by the observer. No second descriptor is opened to acquire or
release it. Exact file metadata, bytes, names and inotify events close through
the critical section; shared parent directories retain stable-five policy.
The owning process and source configuration must remain unchanged. Descriptor
release failure suppresses a positive context exit and preserves a primary body
exception when both fail.

Process death releases the kernel lease; the canonical file remains. A failed
initializer may leave a complete unaccepted mutex record. A fresh validated
mutex context makes no claim that the earlier initialization or a handoff
succeeded. The file is a shared kernel-lock address, not an operation claim or
historical durability receipt. Never remove it while controllers can use it.

All cooperating initializers must use this protocol. Old or unmanaged writers
are not serialized by a lock they do not acquire. The later executor must still
reject schema-1 or inconsistent runtime state and qualify the managed filesystem
before publishing. Holding this mutex does not make a legacy runtime compatible.

The critical section must end before SQL, current/native workers or other slow
operations. This is a caller obligation that the eventual executor must test;
the context cannot certify an arbitrary Python body. Only runtime directory and
profile validation/publication belongs inside it.

The disposable tests exercise real cross-process contention, simultaneous
initialization, owner death, an actual runtime mkdir/profile, failed post-link
initialization, unsafe records, replacement, equal-byte mutation and release
failure. The event-isolation test explicitly models the metadata closer; it
proves event coverage alone. Local tests do not qualify managed publication,
physical power loss, worker sequencing or disaster recovery.
