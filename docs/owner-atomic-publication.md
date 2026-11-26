# Atomic publication for owner metadata

This internal primitive is a prospective storage component, not a managed
handoff command. It does not validate current application state, hold owner
leases, qualify a worker fence or grant native authority. The retirement caller
must provide those guarantees and select the storage protocol explicitly.

`persistence_owner_atomic.publish_private(path, raw, protocol=PROTOCOL)` publishes
one bounded immutable byte string at a private final filename. It returns its
SHA-256 only after publication and descriptor closure succeed. An existing
destination always refuses, including one with identical contents.

The sole protocol is `linux-otmpfile-procfd-exclusive-link-v1`:

1. Hold and validate the private destination-directory descriptor.
2. Open an anonymous `O_TMPFILE` on that same filesystem.
3. Write all bytes, fsync the file, and verify its contents and private identity.
4. Verify the source through a held `/proc/self/fd` directory on procfs.
5. Link that descriptor to the final name using exclusive `linkat` with
   `AT_SYMLINK_FOLLOW`.
6. Fsync and recheck the destination parent, then verify the final file's
   contents, single link and fixed name. No parent walk follows those checks.
7. Close every descriptor before returning success.

The staging inode has zero links. Once published, it has one; there is no named
temporary alias or partial final file to clean up. The code never uses
`O_TMPFILE | O_EXCL`, which would prevent linking the anonymous file. It does
not use rename-overwrite, truncation, a direct-write fallback or an alternative
link protocol when this one is unsupported.

The implementation requires Linux64, procfs, same-filesystem anonymous files,
exclusive linking and usable file/directory fsync. These must be qualified on
the selected managed filesystem before application. Local tests do not prove
managed support or physical power-loss behavior.

## Failure behavior

| Failure point | Final name |
| --- | --- |
| Before link, including a partial write or file-fsync failure | Absent; anonymous staging is released on close or process death. |
| Destination already exists | Existing bytes and identity are retained. |
| After link, including directory-fsync or descriptor-close failure | A complete but unaccepted candidate may remain. No success is returned. |
| Unsupported filesystem or proc descriptor binding | Refusal; no weaker publication method is selected. |

The caller must preserve failure evidence and inspect the exact fixed state
before selecting a continuation. A surviving candidate is not proof of a
successful callback, durable directory entry or completed handoff. This
primitive does not repair inherited truncated files or silently adopt existing
metadata.

The lease-owning caller must retain its own observers and reclose selected
files through the enclosing resource exits. This byte publisher is not a
replacement for that complete operation proof.

The disposable local tests exercise actual process death before and after the
link, short and failed writes, fsync/close failures, exclusive-name refusal,
wrong procfs/descriptor binding, private metadata and unexpected extra links.
They use synthetic bytes and no managed host. Run them with the repository's
normal test environment and `test_persistence_owner_atomic.py`.
