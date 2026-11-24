"""One bounded full-snapshot encryption pipeline; never accepts shell commands.

The caller owns exclusive artifact creation and independent path/readback checks.
Partial ciphertext is retained on every failure. Hard-NFS I/O can resist signals;
unproved termination is explicitly uncertain, never permission to retry.
"""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
WORKER = """import hashlib,json,os,resource,subprocess,sys
p=json.loads(sys.argv[1]);out=p['fd']
gate=os.read(p['gate'],4);os.close(p['gate'])
if gate!=b'RUN\\n':sys.exit(125)
resource.setrlimit(resource.RLIMIT_FSIZE,(p['max_bytes'],p['max_bytes']))
producer=subprocess.Popen([p['zfs'],'send','-p',p['snapshot']],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE)
try:
 encryptor=subprocess.Popen([p['age'],'--encrypt','--recipient',p['recipient']],stdin=producer.stdout,stdout=subprocess.PIPE)
finally:
 producer.stdout.close()
checksum=hashlib.sha256();count=0
while True:
 chunk=encryptor.stdout.read(65536)
 if not chunk:break
 if count+len(chunk)>p['max_bytes']:raise RuntimeError('ciphertext limit')
 pending=memoryview(chunk)
 while pending:
  written=os.write(out,pending)
  if written<=0:raise RuntimeError('ciphertext write failed')
  checksum.update(pending[:written]);count+=written;pending=pending[written:]
encryptor.stdout.close()
consumer_code=encryptor.wait();producer_code=producer.wait()
synced=False
if consumer_code==0 and producer_code==0:
 os.fsync(out);synced=True
print(json.dumps({'producer_exit_code':producer_code,'encryptor_exit_code':consumer_code,'file_fsynced':synced,'ciphertext_bytes':count,'ciphertext_sha256':checksum.hexdigest()}),flush=True)
sys.exit(0 if synced else 1)
"""


class StreamError(ValueError):
    def __init__(
        self,
        code,
        command_outcome="not-dispatched",
        *,
        group_stopped=True,
        worker_pid=None,
        worker_start_ticks=None,
        result=None,
    ):
        self.code = code
        self.command_outcome = command_outcome
        self.group_stopped = group_stopped
        self.worker_pid, self.worker_start_ticks = worker_pid, worker_start_ticks
        self.result = result
        self.producer_exit_code = result.get("producer_exit_code") if result else None
        self.encryptor_exit_code = result.get("encryptor_exit_code") if result else None
        super().__init__(code)


def require(value, code):
    if not value:
        raise StreamError(code)


def tool(reference):
    require(
        type(reference) is dict and set(reference) == {"path", "sha256"},
        "persistence-stream-tool-invalid",
    )
    require(
        type(reference["path"]) is str
        and type(reference["sha256"]) is str
        and re.fullmatch("[a-f0-9]{64}", reference["sha256"]),
        "persistence-stream-tool-invalid",
    )
    path = Path(reference["path"])
    require(
        path.is_absolute() and path.resolve(strict=True) == path,
        "persistence-stream-tool-path",
    )
    before = path.lstat()
    require(
        stat.S_ISREG(before.st_mode)
        and before.st_uid in {0, os.geteuid()}
        and not before.st_mode & 0o6022
        and before.st_mode & 0o100
        and 0 < before.st_size <= 33554432,
        "persistence-stream-tool-permissions",
    )
    fingerprint = lambda s: (
        s.st_dev,
        s.st_ino,
        s.st_mode,
        s.st_uid,
        s.st_gid,
        s.st_nlink,
        s.st_size,
        s.st_mtime_ns,
        s.st_ctime_ns,
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(
            fingerprint(os.fstat(fd)) == fingerprint(before),
            "persistence-stream-tool-changed",
        )
        checksum = hashlib.sha256()
        count = 0
        while raw := os.read(fd, 65536):
            count += len(raw)
            require(count <= before.st_size, "persistence-stream-tool-changed")
            checksum.update(raw)
        require(
            fingerprint(os.fstat(fd)) == fingerprint(before)
            and fingerprint(path.lstat()) == fingerprint(before)
            and checksum.hexdigest() == reference["sha256"],
            "persistence-stream-tool-changed",
        )
    finally:
        os.close(fd)
    return str(path)


def process(pid):
    try:
        with open("/proc/" + str(pid) + "/stat", "rb") as stream:
            raw = stream.read(16385)
        require(len(raw) <= 16384, "persistence-stream-process-invalid")
        parts = raw.rpartition(b") ")[2].split()
        return {
            "state": parts[0].decode(),
            "parent": int(parts[1]),
            "group": int(parts[2]),
            "session": int(parts[3]),
            "birth": int(parts[19]),
        }
    except (FileNotFoundError, ProcessLookupError):
        return None


def active_group(pid):
    members = []
    entries = list(Path("/proc").glob("[0-9]*"))
    require(len(entries) <= 32768, "persistence-stream-process-scan-limit")
    for entry in entries:
        try:
            row = process(int(entry.name))
        except PermissionError:
            if entry.stat().st_uid == os.geteuid():
                raise
            continue
        if (
            row
            and row["group"] == pid
            and row["session"] == pid
            and row["state"] != "Z"
        ):
            members.append(int(entry.name))
    return members


def anchor(pid, birth):
    row = process(pid)
    return bool(
        row
        and row["birth"] == birth
        and row["parent"] == os.getpid()
        and row["group"] == row["session"] == pid
    )


def stop_group(pid, birth):
    try:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            if not anchor(pid, birth):
                return False
            if not active_group(pid):
                return True
            os.killpg(pid, sig)
            end = time.monotonic() + 0.75
            while time.monotonic() < end:
                if not anchor(pid, birth):
                    return False
                if not active_group(pid):
                    return True
                time.sleep(0.02)
        return False
    except (OSError, ValueError, IndexError):
        return False


def fd_identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
    )


def encrypt_snapshot(
    snapshot,
    recipient,
    output_fd,
    tools,
    *,
    journal_fd,
    timeout_seconds=60,
    max_ciphertext_bytes=67108864,
):
    require(
        type(snapshot) is str
        and len(snapshot) <= 1024
        and re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_.-]+)+@cmdmesh-[a-f0-9]{64}",
            snapshot,
        )
        and not ({".", ".."} & set(snapshot.split("@", 1)[0].split("/"))),
        "persistence-stream-snapshot-invalid",
    )
    require(
        type(recipient) is str
        and re.fullmatch(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}", recipient),
        "persistence-stream-recipient-invalid",
    )
    require(
        type(timeout_seconds) in {int, float} and 0.05 <= timeout_seconds <= 600,
        "persistence-stream-deadline-invalid",
    )
    require(
        type(max_ciphertext_bytes) is int and 1024 <= max_ciphertext_bytes <= 2**40,
        "persistence-stream-limit-invalid",
    )
    require(
        type(output_fd) is int
        and output_fd > 2
        and type(tools) is dict
        and set(tools) == {"age", "zfs"}
        and type(journal_fd) is int
        and journal_fd > 2
        and journal_fd != output_fd,
        "persistence-stream-input-invalid",
    )
    try:
        paths = {name: tool(reference) for name, reference in tools.items()}
        before = os.fstat(output_fd)
        flags = fcntl.fcntl(output_fd, fcntl.F_GETFL)
        require(
            stat.S_ISREG(before.st_mode)
            and stat.S_IMODE(before.st_mode) == 0o600
            and before.st_nlink == 1
            and before.st_size == 0
            and os.lseek(output_fd, 0, os.SEEK_CUR) == 0
            and flags & os.O_ACCMODE in {os.O_WRONLY, os.O_RDWR}
            and not flags & os.O_APPEND,
            "persistence-stream-output-invalid",
        )
        journal = os.fstat(journal_fd)
        journal_flags = fcntl.fcntl(journal_fd, fcntl.F_GETFL)
        require(
            stat.S_ISREG(journal.st_mode)
            and stat.S_IMODE(journal.st_mode) == 0o600
            and journal.st_uid == os.geteuid()
            and journal.st_nlink == 1
            and journal.st_size == 0
            and os.lseek(journal_fd, 0, os.SEEK_CUR) == 0
            and journal_flags & os.O_ACCMODE in {os.O_WRONLY, os.O_RDWR}
            and not journal_flags & os.O_APPEND
            and (journal.st_dev, journal.st_ino) != (before.st_dev, before.st_ino),
            "persistence-stream-journal-invalid",
        )
        require(
            signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
            "persistence-stream-reaper-unsupported",
        )
        probe = os.pidfd_open(os.getpid())
        os.close(probe)
    except StreamError:
        raise
    except (OSError, ValueError):
        raise StreamError("persistence-stream-input-unavailable") from None
    parameters = {
        **paths,
        "snapshot": snapshot,
        "recipient": recipient,
        "fd": output_fd,
        "max_bytes": max_ciphertext_bytes,
    }
    try:
        gate_read, gate_write = os.pipe()
    except OSError:
        raise StreamError("persistence-stream-worker-unavailable") from None
    parameters["gate"] = gate_read
    try:
        child = subprocess.Popen(
            [sys.executable, "-I", "-S", "-B", "-c", WORKER, json.dumps(parameters)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(output_fd, gate_read),
            start_new_session=True,
            env=ENV,
        )
    except (OSError, subprocess.SubprocessError):
        os.close(gate_read)
        os.close(gate_write)
        raise StreamError("persistence-stream-worker-unavailable") from None
    os.close(gate_read)
    pid, birth, pidfd = child.pid, None, None
    group_closed = False
    released = False
    stdout, stderr = bytearray(), bytearray()
    deadline = time.monotonic() + timeout_seconds
    try:
        row = process(pid)
        require(
            row
            and row["group"] == row["session"] == pid
            and row["parent"] == os.getpid(),
            "persistence-stream-anchor-invalid",
        )
        birth = row["birth"]
        armed = json.dumps(
            {
                "document_type": "cmdmesh.proxmox.persistence.pipeline-armed",
                "schema_version": 1,
                "worker_pid": pid,
                "worker_start_ticks": birth,
                "worker_sha256": hashlib.sha256(WORKER.encode()).hexdigest(),
                "parameters_sha256": hashlib.sha256(
                    json.dumps(
                        parameters, sort_keys=True, separators=(",", ":")
                    ).encode()
                ).hexdigest(),
                "parameters": parameters,
                "output_identity": fd_identity(before),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        pending = memoryview(armed)
        while pending:
            n = os.write(journal_fd, pending)
            require(n > 0, "persistence-stream-journal-write-failed")
            pending = pending[n:]
        os.fsync(journal_fd)
        require(
            fd_identity(os.fstat(journal_fd)) == fd_identity(journal)
            and os.fstat(journal_fd).st_size == len(armed),
            "persistence-stream-journal-changed",
        )
        require(
            time.monotonic() < deadline, "persistence-stream-deadline-before-dispatch"
        )
        released = True
        require(os.write(gate_write, b"RUN\n") == 4, "persistence-stream-gate-failed")
        os.close(gate_write)
        gate_write = None
        pidfd = os.pidfd_open(pid)
        with selectors.DefaultSelector() as selector:
            selector.register(pidfd, selectors.EVENT_READ, "exit")
            for handle, name in ((child.stdout, "stdout"), (child.stderr, "stderr")):
                os.set_blocking(handle.fileno(), False)
                selector.register(handle, selectors.EVENT_READ, name)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise StreamError("persistence-stream-timeout", "unknown")
                for key, unused in selector.select(
                    min(0.1, max(0, deadline - time.monotonic()))
                ):
                    if key.data == "exit":
                        selector.unregister(key.fileobj)
                        continue
                    raw = os.read(key.fd, 65536)
                    if not raw:
                        selector.unregister(key.fileobj)
                        continue
                    target, limit = (
                        (stdout, 4096) if key.data == "stdout" else (stderr, 65536)
                    )
                    require(
                        len(target) + len(raw) <= limit,
                        "persistence-stream-diagnostic-limit",
                    )
                    target.extend(raw)
        require(
            anchor(pid, birth) and not active_group(pid),
            "persistence-stream-group-not-closed",
        )
        group_closed = True
        code = child.wait(timeout=1)
        try:
            result = json.loads(stdout)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise StreamError("persistence-stream-result-invalid", "unknown") from None
        require(
            type(result) is dict
            and set(result)
            == {
                "producer_exit_code",
                "encryptor_exit_code",
                "file_fsynced",
                "ciphertext_bytes",
                "ciphertext_sha256",
            },
            "persistence-stream-result-invalid",
        )
        require(
            all(
                type(result[k]) is int and -128 <= result[k] <= 255
                for k in ("producer_exit_code", "encryptor_exit_code")
            )
            and type(result["file_fsynced"]) is bool
            and type(result["ciphertext_bytes"]) is int
            and 0 <= result["ciphertext_bytes"] <= max_ciphertext_bytes
            and type(result["ciphertext_sha256"]) is str
            and re.fullmatch("[a-f0-9]{64}", result["ciphertext_sha256"]),
            "persistence-stream-result-invalid",
        )
        if (
            code != 0
            or result["producer_exit_code"] != 0
            or result["encryptor_exit_code"] != 0
        ):
            raise StreamError(
                "persistence-stream-command-failed", "failed", result=result
            )
        require(
            result["file_fsynced"] is True and result["ciphertext_bytes"] > 0,
            "persistence-stream-result-invalid",
        )
        after = os.fstat(output_fd)
        require(
            fd_identity(after) == fd_identity(before)
            and after.st_size == result["ciphertext_bytes"]
            and os.lseek(output_fd, 0, os.SEEK_CUR) == after.st_size,
            "persistence-stream-output-changed",
        )
        for reference in tools.values():
            tool(reference)
        return {
            **result,
            "command_outcome": "succeeded",
            "group_stopped": True,
            "worker_pid": pid,
            "worker_start_ticks": birth,
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        }
    except (
        StreamError,
        OSError,
        ValueError,
        IndexError,
        subprocess.SubprocessError,
    ) as error:
        stopped = group_closed or (birth is not None and stop_group(pid, birth))
        if stopped and not group_closed:
            child.wait(timeout=1)
        outcome = (
            "not-dispatched"
            if not released
            else (
                error.command_outcome
                if isinstance(error, StreamError)
                and error.command_outcome != "not-dispatched"
                else "unknown"
            )
        )
        raise StreamError(
            (
                error.code
                if isinstance(error, StreamError)
                else "persistence-stream-execution-uncertain"
            ),
            outcome if stopped else "unknown",
            group_stopped=stopped,
            worker_pid=pid,
            worker_start_ticks=birth,
            result=error.result if isinstance(error, StreamError) else None,
        ) from None
    finally:
        if gate_write is not None:
            os.close(gate_write)
        if pidfd is not None:
            os.close(pidfd)
        child.stdout.close()
        child.stderr.close()
