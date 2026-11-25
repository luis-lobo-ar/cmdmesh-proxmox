"""Real age encryption over a synthetic producer; never invokes live ZFS."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(
    0, str(ROOT / "ansible/ansible_collections/cmdmesh/proxmox/plugins/module_utils")
)
import persistence_stream as stream

AGE = os.environ.get("CMDMESH_AGE") or shutil.which("age")
KEYGEN = os.environ.get("CMDMESH_AGE_KEYGEN") or shutil.which("age-keygen")


def process_state(path):
    try:
        return path.read_text().rpartition(") ")[2].split()[0]
    except FileNotFoundError:
        return None


@unittest.skipUnless(
    AGE and KEYGEN, "provide standard age and age-keygen for real crypto tests"
)
class StreamTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".generated"
        scratch.mkdir(mode=0o700, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="stream-", dir=scratch)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key = self.root / "identity.agekey"
        result = subprocess.run(
            [KEYGEN, "-o", str(self.key)], capture_output=True, timeout=10, umask=0o077
        )
        self.assertEqual(result.returncode, 0)
        result = subprocess.run(
            [KEYGEN, "-y", str(self.key)], capture_output=True, timeout=10
        )
        self.assertEqual(result.returncode, 0)
        self.recipient = result.stdout.decode().strip()
        self.snapshot = "tank/example/data@cmdmesh-" + "a" * 64
        self.output = self.root / "data.zfs.age"
        self.fd = os.open(self.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.addCleanup(os.close, self.fd)
        self.journal = self.root / "armed.json"
        self.journal_fd = os.open(
            self.journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        self.addCleanup(os.close, self.journal_fd)

    def tools(self, body):
        producer = self.root / "zfs"
        producer.write_text("#!" + sys.executable + "\nimport os,sys,time\n" + body)
        producer.chmod(0o700)
        self.producer = producer
        return {
            role: {"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
            for role, p in (("zfs", producer), ("age", Path(AGE)))
        }

    def test_manifest_roundtrip_uses_sealed_fd_and_no_producer(self):
        raw = b'{"document_type":"synthetic-manifest","value":"not-in-journal"}'
        tools = {
            "age": {
                "path": str(Path(AGE).resolve()),
                "sha256": hashlib.sha256(Path(AGE).read_bytes()).hexdigest(),
            }
        }
        result = stream.encrypt_manifest(
            raw, self.recipient, self.fd, tools, journal_fd=self.journal_fd
        )
        self.assertEqual(result["source_kind"], "manifest")
        self.assertIsNone(result["producer_exit_code"])
        self.assertEqual(result["encryptor_exit_code"], 0)
        self.assertTrue(result["file_fsynced"] and result["group_stopped"])
        self.assertEqual(
            result["ciphertext_sha256"],
            hashlib.sha256(self.output.read_bytes()).hexdigest(),
        )
        actual = subprocess.run(
            [AGE, "--decrypt", "--identity", str(self.key), str(self.output)],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(actual.returncode, 0)
        self.assertEqual(actual.stdout, raw)
        armed = json.loads(self.journal.read_bytes())
        self.assertEqual(
            armed["parameters"]["input_sha256"], hashlib.sha256(raw).hexdigest()
        )
        self.assertEqual(armed["parameters"]["input_bytes"], len(raw))
        self.assertNotIn(b"not-in-journal", self.journal.read_bytes())
        self.assertEqual(
            sorted(p.name for p in self.root.iterdir()),
            ["armed.json", "data.zfs.age", "identity.agekey"],
        )

    def test_manifest_input_is_sealed_before_dispatch(self):
        import fcntl

        raw = b'{"manifest":"unchanged"}'
        tools = {
            "age": {
                "path": str(Path(AGE).resolve()),
                "sha256": hashlib.sha256(Path(AGE).read_bytes()).hexdigest(),
            }
        }
        original = os.fsync
        observed = []

        def inspect_seals(fd):
            if fd == self.journal_fd:
                armed = json.loads(self.journal.read_bytes())
                input_fd = armed["parameters"]["input_fd"]
                with self.assertRaises(OSError):
                    os.pwrite(input_fd, b"changed", 0)
                observed.append(fcntl.fcntl(input_fd, fcntl.F_GET_SEALS))
            return original(fd)

        with mock.patch.object(stream.os, "fsync", side_effect=inspect_seals):
            stream.encrypt_manifest(
                raw, self.recipient, self.fd, tools, journal_fd=self.journal_fd
            )
        self.assertEqual(len(observed), 1)
        self.assertEqual(
            observed[0],
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL,
        )

    def test_invalid_manifest_bytes_refuse_before_any_tool_dispatch(self):
        tools = {
            "age": {
                "path": str(Path(AGE).resolve()),
                "sha256": hashlib.sha256(Path(AGE).read_bytes()).hexdigest(),
            }
        }
        for raw in (None, "not bytes", b"", b"x" * 1048577):
            with self.subTest(kind=type(raw).__name__), self.assertRaises(
                stream.StreamError
            ):
                stream.encrypt_manifest(
                    raw, self.recipient, self.fd, tools, journal_fd=self.journal_fd
                )
        self.assertEqual(self.output.stat().st_size, 0)
        self.assertEqual(self.journal.stat().st_size, 0)

    def test_manifest_encryptor_failure_cannot_be_success(self):
        tools = self.tools("sys.exit(0)")
        # Valid syntax with an invalid bech32 checksum: standard age rejects it.
        with self.assertRaises(stream.StreamError) as failed:
            stream.encrypt_manifest(
                b'{"manifest":"test"}',
                "age1" + "q" * 58,
                self.fd,
                {"age": tools["age"]},
                journal_fd=self.journal_fd,
            )
        self.assertEqual(failed.exception.command_outcome, "failed")
        self.assertTrue(failed.exception.group_stopped)
        self.assertIsNone(failed.exception.producer_exit_code)
        self.assertNotEqual(failed.exception.encryptor_exit_code, 0)

    def test_manifest_cannot_report_a_subprocess_exit_that_never_existed(self):
        tools = self.tools("sys.exit(0)")
        worker = "import json;print(json.dumps({'producer_exit_code':0,'encryptor_exit_code':0,'file_fsynced':True,'ciphertext_bytes':1,'ciphertext_sha256':'a'*64}))"
        with mock.patch.object(stream, "WORKER", worker), self.assertRaises(
            stream.StreamError
        ) as failed:
            stream.encrypt_manifest(
                b"{}",
                self.recipient,
                self.fd,
                {"age": tools["age"]},
                journal_fd=self.journal_fd,
            )
        self.assertEqual(failed.exception.code, "persistence-stream-result-invalid")
        self.assertTrue(failed.exception.group_stopped)

    def test_unsealed_manifest_is_rejected_by_the_worker(self):
        import fcntl

        tools = self.tools("sys.exit(0)")
        original = fcntl.fcntl

        def omit_seals(fd, command, *args):
            return 0 if command == fcntl.F_ADD_SEALS else original(fd, command, *args)

        with mock.patch.object(
            stream.fcntl, "fcntl", side_effect=omit_seals
        ), self.assertRaises(stream.StreamError) as failed:
            stream.encrypt_manifest(
                b"{}",
                self.recipient,
                self.fd,
                {"age": tools["age"]},
                journal_fd=self.journal_fd,
            )
        self.assertTrue(failed.exception.group_stopped)
        self.assertEqual(self.output.stat().st_size, 0)

    def test_worker_checks_the_sealed_input_hash(self):
        tools = self.tools("sys.exit(0)")
        original = stream._encrypt

        def changed(source, *args, **kwargs):
            return original(dict(source, input_sha256="0" * 64), *args, **kwargs)

        with mock.patch.object(
            stream, "_encrypt", side_effect=changed
        ), self.assertRaises(stream.StreamError) as failed:
            stream.encrypt_manifest(
                b"{}",
                self.recipient,
                self.fd,
                {"age": tools["age"]},
                journal_fd=self.journal_fd,
            )
        self.assertTrue(failed.exception.group_stopped)
        self.assertEqual(self.output.stat().st_size, 0)

    def test_manifest_ciphertext_limit_is_enforced(self):
        tools = self.tools("sys.exit(0)")
        with self.assertRaises(stream.StreamError) as failed:
            stream.encrypt_manifest(
                b"x" * 8192,
                self.recipient,
                self.fd,
                {"age": tools["age"]},
                journal_fd=self.journal_fd,
                max_ciphertext_bytes=1024,
            )
        self.assertTrue(failed.exception.group_stopped)
        self.assertLessEqual(self.output.stat().st_size, 1024)

    def run_stream(self, tools, **kwargs):
        return stream.encrypt_snapshot(
            self.snapshot,
            self.recipient,
            self.fd,
            tools,
            journal_fd=self.journal_fd,
            timeout_seconds=kwargs.get("timeout_seconds", 5),
            max_ciphertext_bytes=kwargs.get("max_ciphertext_bytes", 1048576),
        )

    def test_success_decrypts_exact_producer_bytes_and_fsyncs(self):
        expected = b"\x00reference full ZFS stream fixture\xff\n"
        result = self.run_stream(
            self.tools("sys.stdout.buffer.write(" + repr(expected) + ")\n")
        )
        self.assertEqual(result["command_outcome"], "succeeded")
        self.assertTrue(result["file_fsynced"] and result["group_stopped"])
        self.assertEqual(result["producer_exit_code"], 0)
        self.assertEqual(result["encryptor_exit_code"], 0)
        self.assertEqual(
            result["ciphertext_sha256"],
            hashlib.sha256(self.output.read_bytes()).hexdigest(),
        )
        decoded = subprocess.run(
            [AGE, "--decrypt", "--identity", str(self.key), str(self.output)],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(decoded.returncode, 0)
        self.assertEqual(decoded.stdout, expected)

    def test_failed_sender_is_not_hidden_by_successful_age(self):
        with self.assertRaises(stream.StreamError) as failed:
            self.run_stream(
                self.tools(
                    "sys.stdout.buffer.write(b'partial stream');sys.stdout.flush();sys.exit(23)\n"
                )
            )
        self.assertEqual(failed.exception.command_outcome, "failed")
        self.assertEqual(failed.exception.producer_exit_code, 23)
        self.assertEqual(failed.exception.encryptor_exit_code, 0)
        self.assertTrue(failed.exception.group_stopped)
        self.assertGreater(self.output.stat().st_size, 0)

    def test_standard_age_rejects_bad_recipient_checksum(self):
        self.recipient = "age1" + "q" * 58
        with self.assertRaises(stream.StreamError):
            self.run_stream(self.tools("sys.stdout.buffer.write(b'data')\n"))

    def test_file_limit_preserves_partial_ciphertext_without_success(self):
        with self.assertRaises(stream.StreamError):
            self.run_stream(
                self.tools("sys.stdout.buffer.write(b'x'*2097152)\n"),
                max_ciphertext_bytes=1024,
            )
        self.assertLessEqual(self.output.stat().st_size, 1024)
        self.assertTrue(self.output.exists())

    def test_timeout_stops_the_owned_group_including_forked_child(self):
        marker = self.root / "pids"
        body = (
            "child=os.fork()\nif child==0:\n time.sleep(60)\nelse:\n open("
            + repr(str(marker))
            + ",'w').write(str(os.getpid())+' '+str(child))\n time.sleep(60)\n"
        )
        started = time.monotonic()
        with self.assertRaises(stream.StreamError) as failed:
            self.run_stream(self.tools(body), timeout_seconds=0.5)
        self.assertLess(time.monotonic() - started, 8)
        self.assertTrue(failed.exception.group_stopped)
        for pid in marker.read_text().split():
            status = Path("/proc") / pid / "stat"
            if status.exists():
                self.assertEqual(status.read_text().rpartition(") ")[2].split()[0], "Z")

    def test_changed_tool_refuses_before_dispatch(self):
        tools = self.tools("sys.stdout.buffer.write(b'data')\n")
        self.producer.write_text("changed executable\n")
        with self.assertRaises(stream.StreamError) as failed:
            self.run_stream(tools)
        self.assertEqual(failed.exception.command_outcome, "not-dispatched")
        self.assertEqual(self.output.stat().st_size, 0)

    def test_nonzero_initial_offset_refuses_before_worker_or_journal_write(self):
        os.lseek(self.fd, 1, os.SEEK_SET)
        with self.assertRaises(stream.StreamError) as failed:
            self.run_stream(self.tools("sys.stdout.buffer.write(b'data')\n"))
        self.assertEqual(failed.exception.command_outcome, "not-dispatched")
        self.assertEqual(self.journal.stat().st_size, 0)

    def test_stderr_flood_is_bounded_and_stops_group(self):
        with self.assertRaises(stream.StreamError) as failed:
            self.run_stream(
                self.tools(
                    "sys.stderr.buffer.write(b'x'*1048576);sys.stderr.flush();time.sleep(60)\n"
                )
            )
        self.assertEqual(failed.exception.code, "persistence-stream-diagnostic-limit")
        self.assertTrue(failed.exception.group_stopped)

    def test_consumer_failure_with_sleeping_producer_cannot_hang(self):
        self.recipient = "age1" + "q" * 58
        start = time.monotonic()
        with self.assertRaises(stream.StreamError) as failed:
            self.run_stream(self.tools("time.sleep(60)\n"), timeout_seconds=0.3)
        self.assertLess(time.monotonic() - start, 8)
        self.assertTrue(failed.exception.group_stopped)

    def test_worker_exit_without_result_never_reports_success(self):
        tools = self.tools("sys.stdout.buffer.write(b'data')\n")
        with mock.patch.object(
            stream, "WORKER", "import os;os._exit(0)"
        ), self.assertRaises(stream.StreamError) as failed:
            self.run_stream(tools)
        self.assertTrue(failed.exception.group_stopped)
        self.assertEqual(self.output.stat().st_size, 0)

    def test_deep_worker_frame_is_a_typed_uncertain_failure(self):
        tools = self.tools("sys.stdout.buffer.write(b'data')\n")
        worker = "import json,os,sys\np=json.loads(sys.argv[1]);os.read(p['gate'],4)\nos.write(1,b'['*1500+b'0'+b']'*1500)\n"
        with mock.patch.object(stream, "WORKER", worker), self.assertRaises(
            stream.StreamError
        ) as failed:
            self.run_stream(tools)
        self.assertEqual(failed.exception.code, "persistence-stream-result-invalid")
        self.assertEqual(failed.exception.command_outcome, "unknown")
        self.assertTrue(failed.exception.group_stopped)

    def test_failed_arming_fsync_cannot_release_tools(self):
        marker = self.root / "producer-ran"
        tools = self.tools("open(" + repr(str(marker)) + ",'w').write('ran')\n")
        with mock.patch.object(
            stream.os, "fsync", side_effect=OSError("journal unavailable")
        ), self.assertRaises(stream.StreamError) as failed:
            self.run_stream(tools)
        self.assertEqual(failed.exception.command_outcome, "not-dispatched")
        self.assertTrue(failed.exception.group_stopped)
        self.assertFalse(marker.exists())
        self.assertEqual(self.output.stat().st_size, 0)

    def test_arming_is_durable_before_the_producer_starts(self):
        marker = self.root / "journal-synced"
        tools = self.tools(
            "import json\nr=json.loads(open("
            + repr(str(self.journal))
            + ").read())\nassert r['worker_pid']==os.getppid()\nassert os.path.exists("
            + repr(str(marker))
            + ")\nsys.stdout.buffer.write(b'full stream')\n"
        )
        original = os.fsync

        def recorded(fd):
            original(fd)
            if fd == self.journal_fd:
                marker.write_text("fsync returned")

        with mock.patch.object(stream.os, "fsync", side_effect=recorded):
            result = self.run_stream(tools)
        armed = json.loads(self.journal.read_bytes())
        self.assertEqual(armed["schema_version"], 1)
        self.assertEqual(
            armed["parameters_sha256"],
            hashlib.sha256(
                json.dumps(
                    armed["parameters"], sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest(),
        )
        self.assertEqual(result["worker_pid"], armed["worker_pid"])

    def test_partial_os_writes_keep_produced_digest_and_bytes_exact(self):
        prefix = "import os\nreal=os.write\nos.write=lambda fd,raw:real(fd,raw[:7])\n"
        tools = self.tools("sys.stdout.buffer.write(b'full stream'*100)\n")
        with mock.patch.object(stream, "WORKER", prefix + stream.WORKER):
            result = self.run_stream(tools)
        self.assertEqual(result["ciphertext_bytes"], self.output.stat().st_size)
        self.assertEqual(
            result["ciphertext_sha256"],
            hashlib.sha256(self.output.read_bytes()).hexdigest(),
        )

    def test_closed_pipes_do_not_hide_a_live_descendant(self):
        marker = self.root / "descendant"
        body = (
            "child=os.fork()\nif child==0:\n os.close(0);os.close(1);os.close(2)\n time.sleep(60)\nelse:\n open("
            + repr(str(marker))
            + ",'w').write(str(child))\n sys.stdout.buffer.write(b'complete fixture')\n"
        )
        with self.assertRaises(stream.StreamError) as failed:
            self.run_stream(self.tools(body))
        self.assertEqual(failed.exception.code, "persistence-stream-group-not-closed")
        self.assertTrue(failed.exception.group_stopped)
        path = Path("/proc") / marker.read_text() / "stat"
        self.assertIn(process_state(path), (None, "Z"))

    def test_parent_death_after_arming_cannot_launch_the_producer(self):
        marker = self.root / "producer-ran"
        tools = self.tools("open(" + repr(str(marker)) + ",'w').write('ran')\n")
        driver = "import json,os,sys\nsys.path.insert(0,sys.argv[1])\nimport persistence_stream as s\np=json.loads(sys.argv[2]);real=os.fsync\ndef die(fd):\n real(fd)\n if fd==p['journal']:os._exit(73)\ns.os.fsync=die\ns.encrypt_snapshot(p['snapshot'],p['recipient'],p['output'],p['tools'],journal_fd=p['journal'])\n"
        params = {
            "snapshot": self.snapshot,
            "recipient": self.recipient,
            "output": self.fd,
            "journal": self.journal_fd,
            "tools": tools,
        }
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-c",
                driver,
                str(
                    ROOT
                    / "ansible/ansible_collections/cmdmesh/proxmox/plugins/module_utils"
                ),
                json.dumps(params),
            ],
            pass_fds=(self.fd, self.journal_fd),
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 73)
        armed = json.loads(self.journal.read_bytes())
        path = Path("/proc") / str(armed["worker_pid"]) / "stat"
        end = time.monotonic() + 3
        while process_state(path) not in (None, "Z") and time.monotonic() < end:
            time.sleep(0.02)
        self.assertIn(process_state(path), (None, "Z"))
        self.assertFalse(marker.exists())
        self.assertEqual(self.output.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
