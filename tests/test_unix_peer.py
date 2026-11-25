"""Authenticate a local process before disclosing an application credential."""

from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import unix_peer

SERVER = r"""
import json,os,pathlib,signal,socket,sys,time
root=pathlib.Path(sys.argv[1]);mode=sys.argv[2]
if mode=='exec':
 def replace_process(*unused):
  os.execv(sys.executable,[sys.executable,'-I','-S','-c',"import time;print('replaced',flush=True);time.sleep(60)"])
 signal.signal(signal.SIGUSR1,replace_process)
directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
with socket.socket(socket.AF_UNIX) as listener:
 listener.bind(f'/proc/self/fd/{directory}/api.sock');os.chmod(root/'api.sock',0o600);listener.listen(1)
 print('ready',flush=True)
 with listener.accept()[0] as channel:
  raw=b''
  while not raw.endswith(b'\n'):
   part=channel.recv(4096)
   if not part:break
   raw+=part
  (root/'received').write_bytes(raw)
  print('received',flush=True)
  if raw:
   if mode=='echo':channel.sendall(b'{"outcome":"read"}\n')
   elif mode=='trailing':channel.sendall(b'{}\n{}\n')
   elif mode=='oversize':channel.sendall(b'x'*4097+b'\n')
   elif mode=='partial':channel.sendall(b'{"incomplete":')
   elif mode=='slow':time.sleep(2)
 while not (root/'release').exists():time.sleep(0.01)
"""


class UnixPeerTests(unittest.TestCase):
    @contextmanager
    def server(self, mode="echo"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            child = subprocess.Popen(
                [sys.executable, "-I", "-S", "-B", "-c", SERVER, str(root), mode],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            descriptor = None
            try:
                line = child.stdout.readline()
                if line != b"ready\n":
                    self.fail(child.communicate(timeout=5)[1].decode())
                binding = unix_peer.process_identity(child.pid)
                descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                yield root, child, descriptor, binding
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                (root / "release").touch()
                if child.poll() is None:
                    child.terminate()
                child.communicate(timeout=5)

    def test_real_peer_and_single_response(self):
        with self.server() as (root, child, descriptor, binding):
            payload = b'{"token":"private-test-credential"}\n'
            result = unix_peer.exchange(
                descriptor, "api.sock", binding, lambda: payload, timeout=2
            )
            self.assertEqual(json.loads(result), {"outcome": "read"})
            self.assertEqual((root / "received").read_bytes(), payload)

    def test_wrong_process_refuses_before_credentials(self):
        for field, value in (
            ("pid", os.getpid()),
            ("birth", 1),
            ("uid", os.getuid() + 1),
            ("gid", os.getgid() + 1),
            ("pid_namespace", 1),
            ("mount_namespace", 1),
            ("root", (1, 1)),
            ("executable", (1, 1)),
            ("nspid", (1,)),
            ("cgroup", "0::/wrong.service\n"),
            ("argv", ("/wrong-program",)),
        ):
            with self.subTest(field=field), self.server() as (
                root,
                child,
                descriptor,
                binding,
            ):
                called = []
                with self.assertRaises(unix_peer.PeerError):
                    unix_peer.exchange(
                        descriptor,
                        "api.sock",
                        replace(binding, **{field: value}),
                        lambda: called.append(True) or b"credential\n",
                        timeout=2,
                    )
                self.assertEqual(called, [])
                # On wrong PID/UID/GID the server can see a connection, never bytes.
                if (root / "received").exists():
                    self.assertEqual((root / "received").read_bytes(), b"")

    def test_symlink_socket_or_public_parent_refuses_without_supplier(self):
        for mutation in ("symlink", "parent", "socket"):
            with self.subTest(mutation=mutation), self.server() as (
                root,
                child,
                descriptor,
                binding,
            ):
                name = "api.sock"
                if mutation == "symlink":
                    (root / "alias.sock").symlink_to("api.sock")
                    name = "alias.sock"
                elif mutation == "parent":
                    root.chmod(0o755)
                else:
                    (root / "api.sock").chmod(0o666)
                called = []
                with self.assertRaises(unix_peer.PeerError):
                    unix_peer.exchange(
                        descriptor, name, binding, lambda: called.append(True)
                    )
                self.assertEqual(called, [])

    def test_connected_peer_credential_mismatch_before_supplier(self):
        with self.server() as (root, child, descriptor, binding):
            called = []
            # This identity is internally current and valid, but not the listener.
            other = unix_peer.process_identity(os.getpid())
            with self.assertRaisesRegex(unix_peer.PeerError, "credentials-mismatch"):
                unix_peer.exchange(
                    descriptor, "api.sock", other, lambda: called.append(True)
                )
            self.assertEqual(called, [])
            self.assertEqual(child.stdout.readline(), b"received\n")
            self.assertEqual((root / "received").read_bytes(), b"")

    def test_process_change_during_supplier_refuses_before_send(self):
        with self.server() as (root, child, descriptor, binding):

            def payload():
                (root / "api.sock").chmod(0o666)
                return b"private-test-credential\n"

            with self.assertRaises(unix_peer.PeerError) as raised:
                unix_peer.exchange(descriptor, "api.sock", binding, payload)
            self.assertNotIn("credential", str(raised.exception))
            self.assertEqual(child.stdout.readline(), b"received\n")
            self.assertEqual((root / "received").read_bytes(), b"")

    def test_response_limits_no_retry(self):
        for mode in ("trailing", "oversize", "partial", "slow"):
            with self.subTest(mode=mode), self.server(mode) as (
                root,
                child,
                descriptor,
                binding,
            ):
                calls = []
                with self.assertRaises(unix_peer.PeerError):
                    unix_peer.exchange(
                        descriptor,
                        "api.sock",
                        binding,
                        lambda: calls.append(True) or b"credential\n",
                        timeout=0.25,
                        response_limit=4096,
                    )
                self.assertEqual(calls, [True])

    def test_real_exec_after_admission_does_not_receive_credential(self):
        with self.server("exec") as (root, child, descriptor, binding):

            def payload():
                child.send_signal(signal.SIGUSR1)
                self.assertEqual(child.stdout.readline(), b"replaced\n")
                return b"private-test-credential\n"

            with self.assertRaises(unix_peer.PeerError):
                unix_peer.exchange(descriptor, "api.sock", binding, payload)
            self.assertFalse((root / "received").exists())

    def test_supplier_errors_are_private_and_send_no_bytes(self):
        for exception in (ValueError, RuntimeError, unix_peer.PeerError):
            with self.subTest(exception=exception), self.server() as (
                root,
                child,
                descriptor,
                binding,
            ):

                def payload():
                    raise exception("private-test-credential")

                with self.assertRaises(unix_peer.PeerError) as raised:
                    unix_peer.exchange(descriptor, "api.sock", binding, payload)
                self.assertNotIn("private-test-credential", str(raised.exception))
                self.assertEqual(child.stdout.readline(), b"received\n")
                self.assertEqual((root / "received").read_bytes(), b"")

    def test_late_closing_process_proof_cannot_return_success(self):
        with self.server() as (root, child, descriptor, binding):
            original = unix_peer._process

            def slow_closing_proof(*args):
                # The actual server's received marker establishes that this
                # delay belongs to the final process proof, not admission.
                if (root / "received").exists():
                    time.sleep(0.15)
                return original(*args)

            with mock.patch.object(
                unix_peer, "_process", side_effect=slow_closing_proof
            ):
                with self.assertRaisesRegex(unix_peer.PeerError, "timeout"):
                    unix_peer.exchange(
                        descriptor,
                        "api.sock",
                        binding,
                        lambda: b"credential\n",
                        timeout=0.05,
                    )

    def test_path_and_binding_validation(self):
        with self.server() as (root, child, descriptor, binding):
            for name in ("../api.sock", "/api.sock", "a/b", "", ".", ".."):
                with self.subTest(name=name), self.assertRaises(unix_peer.PeerError):
                    unix_peer.exchange(descriptor, name, binding, lambda: b"a\n")
            with self.assertRaises(unix_peer.PeerError):
                replace(binding, pid=True)
            with self.assertRaises(unix_peer.PeerError):
                unix_peer.process_identity(2**40)
            with self.assertRaises(unix_peer.PeerError):
                unix_peer.exchange(
                    descriptor, "api.sock", binding, lambda: b"a\n", timeout=True
                )


if __name__ == "__main__":
    unittest.main()
