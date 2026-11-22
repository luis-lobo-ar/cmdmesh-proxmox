"""Fixed controller/access probes. Explicit trusted tools, no repair actions."""

import ipaddress
import hashlib
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import subprocess
import tempfile
import time

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
VERSIONS = {
    "ansible-playbook": ("--version", r"ansible-playbook \[core (\d+)\.(\d+)\.(\d+)\]"),
    "python3": ("--version", r"Python (\d+)\.(\d+)\.(\d+)"),
    "terraform": ("version", r"Terraform v(\d+)\.(\d+)\.(\d+)"),
    "ssh": ("-V", r"OpenSSH_(\d+)\.(\d+)(?:p(\d+))?(?:[ ,].*)?"),
}
GUIDANCE = {
    "tls-name-mismatch": (
        "The certificate does not match the configured server name",
        "Check tls.server_name against the intended certificate SAN",
        "Correct the intended endpoint or certificate separately; never disable hostname verification",
    ),
    "tls-chain-unverified": (
        "The certificate chain or validity could not be verified",
        "Check the trusted CA, chain and certificate validity",
        "Recover trust over an established channel; never trust an unverified fetched certificate",
    ),
    "tls-trust-unavailable": (
        "The configured CA trust cannot be loaded",
        "Check the explicit CA path, permissions and regular ASCII PEM data",
        "Restore the intended trust input separately; do not fall back to system trust for an invalid explicit CA",
    ),
    "tls-handshake-failed": (
        "The verified TLS handshake failed",
        "Check the selected port, protocol and server TLS configuration",
        "Repair the intended service separately; no insecure retry was attempted",
    ),
    "controller-tool-unavailable": (
        "An explicitly selected tool cannot run",
        "Check the private controller.tools executable path and permissions",
        "Install or select a qualified tool separately; diagnosis does not install software",
    ),
    "controller-version-unsupported": (
        "A tool version is unknown or outside the requested range",
        "Check describe and the requested minimum/maximum_exclusive version",
        "Select a tested tool version; do not treat exit zero as compatibility evidence",
    ),
    "controller-scratch-invalid": (
        "Controller scratch is not an existing private owned directory",
        "Check controller.scratch_root ownership, mode and symlink-free path",
        "Create an owner-only project directory separately; do not substitute system temporary storage",
    ),
    "controller-space-insufficient": (
        "Controller scratch has insufficient available space",
        "Check available space and the explicit minimum_free_bytes",
        "Free or select storage separately; diagnosis does not remove files",
    ),
    "controller-socket-unavailable": (
        "The selected scratch cannot host the required Unix socket",
        "Check Unix socket support and absolute path length",
        "Select a suitable private project scratch path; do not disable access verification",
    ),
    "probe-output-limit": (
        "A fixed probe exceeded its output limit",
        "Check the selected tool identity and version behavior",
        "Investigate the tool separately; raw output remains withheld",
    ),
    "probe-output-invalid": (
        "The evidence transport returned invalid UTF-8",
        "Check the selected collector and transport encoding",
        "Recollect valid evidence; corrupted bytes are never replaced or accepted as observations",
    ),
    "probe-deadline": (
        "A fixed probe exceeded its deadline",
        "Check local tool startup or remote connectivity",
        "Reconcile the observation before retrying; no repair was attempted",
    ),
    "origin-mismatch": (
        "The requested origin differs from the private configured origin",
        "Compare input.origin with config.origin",
        "Correct the explicit origin before probing",
    ),
    "dns-unavailable": (
        "The configured host could not be resolved",
        "Check the explicit hostname and controller resolver",
        "Repair DNS separately; do not substitute a remembered address",
    ),
    "tcp-unavailable": (
        "The configured TCP endpoint could not be reached",
        "Check the explicit host, port, route and firewall",
        "Repair connectivity separately; do not create broad ingress exceptions",
    ),
    "ssh-host-key-unverified": (
        "SSH could not verify the selected host key",
        "Check the explicit known_hosts entry and independently confirmed server key",
        "Recover trust over an established channel; never disable strict checking",
    ),
    "ssh-authentication-failed": (
        "SSH authentication failed with the selected identity",
        "Check ssh.user and identity_file permissions and authorization",
        "Repair the intended identity separately; do not fall back to agent keys or passwords",
    ),
    "ssh-identity-mismatch": (
        "The remote UID differs from the requested identity",
        "Check expected_uid and the explicitly selected SSH user",
        "Correct the identity before any dependent operation",
    ),
    "ssh-invalid-identity-evidence": (
        "The fixed UID probe returned invalid evidence",
        "Check the configured executable and remote login behavior",
        "Investigate without accepting raw output as identity proof",
    ),
    "ssh-probe-failed": (
        "The fixed SSH probe failed",
        "Check connectivity, host-key trust and explicit identity",
        "Investigate the bounded failure separately; no fallback or repair occurred",
    ),
}


class ProbeError(Exception):
    def __init__(self, code, outcome="rejected"):
        self.code, self.outcome = code, outcome


def keys(value, required, optional=()):
    if (
        not isinstance(value, dict)
        or not required <= value.keys()
        or value.keys() - required - set(optional)
    ):
        raise ProbeError("invalid-probe-configuration")


def integer(value, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise ProbeError("invalid-probe-configuration")


def identifier(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ProbeError("invalid-probe-configuration")


def regular(value, executable=False):
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ProbeError("invalid-probe-configuration")
    path = Path(value)
    try:
        metadata = path.stat()
    except OSError:
        raise ProbeError(
            (
                "controller-tool-unavailable"
                if executable
                else "invalid-probe-configuration"
            ),
            "unavailable",
        ) from None
    if not stat.S_ISREG(metadata.st_mode) or (
        executable and not os.access(path, os.X_OK)
    ):
        raise ProbeError(
            (
                "controller-tool-unavailable"
                if executable
                else "invalid-probe-configuration"
            ),
            "unavailable",
        )
    return path


def ssh_file(value):
    path = regular(value)
    if any(c.isspace() or c in "\"'\\%$~" for c in str(path)):
        raise ProbeError("invalid-probe-configuration")
    return path


def scratch(config):
    controller = config.get("controller")
    keys(controller, {"scratch_root"}, {"tools"})
    value = controller["scratch_root"]
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ProbeError("controller-scratch-invalid")
    path = Path(value)
    try:
        metadata = path.stat()
        if (
            path.resolve() != path
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
        ):
            raise ProbeError("controller-scratch-invalid")
    except OSError:
        raise ProbeError("controller-scratch-invalid") from None
    return path


def bounded_probe(program, args, work, *, timeout_seconds=3, strict_output=False):
    marker = os.environ.get("CMDMESH_INSPECTION_PROCESS_GROUP")
    if marker is not None and (marker != "1" or os.getpgrp() != os.getpid()):
        raise ProbeError("invalid-supervision-context")
    supervised = marker == "1"
    config_path = work / "ansible.cfg"
    config_path.write_text(
        "[defaults]\ngathering = explicit\nretry_files_enabled = False\n"
    )
    config_path.chmod(0o600)
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "TERM": "dumb",
        "TMPDIR": str(work),
        "ANSIBLE_CONFIG": str(config_path),
        "ANSIBLE_HOME": str(work / "ansible"),
        "ANSIBLE_LOCAL_TEMP": str(work / "ansible-local"),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        process = subprocess.Popen(
            [str(program), *args],
            cwd=work,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=not supervised,
        )
    except OSError:
        raise ProbeError("controller-tool-unavailable", "unavailable") from None
    output, error = bytearray(), bytearray()
    started = time.monotonic()
    try:
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        while True:
            for stream, target in ((process.stdout, output), (process.stderr, error)):
                try:
                    data = os.read(stream.fileno(), 8192)
                except BlockingIOError:
                    data = b""
                target.extend(data)
                if len(output) + len(error) > 65536:
                    raise ProbeError("probe-output-limit", "unavailable")
            status = process.poll()
            if status is not None:
                # Drain bounded buffered bytes without waiting for inherited EOF.
                for stream, target in (
                    (process.stdout, output),
                    (process.stderr, error),
                ):
                    while True:
                        try:
                            data = os.read(stream.fileno(), 8192)
                        except BlockingIOError:
                            break
                        if not data:
                            break
                        target.extend(data)
                        if len(output) + len(error) > 65536:
                            raise ProbeError("probe-output-limit", "unavailable")
                try:
                    decoded = output.decode(
                        "utf-8", "strict" if strict_output else "replace"
                    )
                except UnicodeError:
                    raise ProbeError("probe-output-invalid", "incomplete") from None
                return (
                    status,
                    decoded,
                    error.decode("utf-8", "replace"),
                )
            if time.monotonic() - started >= timeout_seconds:
                raise ProbeError("probe-deadline", "unavailable")
            time.sleep(0.01)
    finally:
        try:
            if supervised:
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()
        process.stderr.close()


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+\.\d+", value):
        raise ProbeError("invalid-probe-configuration")
    return tuple(map(int, value.split(".")))


def controller(value, config):
    keys(value, {"required_tools", "minimum_free_bytes"}, {"require_unix_socket"})
    tools = value["required_tools"]
    if not isinstance(tools, dict) or not tools or tools.keys() - VERSIONS.keys():
        raise ProbeError("invalid-probe-configuration")
    integer(value["minimum_free_bytes"], 0, 2**63 - 1)
    if type(value.get("require_unix_socket", False)) is not bool:
        raise ProbeError("invalid-probe-configuration")
    root = scratch(config)
    configured = config["controller"].get("tools", {})
    if not isinstance(configured, dict) or configured.keys() - VERSIONS.keys():
        raise ProbeError("invalid-probe-configuration")
    selected = {}
    for name, constraint in tools.items():
        keys(constraint, {"minimum", "maximum_exclusive"})
        low, high = version(constraint["minimum"]), version(
            constraint["maximum_exclusive"]
        )
        if low >= high:
            raise ProbeError("invalid-probe-configuration")
        selected[name] = (regular(configured.get(name), executable=True), low, high)
    space = os.statvfs(root)
    available = space.f_bavail * space.f_frsize
    if available < value["minimum_free_bytes"]:
        raise ProbeError("controller-space-insufficient", "unavailable")
    with tempfile.TemporaryDirectory(prefix="probe-", dir=root) as directory:
        work = Path(directory)
        socket_available = False
        with socket.socket(socket.AF_UNIX) as unix:
            try:
                unix.bind(str(work / "socket"))
                socket_available = True
            except OSError:
                pass
        if value.get("require_unix_socket", False) and not socket_available:
            raise ProbeError("controller-socket-unavailable", "unavailable")
        results = {}
        for name, (executable, low, high) in selected.items():
            argument, pattern = VERSIONS[name]
            status, output, error = bounded_probe(executable, [argument], work)
            text = (error if name == "ssh" else output).splitlines()
            match = re.fullmatch(pattern, text[0]) if text else None
            if status != 0 or not match:
                raise ProbeError("controller-version-unsupported", "unsupported")
            found = tuple(int(part or 0) for part in match.groups())
            if not low <= found < high:
                raise ProbeError("controller-version-unsupported", "unsupported")
            results[name] = {
                "version": ".".join(map(str, found)),
                "requirement_met": True,
            }
    return {
        "tools": results,
        "available_bytes": available,
        "unix_socket_available": socket_available,
        "remote_access_tested": False,
        "mutation_authorized": False,
        "qualification": "requested-version-ranges-only",
    }


def endpoint(config):
    host = config["host"]
    if not isinstance(host, str) or len(host) > 253:
        raise ProbeError("invalid-probe-configuration")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not all(NAME.fullmatch(part) for part in host.split(".")):
            raise ProbeError("invalid-probe-configuration")
    integer(config["port"], 1, 65535)
    try:
        return socket.create_connection((host, config["port"]), timeout=2)
    except socket.gaierror:
        raise ProbeError("dns-unavailable", "unavailable") from None
    except OSError:
        raise ProbeError("tcp-unavailable", "unavailable") from None


def ssh_command(config, command, *, timeout_seconds=3, strict_output=False):
    """Internal fixed callers only: public input never supplies a command."""
    settings = config.get("ssh")
    keys(
        settings,
        {"executable", "host", "port", "user", "identity_file", "known_hosts_file"},
    )
    identifier(settings["user"])
    root = scratch(config)
    executable = regular(settings["executable"], executable=True)
    identity = ssh_file(settings["identity_file"])
    known_hosts = ssh_file(settings["known_hosts_file"])
    with endpoint(settings):
        pass
    options = [
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "CertificateFile=none",
        "PreferredAuthentications=publickey",
        "ForwardAgent=no",
        "ControlMaster=no",
        "ControlPath=none",
        "ControlPersist=no",
        "GlobalKnownHostsFile=/dev/null",
        f"UserKnownHostsFile={known_hosts}",
        "UpdateHostKeys=no",
        "ProxyCommand=none",
        "ProxyJump=none",
        "ClearAllForwardings=yes",
        "RequestTTY=no",
        "NumberOfPasswordPrompts=0",
        "ConnectionAttempts=1",
        "ConnectTimeout=2",
        "LogLevel=ERROR",
    ]
    args = ["-F", "none", "-i", str(identity), "-p", str(settings["port"])]
    for option in options:
        args.extend(["-o", option])
    args.extend(["-l", settings["user"], "--", settings["host"], command])
    with tempfile.TemporaryDirectory(prefix="probe-", dir=root) as directory:
        status, output, error = bounded_probe(
            executable,
            args,
            Path(directory),
            timeout_seconds=timeout_seconds,
            strict_output=strict_output,
        )
    if status != 0:
        if (
            "Host key verification failed" in error
            or "REMOTE HOST IDENTIFICATION HAS CHANGED" in error
        ):
            raise ProbeError("ssh-host-key-unverified", "unavailable")
        if "Permission denied" in error:
            raise ProbeError("ssh-authentication-failed", "unavailable")
    return status, output


def ssh(value, config):
    keys(value, {"origin", "expected_uid"})
    identifier(value["origin"])
    if config.get("origin") != value["origin"]:
        raise ProbeError("origin-mismatch")
    integer(value["expected_uid"], 0, 2**32 - 1)
    status, output = ssh_command(config, "id -u")
    if status != 0:
        raise ProbeError("ssh-probe-failed", "unavailable")
    if not re.fullmatch(r"[0-9]{1,10}\n?", output):
        raise ProbeError("ssh-invalid-identity-evidence", "incomplete")
    uid = int(output)
    if uid != value["expected_uid"]:
        raise ProbeError("ssh-identity-mismatch")
    return {
        "uid": uid,
        "origin": value["origin"],
        "host_key_checking": "strict",
        "application_health_tested": False,
        "mutation_authorized": False,
    }


def tls_settings(settings):
    keys(settings, {"host", "port", "server_name"}, {"ca_file"})
    server_name = settings["server_name"]
    if (
        not isinstance(server_name, str)
        or not server_name
        or len(server_name) > 253
        or "%" in server_name
    ):
        raise ProbeError("invalid-probe-configuration")
    try:
        ipaddress.ip_address(server_name)
    except ValueError:
        if not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in server_name.split(".")
        ):
            raise ProbeError("invalid-probe-configuration") from None
    return server_name


def tls_handshake(settings, context, trust):
    server_name = tls_settings(settings)
    try:
        with endpoint(settings) as connection:
            with context.wrap_socket(
                connection, server_hostname=server_name
            ) as secured:
                digest = hashlib.sha256(
                    secured.getpeercert(binary_form=True)
                ).hexdigest()
                protocol = secured.version()
    except ssl.SSLCertVerificationError as error:
        code = (
            "tls-name-mismatch"
            if error.verify_code in (62, 64)
            else "tls-chain-unverified"
        )
        raise ProbeError(code, "unavailable") from None
    except (OSError, ssl.SSLError):
        raise ProbeError("tls-handshake-failed", "unavailable") from None
    return {
        "certificate_verified": True,
        "trust": trust,
        "peer_certificate_sha256": digest,
        "protocol": protocol,
    }


def tls(value, config):
    import inventory

    keys(value, {"origin"})
    identifier(value["origin"])
    if config.get("origin") != value["origin"]:
        raise ProbeError("origin-mismatch")
    settings = config.get("tls")
    tls_settings(settings)
    try:
        context, trust = inventory.prepare_trust(settings)
    except inventory.InventoryError as error:
        if str(error) == "ca_file must name a nonempty regular file":
            raise ProbeError("invalid-probe-configuration") from None
        raise ProbeError("tls-trust-unavailable", "unavailable") from None
    return {
        **tls_handshake(settings, context, trust),
        "origin": value["origin"],
        "api_permission_tested": False,
        "mutation_authorized": False,
    }


def run(action, value, config):
    try:
        data = {
            "controller-diagnose": controller,
            "ssh-diagnose": ssh,
            "tls-diagnose": tls,
        }[action](value, config)
        return {"outcome": "observed", "data": data, "diagnostics": []}
    except ProbeError as error:
        code, outcome = error.code, error.outcome
    except (OSError, ValueError, TypeError):
        code, outcome = "invalid-probe-configuration", "rejected"
    summary, check, recovery = GUIDANCE.get(
        code,
        (
            "Probe input or private configuration is invalid",
            "Use describe and check the explicit private configuration fields",
            "Correct the input; do not substitute ambient configuration or execute a repair",
        ),
    )
    return {
        "outcome": outcome,
        "data": {},
        "diagnostics": [
            {
                "code": code,
                "summary": summary,
                "next_checks": [check],
                "recovery": [recovery],
            }
        ],
    }


def descriptions():
    def obj(properties, required):
        return {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        }

    constraint = obj(
        {
            key: {"type": "string", "pattern": r"^\d+\.\d+\.\d+$"}
            for key in ("minimum", "maximum_exclusive")
        },
        ["minimum", "maximum_exclusive"],
    )
    return [
        {
            "id": "controller-diagnose",
            "aliases": ["check controller tools", "diagnose local scratch"],
            "input_schema": obj(
                {
                    "required_tools": {
                        **obj({key: constraint for key in VERSIONS}, []),
                        "minProperties": 1,
                    },
                    "minimum_free_bytes": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 2**63 - 1,
                    },
                    "require_unix_socket": {"type": "boolean", "default": False},
                },
                ["required_tools", "minimum_free_bytes"],
            ),
            "required_configuration": "controller.scratch_root and explicit controller.tools absolute executable paths",
            "expected_result": "Fixed tool versions meet supplied ranges; scratch prerequisites observed, not remote compatibility certified",
            "known_failures": [
                key
                for key in GUIDANCE
                if key.startswith("controller-") or key.startswith("probe-")
            ],
            "recovery": "Select or repair tools and scratch separately; no auto install or removal",
        },
        {
            "id": "ssh-diagnose",
            "aliases": ["check explicit SSH access", "check remote uid"],
            "input_schema": obj(
                {
                    "origin": {"type": "string", "pattern": NAME.pattern},
                    "expected_uid": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 2**32 - 1,
                    },
                },
                ["origin", "expected_uid"],
            ),
            "required_configuration": "origin, controller.scratch_root, ssh.executable/host/port/user/identity_file/known_hosts_file",
            "expected_result": "DNS/TCP and strict explicit SSH access return the expected UID; no application health claim",
            "known_failures": [
                key
                for key in GUIDANCE
                if key.startswith("ssh-")
                or key in ("origin-mismatch", "dns-unavailable", "tcp-unavailable")
            ],
            "recovery": "Recover the intended key or connectivity separately; no SSH config, agent, multiplexing, password or insecure fallback",
        },
        {
            "id": "tls-diagnose",
            "aliases": ["check certificate trust and name", "diagnose TLS access"],
            "input_schema": obj(
                {"origin": {"type": "string", "pattern": NAME.pattern}}, ["origin"]
            ),
            "required_configuration": "origin and tls.host/port/server_name with optional explicit tls.ca_file",
            "expected_result": "Verified TLS handshake with exact server name and captured CA receipt; no HTTP request or API credentials",
            "known_failures": [
                key
                for key in GUIDANCE
                if key.startswith("tls-")
                or key in ("origin-mismatch", "dns-unavailable", "tcp-unavailable")
            ],
            "recovery": "Repair trust, certificate identity or connectivity separately; no insecure fallback",
        },
    ]
