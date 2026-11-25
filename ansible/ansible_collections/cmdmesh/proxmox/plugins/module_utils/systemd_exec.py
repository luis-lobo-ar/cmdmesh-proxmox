"""Read typed systemd pre-start commands without parsing display/history text."""

from pathlib import PurePosixPath

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_observe as observe,
    persistence_state as state,
)

FIELDS = (
    "path",
    "argv",
    "ignore_errors",
    "start_real_us",
    "start_monotonic_us",
    "stop_real_us",
    "stop_monotonic_us",
    "pid",
    "code",
    "status",
)


def require(value):
    state.require(value, "systemd-exec-proof-refused")


def decode_commands(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 65536)
    value = observe.decode(raw)
    state.keys(value, {"type", "data"})
    require(
        value["type"] == "a(sasbttttuii)"
        and type(value["data"]) is list
        and len(value["data"]) <= 32
    )
    result = []
    for row in value["data"]:
        require(type(row) is list and len(row) == len(FIELDS))
        path, argv, ignored, *numbers = row
        require(
            type(path) is str
            and path.startswith("/")
            and path != "/"
            and len(path) <= 4096
            and str(PurePosixPath(path)) == path
            and ".." not in PurePosixPath(path).parts
            and not any(char in path for char in "\r\n\0")
        )
        require(
            type(argv) is list
            and 1 <= len(argv) <= 128
            and all(
                type(arg) is str and len(arg) <= 4096 and "\0" not in arg
                for arg in argv
            )
            and type(ignored) is bool
        )
        require(
            all(type(part) is int for part in numbers)
            and all(0 <= part < 2**64 for part in numbers[:4])
            and 0 <= numbers[4] < 2**32
            and 0 <= numbers[5] <= 6
            and 0 <= numbers[6] <= 255
        )
        result.append(dict(zip(FIELDS, row)))
    return result


def unit_path(unit):
    require(state.matches(r"[A-Za-z0-9][A-Za-z0-9:_.@-]{0,127}\.service", unit))
    encoded = "".join(
        char if char.isascii() and char.isalnum() else "_" + format(ord(char), "02x")
        for char in unit
    )
    return "/org/freedesktop/systemd1/unit/" + encoded


def commands(unit):
    path = unit_path(unit)
    raw = observe.native(
        [
            "/usr/bin/busctl",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            path,
            "org.freedesktop.systemd1.Service",
            "ExecStartPre",
        ]
    )
    return decode_commands(raw)


def require_success(values, expected_argv, low_unix_s, high_unix_s):
    require(
        type(values) is list
        and len(values) == 1
        and type(low_unix_s) is int
        and type(high_unix_s) is int
        and 0 < low_unix_s <= high_unix_s
    )
    value = values[0]
    require(
        value["argv"] == expected_argv
        and value["path"] == expected_argv[0]
        and value["ignore_errors"] is False
        and value["code"] == 1
        and value["status"] == 0
        and value["pid"] > 1
        and 0 < value["start_monotonic_us"] <= value["stop_monotonic_us"]
        and (low_unix_s - 2) * 1000000
        <= value["start_real_us"]
        <= value["stop_real_us"]
        <= (high_unix_s + 2) * 1000000
    )
