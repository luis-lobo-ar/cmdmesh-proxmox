"""Pure selected-worker normal-return evidence, never recovery authority.

The caller supplies a trusted source-profile hash and freshly collected native
records. This validator cannot authenticate a journal export or associate a
worker with a lost request. No file, process, clock or network observation occurs.
"""

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_guest_api as api,
)

state, observe = api.state, api.observe
DOCUMENT = "cmdmesh.proxmox.owner-normal-return-observation"
LIMIT = 262144
EVENT_FIELDS = {
    "MESSAGE",
    "PRIORITY",
    "SYSLOG_IDENTIFIER",
    "_PID",
    "_UID",
    "_GID",
    "_EXE",
    "_COMM",
    "_SYSTEMD_UNIT",
    "_SYSTEMD_INVOCATION_ID",
    "_BOOT_ID",
    "__REALTIME_TIMESTAMP",
    "__MONOTONIC_TIMESTAMP",
    "__SEQNUM",
    "__SEQNUM_ID",
    "__CURSOR",
}


def require(value, code):
    state.require(value, "persistence-owner-reaper-" + code)


def _number(value):
    require(state.matches(r"[1-9][0-9]{0,19}", value), "journal-number")
    result = int(value)
    require(result < 2**64, "journal-number")
    return result


def _event(value, boot):
    require(type(value) is dict and set(value) == EVENT_FIELDS, "event-schema")
    require(all(type(item) is str for item in value.values()), "event-type")
    expected = {
        "PRIORITY": "6",
        "SYSLOG_IDENTIFIER": "pvedaemon",
        "_UID": "0",
        "_GID": "0",
        "_EXE": "/usr/bin/perl",
        "_SYSTEMD_UNIT": "pvedaemon.service",
        "_BOOT_ID": boot,
    }
    require(all(value[key] == item for key, item in expected.items()), "producer")
    require(
        all(
            state.matches(r"[a-f0-9]{32}", value[key])
            for key in ("_SYSTEMD_INVOCATION_ID", "__SEQNUM_ID")
        ),
        "journal-identity",
    )
    pid = _number(value["_PID"])
    require(pid > 1, "producer-pid")
    sequence = _number(value["__SEQNUM"])
    monotonic = _number(value["__MONOTONIC_TIMESTAMP"])
    realtime = _number(value["__REALTIME_TIMESTAMP"])
    # Fixed journalctl projection, including internally joined cursor fields.
    prefix = (
        f"s={value['__SEQNUM_ID']};i={sequence:x};b={boot};"
        f"m={monotonic:x};t={realtime:x};x="
    )
    require(
        value["__CURSOR"].startswith(prefix)
        and state.matches(r"[a-f0-9]{1,16}", value["__CURSOR"][len(prefix) :]),
        "cursor",
    )
    return pid, sequence, monotonic


def validate_normal_return(
    binding,
    expected_boot_id,
    expected_source_sha256,
    raw,
    raw_sha256,
    *,
    birth_floor,
    excluded_upids=(),
):
    """Join one completed start task, exact log and three trusted journal events.

    Birth floor is inclusive because process births are tick-quantized. Only
    explicitly supplied accepted prior UPIDs are excluded. The full causal
    certificate must separately qualify that floor, exclusion set, source
    profile, consumed actor claims, live state and actual lease/control closure.
    """
    require(type(binding) is api.GuestBinding, "binding")
    require(
        state.matches(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", expected_boot_id),
        "boot",
    )
    state.digest(expected_source_sha256)
    state.digest(raw_sha256)
    require(type(birth_floor) is int and 0 < birth_floor < 2**64, "birth-floor")
    require(type(excluded_upids) is tuple and len(excluded_upids) <= 32, "exclusions")
    for upid in excluded_upids:
        api.parse_upid(binding, upid)
    require(len(set(excluded_upids)) == len(excluded_upids), "exclusions")
    require(type(raw) is bytes and 0 < len(raw) <= LIMIT, "raw-input")
    require(state.sha256(raw) == raw_sha256, "external-hash")
    value = observe.decode(raw)
    require(
        type(value) is dict
        and set(value)
        == {
            "document_type",
            "schema_version",
            "source_manifest_sha256",
            "task",
            "log",
            "events",
        }
        and state.canonical(value) == raw,
        "schema",
    )
    require(
        value["document_type"] == DOCUMENT
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["source_manifest_sha256"] == expected_source_sha256,
        "profile",
    )
    task = value["task"]
    require(type(task) is dict and type(task.get("upid")) is str, "task")
    upid = task["upid"]
    identity = api.parse_upid(binding, upid)
    api.validate_task_status(binding, upid, task)
    require(
        task["status"] == "stopped"
        and identity["pstart"] >= birth_floor
        and upid not in excluded_upids,
        "candidate",
    )
    code = task["exitstatus"]
    require(code in {"OK", "WARNINGS: 1"}, "exitstatus")
    texts = ["TASK OK"] if code == "OK" else [api.WARNING, "TASK WARNINGS: 1"]
    expected_log = [{"n": index, "t": text} for index, text in enumerate(texts, 1)]
    api.native_outcome(task, value["log"])
    require(value["log"] == expected_log, "task-log")

    events = value["events"]
    require(type(events) is list and len(events) == 3, "events")
    boot = expected_boot_id.replace("-", "")
    by_message = {}
    numbers = {}
    for event in events:
        details = _event(event, boot)
        message = event["MESSAGE"]
        require(message not in by_message, "duplicate-event")
        by_message[message] = event
        numbers[message] = details
    start_message = "<root@pam> starting task " + upid
    child_message = f"starting CT {binding.vmid}: {upid}"
    end_message = f"<root@pam> end task {upid} {code}"
    ordered = [start_message, child_message, end_message]
    require(set(by_message) == set(ordered), "event-messages")
    start, child, end = (by_message[key] for key in ordered)
    start_n, child_n, end_n = (numbers[key] for key in ordered)
    require(
        start_n[0] == end_n[0]
        and start_n[0] != identity["pid"]
        and child_n[0] == identity["pid"]
        and start["_COMM"] == end["_COMM"] == "pvedaemon worke"
        and child["_COMM"] == ("task UPID:" + binding.node)[:15],
        "worker-join",
    )
    require(
        len({event["_SYSTEMD_INVOCATION_ID"] for event in events}) == 1
        and len({event["__SEQNUM_ID"] for event in events}) == 1
        and start_n[1] < child_n[1] < end_n[1]
        and start_n[2] <= child_n[2] <= end_n[2],
        "event-order",
    )
    return {
        "upid": upid,
        "worker": {"pid": identity["pid"], "pstart": identity["pstart"]},
        "exitstatus": code,
        "observation_sha256": raw_sha256,
        "source_manifest_sha256": expected_source_sha256,
        "normal_return_observed": True,
        "original_request_fenced": False,
        "original_native_operation_qualified": False,
        "ack_recovered": False,
        "native_action_dispatched": False,
    }
