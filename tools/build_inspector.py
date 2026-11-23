#!/usr/bin/env python3
"""Build an exclusively created, reproducible inspection zipapp from public code."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import zipapp
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "__main__.py": "inspection/__main__.py",
    "inspection.py": "inspection/inspection.py",
    "inventory.py": "bin/cmdmesh-proxmox",
    "probes.py": "inspection/probes.py",
    "memory_state.py": "ansible/ansible_collections/cmdmesh/proxmox/plugins/module_utils/memory_state.py",
    "memory_remote.py": "ansible/ansible_collections/cmdmesh/proxmox/plugins/module_utils/memory_remote.py",
    "memory_collect.py": "inspection/memory_collect.py",
}
DRIVER_SOURCE = (
    "ansible/ansible_collections/cmdmesh/proxmox/plugins/modules/lxc_memory.py"
)


def public_source(root, relative):
    source = root
    for component in Path(relative).parts:
        source = source / component
        if source.is_symlink():
            raise ValueError("bundle sources cannot be symlinks")
    if not stat.S_ISREG(source.stat().st_mode):
        raise ValueError("bundle sources must be regular files")
    return source.read_bytes()


def build(root, output):
    captured = {
        name: public_source(root, relative)
        for name, relative in sorted(SOURCES.items())
    }
    driver_hashes = {
        SOURCES[name]: hashlib.sha256(captured[name]).hexdigest()
        for name in ("memory_state.py", "memory_remote.py")
    }
    driver_hashes[DRIVER_SOURCE] = hashlib.sha256(
        public_source(root, DRIVER_SOURCE)
    ).hexdigest()
    profile = {
        "document_type": "cmdmesh.proxmox.driver-profile",
        "schema_version": 1,
        "profile_id": "proxmox-lxc-memory",
        "profile_version": 1,
        "files": driver_hashes,
    }
    captured["driver-profile.json"] = (
        json.dumps(profile, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    archive = io.BytesIO()
    digests = {}
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as bundle:
        for name, data in sorted(captured.items()):
            digests[name] = hashlib.sha256(data).hexdigest()
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            bundle.writestr(entry, data)
    archive.seek(0)
    executable = io.BytesIO()
    zipapp.create_archive(
        archive, target=executable, interpreter="/usr/bin/env python3"
    )
    data = executable.getvalue()
    descriptor = os.open(
        output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o700)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        output.unlink()
        raise
    return {
        "schema_version": 1,
        "path": str(output),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sources_sha256": digests,
        "driver_files_sha256": driver_hashes,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(build(ROOT, args.out)))
    except (OSError, ValueError):
        parser.exit(
            1,
            "Cannot build inspector: require regular public sources and a new output path; existing files are never overwritten.\n",
        )


if __name__ == "__main__":
    main()
