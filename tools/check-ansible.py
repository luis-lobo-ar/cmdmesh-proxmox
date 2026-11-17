#!/usr/bin/env python3
"""Syntax-check every exported role with no SSH or infrastructure execution."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import yaml

ROOT = Path(__file__).resolve().parents[1]
COLLECTION = ROOT / "ansible/ansible_collections/cmdmesh/proxmox"
paths = [str(ROOT / "ansible/ansible_collections"), str(ROOT / ".ansible/collections")]
environment = {**os.environ, "ANSIBLE_COLLECTIONS_PATH": os.pathsep.join(paths)}
for source in COLLECTION.rglob("*.yml"):
    yaml.safe_load(source.read_text())
with tempfile.TemporaryDirectory() as temporary:
    playbook = Path(temporary) / "syntax.json"
    for role in sorted((COLLECTION / "roles").iterdir()):
        playbook.write_text(json.dumps([{"name": "Validate role syntax", "hosts": "localhost",
                                         "gather_facts": False,
                                         "roles": ["cmdmesh.proxmox." + role.name]}]))
        subprocess.run(["ansible-playbook", "--syntax-check", "-i", "localhost,", str(playbook)],
                       check=True, env=environment)
