#!/usr/bin/env python3
"""Synthetic existing NFS storage; only status may be varied by tests."""
import json
import os
from pathlib import Path
import sys

if Path(sys.argv[0]).name == "pvesh":
    if os.environ.get("FAKE_NFS_EXISTING", "true") == "false":
        sys.exit("storage 'demo-backup' does not exist")
    print(json.dumps({"type": "nfs", "server": "backup.example.invalid", "export": "/backups",
                      "content": "backup", "options": "vers=3"}))
elif sys.argv[1:] == ["status", "--storage", "demo-backup"]:
    print("Name Type Status Total Used Available %")
    print("demo-backup nfs", os.environ.get("FAKE_NFS_STATUS", "inactive"), "100 10 90 10%")
else:
    sys.exit("Unexpected fake storage mutation")
