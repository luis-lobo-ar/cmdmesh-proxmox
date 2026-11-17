#!/usr/bin/env python3
"""Fake backup commands write only a disposable test log and exit code."""
import json
import os
from pathlib import Path
import sys

with Path(os.environ["FAKE_BACKUP_LOG"]).open("a") as log:
    log.write(json.dumps([Path(sys.argv[0]).name, *sys.argv[1:]]) + "\n")
if Path(sys.argv[0]).name == "vzdump":
    sys.exit(int(os.environ.get("FAKE_BACKUP_EXIT", "0")))
if Path(sys.argv[0]).name not in ("qm", "pct") or sys.argv[1:] != ["config", "101"]:
    sys.exit(99)
