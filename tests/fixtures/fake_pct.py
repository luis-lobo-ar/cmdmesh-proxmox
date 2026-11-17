#!/usr/bin/env python3
"""Synthetic pct replacement. Reads/writes only the caller's temporary state."""
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
state_path = Path(os.environ["FAKE_PCT_STATE"])
with Path(os.environ["FAKE_PCT_LOG"]).open("a") as log:
    log.write(json.dumps(args) + "\n")
state = json.loads(state_path.read_text())
if args[:2] == ["config", "101"]:
    print(f'memory: {state["memory"]}\nswap: {state["swap"]}\nrootfs: local:101/rootfs,size={state["disk"]}G')
elif len(args) == 4 and args[:2] == ["set", "101"] and args[2] in ("--memory", "--swap"):
    state[args[2][2:]] = int(args[3])
    state_path.write_text(json.dumps(state))
elif len(args) == 4 and args[:3] == ["resize", "101", "rootfs"]:
    state["disk"] = float(args[3].removesuffix("G"))
    state_path.write_text(json.dumps(state))
else:
    sys.exit("Unexpected fake pct invocation")
