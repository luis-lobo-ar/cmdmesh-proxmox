"""Prospective retirement storage profile, not a publisher or native permission."""

from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_retirement as retirement,
)

PROTOCOL = "linux-otmpfile-procfd-exclusive-link-v1"
RUNTIME_ROOT = retirement.RUNTIME_ROOT
MARKER = retirement.MARKER
RUNTIME = {
    "document_type": "cmdmesh.proxmox.owner-retirement.runtime",
    "schema_version": 2,
    "legacy_schema": 3,
    "target_schema": 4,
    "publication_protocol": PROTOCOL,
}
