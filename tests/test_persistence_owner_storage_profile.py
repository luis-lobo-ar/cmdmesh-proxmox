"""A storage version does not change the externally selected semantic target."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ansible"))
from ansible_collections.cmdmesh.proxmox.plugins.module_utils import (
    persistence_owner_retirement as retirement,
    persistence_owner_storage_profile as profile,
)


class StorageProfileTests(unittest.TestCase):
    def test_explicit_protocol_and_same_metadata_location(self):
        self.assertEqual(profile.PROTOCOL, "linux-otmpfile-procfd-exclusive-link-v1")
        self.assertEqual(profile.RUNTIME_ROOT, retirement.RUNTIME_ROOT)
        self.assertEqual(profile.MARKER, retirement.MARKER)

    def test_runtime_is_a_new_exact_storage_profile(self):
        self.assertEqual(
            profile.RUNTIME,
            {
                **retirement.RUNTIME,
                "schema_version": 2,
                "publication_protocol": profile.PROTOCOL,
            },
        )
        self.assertNotEqual(
            retirement.state.canonical(profile.RUNTIME),
            retirement.state.canonical(retirement.RUNTIME),
        )
        self.assertEqual(retirement.RUNTIME["schema_version"], 1)


if __name__ == "__main__":
    unittest.main()
