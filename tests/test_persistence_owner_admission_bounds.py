"""Reject bounded-record shape limits before canonical output allocation."""

import importlib
import unittest
from unittest import mock


class AdmissionBoundsTests(unittest.TestCase):
    def test_depth_and_node_limits_precede_canonical_encoding(self):
        codec = importlib.import_module(
            "ansible_collections.cmdmesh.proxmox.plugins.module_utils.persistence_owner_execution_admission"
        )
        for raw in (
            b'{"value":' + b"[" * 65 + b"0" + b"]" * 65 + b"}",
            b'{"items":[' + b"0," * 200000 + b"0]}",
        ):
            with self.subTest(bytes=len(raw)), mock.patch.object(
                codec.r.state, "canonical", wraps=codec.r.state.canonical
            ) as encode:
                with self.assertRaises(ValueError):
                    codec._decode(raw, codec.r.state.sha256(raw), codec.RECORD_LIMIT)
                encode.assert_not_called()
