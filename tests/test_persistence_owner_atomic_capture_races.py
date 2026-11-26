"""Actual metadata changes between a policy check and its captured identity."""

import ctypes
import os
import unittest
from unittest import mock

import test_persistence_owner_atomic as fixture


class CapturedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.AtomicTests("runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.atomic = self.case.atomic

    def raced_publish(self, subject):
        library = ctypes.CDLL(None, use_errno=True)
        link = library.linkat
        link.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
        ]
        link.restype = ctypes.c_int
        alias = self.case.root / "unexpected-alias"
        content = self.atomic._content
        calls = 0

        def change_before_capture(fd, raw):
            nonlocal calls
            calls += 1
            if (subject == "before-links" and calls == 1) or (
                subject == "final-links" and calls == 2
            ):
                result = link(
                    -100,
                    os.fsencode("/proc/self/fd/" + str(fd)),
                    -100,
                    os.fsencode(alias),
                    self.atomic.AT_SYMLINK_FOLLOW,
                )
                self.assertEqual(result, 0, ctypes.get_errno())
            if subject == "final-mode" and calls == 2:
                os.fchmod(fd, 0o644)
            return content(fd, raw)

        class MainLink:
            def __call__(self, *args):
                result = link(*args)
                if subject == "before-links":
                    alias.unlink()
                return result

        class Library:
            fstatfs = library.fstatfs
            linkat = MainLink()

        with mock.patch.object(
            self.atomic.ctypes, "CDLL", return_value=Library()
        ), mock.patch.object(
            self.atomic, "_content", side_effect=change_before_capture
        ):
            return self.atomic.publish_observed(
                self.case.path, self.case.raw, protocol=self.atomic.PROTOCOL
            )

    def test_observed_before_identity_must_still_have_zero_links(self):
        with self.assertRaises(ValueError):
            self.raced_publish("before-links")

    def test_observed_final_identity_must_still_have_one_link(self):
        with self.assertRaises(ValueError):
            self.raced_publish("final-links")

    def test_observed_final_identity_must_still_be_private(self):
        with self.assertRaises(ValueError):
            self.raced_publish("final-mode")


if __name__ == "__main__":
    unittest.main()
