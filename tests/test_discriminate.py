"""Regression tests for the Stage 1.5 §7 discrimination rule (src.discriminate)."""
import unittest

from src import discriminate as disc


class Flag(unittest.TestCase):
    def test_rwx_in_allowlisted_process_is_flagged(self):
        # RWX overrides the allowlist (e.g. BlackEnergy -> svchost).
        self.assertTrue(disc._flag("svchost.exe", disc.RWX))

    def test_non_rwx_in_allowlisted_process_is_not_flagged(self):
        self.assertFalse(disc._flag("svchost.exe", "PAGE_READWRITE"))

    def test_non_allowlisted_process_is_flagged_even_without_rwx(self):
        # e.g. imagery ruby (PAGE_READWRITE, ruby.exe not allowlisted).
        self.assertTrue(disc._flag("ruby.exe", "PAGE_READWRITE"))

    def test_random_named_malware_flagged(self):
        self.assertTrue(disc._flag("UWkpjFjDzM.exe", disc.RWX))


class Allowlist(unittest.TestCase):
    def test_expected_benign_runtimes_present(self):
        for name in ("svchost.exe", "MsMpEng.exe", "thunderbird.ex", "RuntimeBroker."):
            self.assertIn(name, disc.ALLOWLIST)

    def test_rwx_constant(self):
        self.assertEqual(disc.RWX, "PAGE_EXECUTE_READWRITE")


if __name__ == "__main__":
    unittest.main()
