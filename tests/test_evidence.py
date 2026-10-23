"""Offline checks for local evidence freshness.

Run with: python -m unittest discover -s tests -v
No network connections or exploit requests are made by these tests.
"""

from pathlib import Path
import tempfile
import unittest

from php2shell import proof_file_is_fresh


class EvidenceFreshnessTests(unittest.TestCase):
    def test_absent_proof_never_confirms(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "not-created.txt"
            self.assertFalse(proof_file_is_fresh(str(path), None))

    def test_old_unchanged_proof_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.txt"
            path.write_text("old proof", encoding="utf-8")
            info = path.stat()
            baseline = (info.st_mtime_ns, info.st_size)
            self.assertFalse(proof_file_is_fresh(str(path), baseline))

    def test_new_proof_can_be_evaluated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.txt"
            path.write_text("new proof", encoding="utf-8")
            self.assertTrue(proof_file_is_fresh(str(path), None))

    def test_changed_proof_can_be_evaluated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.txt"
            path.write_text("old", encoding="utf-8")
            info = path.stat()
            baseline = (info.st_mtime_ns, info.st_size)
            path.write_text("new proof content", encoding="utf-8")
            self.assertTrue(proof_file_is_fresh(str(path), baseline))


if __name__ == "__main__":
    unittest.main()
