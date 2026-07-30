"""Atomic artifact-writing behavior."""

import tempfile
import unittest
from pathlib import Path

from csaf.io_utils import atomic_text_writer


class TestAtomicTextWriter(unittest.TestCase):
    def test_success_atomically_replaces_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "artifact.json"
            destination.write_text("old", encoding="utf-8")
            with atomic_text_writer(destination) as handle:
                handle.write("new")
            self.assertEqual(destination.read_text(encoding="utf-8"), "new")
            self.assertEqual(list(Path(tmp).glob(".*.tmp")), [])

    def test_failure_preserves_existing_destination_and_removes_temporary_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "artifact.json"
            destination.write_text("known-good", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "interrupted"):
                with atomic_text_writer(destination) as handle:
                    handle.write("partial")
                    raise RuntimeError("interrupted")
            self.assertEqual(destination.read_text(encoding="utf-8"), "known-good")
            self.assertEqual(list(Path(tmp).glob(".*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
