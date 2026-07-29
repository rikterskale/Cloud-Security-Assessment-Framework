"""AssessmentLogger: level filtering and dual human/JSONL output."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from csaf.logging_ import AssessmentLogger


class TestAssessmentLogger(unittest.TestCase):
    def make_logger(self, tmp, level):
        log_path = Path(tmp) / "run.log"
        jsonl_path = Path(tmp) / "run.jsonl"
        return AssessmentLogger("RUN-1", log_path=log_path, jsonl_path=jsonl_path, level=level), log_path, jsonl_path

    def emit_all(self, logger):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            logger.debug("comp", "debug msg")
            logger.info("comp", "info msg")
            logger.warn("comp", "warn msg")
            logger.error("comp", "error msg", controlId="CSAF-AWS-IAM-001")
        logger.close()

    def test_level_filtering(self):
        with tempfile.TemporaryDirectory() as tmp:
            logger, log_path, _ = self.make_logger(tmp, "WARN")
            self.emit_all(logger)
            text = log_path.read_text(encoding="utf-8")
            self.assertNotIn("debug msg", text)
            self.assertNotIn("info msg", text)
            self.assertIn("warn msg", text)
            self.assertIn("error msg", text)

    def test_jsonl_records_structured_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            logger, _, jsonl_path = self.make_logger(tmp, "DEBUG")
            self.emit_all(logger)
            records = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(records), 4)
            self.assertEqual({r["level"] for r in records}, {"DEBUG", "INFO", "WARN", "ERROR"})
            error = next(r for r in records if r["level"] == "ERROR")
            self.assertEqual(error["runId"], "RUN-1")
            self.assertEqual(error["controlId"], "CSAF-AWS-IAM-001")

    def test_unknown_level_defaults_to_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            logger, log_path, _ = self.make_logger(tmp, "NOISY")
            self.emit_all(logger)
            text = log_path.read_text(encoding="utf-8")
            self.assertNotIn("debug msg", text)
            self.assertIn("info msg", text)

    def test_no_paths_logger_is_console_only(self):
        logger = AssessmentLogger("RUN-2", level="ERROR")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            logger.info("comp", "quiet")
            logger.error("comp", "loud")
        logger.close()  # must not raise with no file handles


if __name__ == "__main__":
    unittest.main()
