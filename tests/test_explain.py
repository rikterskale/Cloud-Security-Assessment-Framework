"""Offline --explain CONTROL_ID (UX-ENH-007)."""

import io
import json
import unittest
from contextlib import redirect_stdout

from csaf.explain import explain_control
from csaf.resource_paths import read_resource_text
from invoke_assessment import main


def _first_control_id(catalog_name="control-catalog.json"):
    data = json.loads(read_resource_text("controls", catalog_name))
    return data["controls"][0]["id"]


class TestExplain(unittest.TestCase):
    def test_explain_known_control(self):
        cid = _first_control_id()
        text = explain_control("aws", cid)
        self.assertIsNotNone(text)
        self.assertIn(cid, text)
        self.assertIn("Remediation:", text)
        self.assertIn("Implemented by:", text)

    def test_unknown_control_returns_none(self):
        self.assertIsNone(explain_control("aws", "NOPE-999"))

    def test_unknown_cloud_raises(self):
        with self.assertRaises(ValueError):
            explain_control("oracle", "x")

    def test_cli_explain_found(self):
        cid = _first_control_id()
        with redirect_stdout(io.StringIO()) as buf:
            rc = main(["--explain", cid])
        self.assertEqual(rc, 0)
        self.assertIn(cid, buf.getvalue())

    def test_cli_explain_not_found(self):
        with redirect_stdout(io.StringIO()) as buf:
            rc = main(["--explain", "NOPE-999", "--cloud", "gcp"])
        self.assertEqual(rc, 1)
        self.assertIn("not found", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
