"""Control-authoring toolkit: catalog linter + module scaffold (OFF-FEAT-008)."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from csaf.authoring import lint_catalog, lint_main, scaffold_main, scaffold_module
from csaf.resource_paths import read_resource_text

PACKAGED_AWS_CATALOG = None


def _write(tmp, data):
    path = Path(tmp) / "catalog.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _valid_catalog():
    # Reuse a real packaged control so module/check resolution succeeds.
    data = json.loads(read_resource_text("controls", "control-catalog.json"))
    # Keep a single real control to keep the test focused and fast.
    data["controls"] = data["controls"][:1]
    return data


class TestLinter(unittest.TestCase):
    def test_packaged_catalogs_are_clean(self):
        for name in (
            "control-catalog.json",
            "control-catalog-azure.json",
            "control-catalog-gcp.json",
            "control-catalog-k8s.json",
        ):
            data = json.loads(read_resource_text("controls", name))
            with tempfile.TemporaryDirectory() as tmp:
                path = _write(tmp, data)
                issues = lint_catalog(path)
                errors = [i for i in issues if i.level == "error"]
                self.assertEqual(errors, [], f"{name} lint errors: {errors}")

    def test_unknown_check_is_error(self):
        data = _valid_catalog()
        data["controls"][0]["check"] = "check_does_not_exist"
        with tempfile.TemporaryDirectory() as tmp:
            issues = lint_catalog(_write(tmp, data))
        self.assertTrue(any("not implemented" in i.message and i.level == "error" for i in issues))

    def test_unknown_module_is_error(self):
        data = _valid_catalog()
        data["controls"][0]["module"] = "no_such_module"
        with tempfile.TemporaryDirectory() as tmp:
            issues = lint_catalog(_write(tmp, data))
        self.assertTrue(any("not found in aws registry" in i.message for i in issues))

    def test_duplicate_id_is_error(self):
        data = _valid_catalog()
        dup = json.loads(json.dumps(data["controls"][0]))
        data["controls"].append(dup)
        with tempfile.TemporaryDirectory() as tmp:
            issues = lint_catalog(_write(tmp, data), check_registry=False)
        self.assertTrue(any("duplicate control id" in i.message for i in issues))

    def test_bad_severity_is_error(self):
        data = _valid_catalog()
        data["controls"][0]["defaultSeverity"] = "SEVERE"
        with tempfile.TemporaryDirectory() as tmp:
            issues = lint_catalog(_write(tmp, data), check_registry=False)
        # schema rejects it, and/or semantic check flags it — either way an error exists.
        self.assertTrue(any(i.level == "error" for i in issues))

    def test_lint_main_exit_codes(self):
        data = _valid_catalog()
        with tempfile.TemporaryDirectory() as tmp:
            good = _write(tmp, data)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(lint_main([str(good)]), 0)
            data["controls"][0]["module"] = "no_such_module"
            bad = Path(tmp) / "bad.json"
            bad.write_text(json.dumps(data), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(lint_main([str(bad)]), 1)


class TestScaffold(unittest.TestCase):
    def test_scaffold_produces_valid_python_and_entry(self):
        source, entry = scaffold_module("aws", "eventbridge", "check_rules_present")
        self.assertIn("class EventbridgeModule(AssessmentModule):", source)
        self.assertIn("def check_rules_present(self, control, ctx):", source)
        compile(source, "<scaffold>", "exec")  # must be syntactically valid Python
        self.assertEqual(entry["module"], "eventbridge")
        self.assertEqual(entry["check"], "check_rules_present")

    def test_scaffold_rejects_bad_cloud(self):
        with self.assertRaises(ValueError):
            scaffold_module("digitalocean", "x")

    def test_scaffold_main_runs(self):
        with redirect_stdout(io.StringIO()) as buf:
            rc = scaffold_main(["--cloud", "gcp", "--module", "pubsub"])
        self.assertEqual(rc, 0)
        self.assertIn("PubsubModule", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
