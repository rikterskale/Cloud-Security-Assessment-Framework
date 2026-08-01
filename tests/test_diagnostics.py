"""Actionable first-run diagnostics (UX-ENH-001)."""

import unittest

from csaf.diagnostics import explain_exception, format_fatal


class TestExplainException(unittest.TestCase):
    def test_provider_dependency_missing(self):
        summary, hint = explain_exception(ModuleNotFoundError("No module named 'azure'", name="azure"))
        self.assertIn("selected cloud", summary)
        self.assertIn("csaf[azure]", hint)

    def test_core_dependency_missing(self):
        summary, hint = explain_exception(ModuleNotFoundError("No module named 'jsonschema'", name="jsonschema"))
        self.assertIn("dependency", summary.lower())
        self.assertIn("requirements-lock.txt", hint)

    def test_credentials_by_class_name(self):
        exc = type("NoCredentialsError", (Exception,), {})("Unable to locate credentials")
        summary, hint = explain_exception(exc)
        self.assertIn("authenticate", summary.lower())
        self.assertIn("--self-check", hint)

    def test_credentials_by_message(self):
        summary, hint = explain_exception(RuntimeError("could not find credential in chain"))
        self.assertIn("authenticate", summary.lower())

    def test_file_not_found(self):
        summary, hint = explain_exception(FileNotFoundError(2, "No such file", "engagement.json"))
        self.assertIn("not found", summary.lower())
        self.assertIn("--engagement", hint)

    def test_permission_error(self):
        summary, hint = explain_exception(PermissionError("denied"))
        self.assertIn("output directory", summary.lower())
        self.assertIn("--output-dir", hint)

    def test_engagement_message(self):
        summary, hint = explain_exception(ValueError("Engagement signature verification failed"))
        self.assertIn("engagement", summary.lower())
        self.assertIn("csaf-sign-engagement", hint)

    def test_unknown_falls_back_generically(self):
        summary, hint = explain_exception(RuntimeError("something odd"))
        self.assertIn("something odd", summary)
        self.assertIn("--log-level DEBUG", hint)

    def test_format_fatal_shape(self):
        text = format_fatal(ModuleNotFoundError("No module named 'kubernetes'", name="kubernetes"))
        self.assertIn("→", text)
        self.assertIn("csaf[k8s]", text)


if __name__ == "__main__":
    unittest.main()
