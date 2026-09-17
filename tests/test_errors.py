"""Structured error mapping and live-preflight blocking behaviour."""

import unittest
from unittest.mock import patch

from csaf.errors import CsafError, from_exception, probe_cloud_access
from csaf.preflight import run_preflight
from csaf.runner import RunConfig, run_assessment


class TestFromException(unittest.TestCase):
    def test_access_denied_includes_fix_command(self):
        exc = type("ClientError", (Exception,), {})("AccessDenied")
        exc.response = {"Error": {"Code": "AccessDenied"}}
        err = from_exception(exc, resource="s3:ListAllMyBuckets")
        self.assertEqual(err.code, "CSAF-E004")
        self.assertIn("s3:ListAllMyBuckets", err.resource)
        self.assertIn("SecurityAudit", err.fix)


class TestLivePreflightRunner(unittest.TestCase):
    def test_blocking_probe_prevents_run_directory(self):
        err = CsafError("CSAF-E002", "no credentials", "sts:GetCallerIdentity", "aws sts get-caller-identity")
        with patch("csaf.errors.probe_cloud_access", return_value=[err]):
            result = run_assessment(RunConfig(self_check=False, skip_live_preflight=False, log_level="ERROR"))
        self.assertEqual(result.exit_code, 1)
        self.assertIn("CSAF-E002", result.message)
        self.assertIn("aws sts get-caller-identity", result.message)


class TestPreflightAwsRequiresBoto(unittest.TestCase):
    def test_jsonschema_is_required(self):
        checks = run_preflight("aws", ".")
        names = {check.name for check in checks}
        self.assertIn("jsonschema", names)
        self.assertIn("boto3", names)


class TestProbeUnknownCloud(unittest.TestCase):
    def test_unknown_cloud(self):
        errors = probe_cloud_access("oracle")
        self.assertTrue(errors[0].blocking)
        self.assertEqual(errors[0].code, "CSAF-E008")


class TestMultiScopeAndAccounts(unittest.TestCase):
    def test_multiple_aws_accounts_are_fatal(self):
        result = run_assessment(RunConfig(self_check=True, accounts=["111", "222"], log_level="ERROR"))
        self.assertEqual(result.exit_code, 1)
        self.assertIn("multiple AWS accounts", result.message)

    def test_azure_subscriptions_aggregate(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            result = run_assessment(
                RunConfig(
                    cloud="azure",
                    self_check=True,
                    subscriptions=["sub-a", "sub-b"],
                    output_dir=tmp,
                    log_level="ERROR",
                )
            )
            self.assertIn(result.exit_code, (0, 2))
            self.assertTrue((Path(tmp) / "aggregate.json").is_file())

    def test_preflight_live_includes_probe_rows(self):
        err = CsafError("CSAF-E002", "no credentials", "sts", "aws sts get-caller-identity", blocking=True)
        with patch("csaf.preflight.probe_cloud_access", create=True):
            with patch("csaf.errors.probe_cloud_access", return_value=[err]):
                checks = run_preflight("aws", ".", live=True)
        statuses = {c.name: c.status for c in checks}
        self.assertEqual(statuses.get("sts"), "FAIL")


class TestCloudProbes(unittest.TestCase):
    def test_probe_aws_ok(self):
        class Session:
            def __init__(self, profile_name=None):
                self.profile_name = profile_name

            def client(self, service, **kwargs):
                client = unittest.mock.MagicMock()
                if service == "sts":
                    client.get_caller_identity.return_value = {
                        "Arn": "arn:aws:iam::123:user/audit",
                        "Account": "123",
                    }
                return client

        boto3 = unittest.mock.MagicMock()
        boto3.Session.side_effect = Session
        with patch.dict("sys.modules", {"boto3": boto3}):
            from csaf.errors import _probe_aws

            errors = _probe_aws("audit")
        self.assertTrue(errors)
        self.assertFalse(errors[0].blocking)

    def test_probe_aws_sts_failure(self):
        class Session:
            def __init__(self, profile_name=None):
                pass

            def client(self, service, **kwargs):
                client = unittest.mock.MagicMock()
                client.get_caller_identity.side_effect = RuntimeError("Unable to locate credentials")
                return client

        boto3 = unittest.mock.MagicMock()
        boto3.Session.side_effect = Session
        with patch.dict("sys.modules", {"boto3": boto3}):
            from csaf.errors import _probe_aws

            errors = _probe_aws("missing")
        self.assertTrue(errors[0].blocking)
        self.assertIn("get-caller-identity", errors[0].fix)

    def test_probe_aws_s3_denied_is_blocking(self):
        class Session:
            def __init__(self, profile_name=None):
                pass

            def client(self, service, **kwargs):
                client = unittest.mock.MagicMock()
                if service == "sts":
                    client.get_caller_identity.return_value = {
                        "Arn": "arn:aws:iam::123:user/audit",
                        "Account": "123",
                    }
                elif service == "s3":
                    client.list_buckets.side_effect = RuntimeError("AccessDenied")
                return client

        boto3 = unittest.mock.MagicMock()
        boto3.Session.side_effect = Session
        with patch.dict("sys.modules", {"boto3": boto3}):
            from csaf.errors import _probe_aws

            errors = _probe_aws("audit")
        denied = [err for err in errors if err.blocking and "s3:ListBuckets" in err.resource]
        self.assertTrue(denied)
        self.assertIn("SecurityAudit", denied[0].fix)

    def test_probe_azure_login_failure(self):
        class Cred:
            def get_token(self, scope):
                raise RuntimeError("credential chain empty")

        azure_identity = unittest.mock.MagicMock()
        azure_identity.DefaultAzureCredential.return_value = Cred()
        with patch.dict(
            "sys.modules",
            {
                "azure": unittest.mock.MagicMock(),
                "azure.identity": azure_identity,
                "requests": unittest.mock.MagicMock(),
            },
        ):
            from csaf.errors import _probe_azure

            errors = _probe_azure(None)
        self.assertEqual(errors[0].code, "CSAF-E002")

    def test_probe_gcp_no_project(self):
        google_auth = unittest.mock.MagicMock()
        google_auth.default.return_value = (object(), None)
        transport = unittest.mock.MagicMock()
        with patch.dict(
            "sys.modules",
            {
                "google": unittest.mock.MagicMock(),
                "google.auth": google_auth,
                "google.auth.transport": unittest.mock.MagicMock(),
                "google.auth.transport.requests": transport,
            },
        ):
            from csaf.errors import _probe_gcp

            errors = _probe_gcp(None)
        self.assertTrue(errors[0].blocking)
        self.assertIn(errors[0].code, {"CSAF-E001", "CSAF-E002"})

    def test_probe_k8s_failure(self):
        k8s = unittest.mock.MagicMock()
        k8s.config.load_kube_config.side_effect = RuntimeError("no kubeconfig")
        with patch.dict(
            "sys.modules", {"kubernetes": k8s, "kubernetes.client": k8s.client, "kubernetes.config": k8s.config}
        ):
            from csaf.errors import _probe_k8s

            errors = _probe_k8s(None, None)
        self.assertEqual(errors[0].code, "CSAF-E002")
        self.assertIn("kubectl", errors[0].fix)


class TestErrorHelpers(unittest.TestCase):
    def test_file_not_found_and_permission(self):
        fn = from_exception(FileNotFoundError(2, "No such file", "engagement.json"))
        self.assertEqual(fn.code, "CSAF-E003")
        perm = from_exception(PermissionError("denied"))
        self.assertEqual(perm.code, "CSAF-E004")
        eng = from_exception(ValueError("engagement signature failed"))
        self.assertEqual(eng.code, "CSAF-E005")
        unknown = from_exception(RuntimeError("odd"))
        self.assertEqual(unknown.code, "CSAF-E999")

    def test_format_error(self):
        from csaf.errors import format_error

        text = format_error(CsafError("CSAF-E001", "missing", "boto3", "pip install"))
        self.assertIn("Resource: boto3", text)
        self.assertIn("Fix: pip install", text)


if __name__ == "__main__":
    unittest.main()
