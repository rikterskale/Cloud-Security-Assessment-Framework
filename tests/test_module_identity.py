"""IAM identity module checks against a faked credential report and policy set."""

import csv
import datetime
import io
import tempfile
import unittest

from csaf.clouds.aws.modules.identity import (
    IdentityModule,
    _age_days,
    _wildcard_match,
)
from tests.fakes import FakeClient, make_control, make_ctx

REPORT_FIELDS = [
    "user",
    "password_enabled",
    "password_last_used",
    "mfa_active",
    "access_key_1_active",
    "access_key_1_last_rotated",
    "access_key_1_last_used_date",
    "access_key_2_active",
    "access_key_2_last_rotated",
    "access_key_2_last_used_date",
]


def days_ago(days: float) -> str:
    moment = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def report_row(**overrides) -> dict:
    row = {field: "N/A" for field in REPORT_FIELDS}
    row.update(
        {
            "password_enabled": "false",
            "mfa_active": "false",
            "access_key_1_active": "false",
            "access_key_2_active": "false",
        }
    )
    row.update(overrides)
    return row


def report_bytes(rows: list[dict]) -> bytes:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=REPORT_FIELDS)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue().encode("utf-8")


def iam_client_with_report(rows: list[dict], **extra_responses) -> FakeClient:
    return FakeClient(
        responses={
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {"Content": report_bytes(rows)},
            **extra_responses,
        }
    )


class IdentityTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = IdentityModule()

    def ctx(self, clients, **kwargs):
        return make_ctx(self.tmp.name, clients=clients, **kwargs)


class TestHelpers(unittest.TestCase):
    def test_age_days_sentinels_and_garbage(self):
        for value in ("", "N/A", "no_information", "not_supported", "not-a-date"):
            self.assertIsNone(_age_days(value), value)

    def test_age_days_parses_z_timestamps(self):
        age = _age_days(days_ago(10))
        self.assertIsNotNone(age)
        self.assertAlmostEqual(age, 10.0, delta=0.1)

    def test_wildcard_match_table(self):
        cases = [
            ("iam:Pass*", "iam:PassRole", True),
            ("iam:*", "iam:PassRole", True),
            ("*", "iam:PassRole", True),
            ("iam:Create*", "iam:CreateAccessKey", True),
            ("IAM:pass*", "iam:PassRole", True),  # IAM matching is case-insensitive
            ("s3:*", "iam:PassRole", False),
            ("iam:PassRole", "iam:PassRole", False),  # no wildcard -> exact match handled elsewhere
            ("iam:Put*", "iam:PassRole", False),
        ]
        for pattern, action, expected in cases:
            self.assertEqual(_wildcard_match(pattern, action), expected, f"{pattern} vs {action}")


class TestRootChecks(IdentityTestCase):
    def test_root_mfa_pass_and_fail(self):
        for mfa, expected in (("true", "Pass"), ("false", "Fail")):
            ctx = self.ctx({"iam": iam_client_with_report([report_row(user="<root_account>", mfa_active=mfa)])})
            result = self.module.root_mfa(make_control(), ctx)
            self.assertEqual(result.status, expected)

    def test_root_row_absent_is_error_not_pass(self):
        ctx = self.ctx({"iam": iam_client_with_report([report_row(user="alice")])})
        result = self.module.root_mfa(make_control(), ctx)
        self.assertEqual(result.status, "Error")

    def test_root_access_keys(self):
        active = report_row(user="<root_account>", access_key_1_active="true")
        inactive = report_row(user="<root_account>")
        self.assertEqual(
            self.module.root_access_keys(make_control(), self.ctx({"iam": iam_client_with_report([active])})).status,
            "Fail",
        )
        self.assertEqual(
            self.module.root_access_keys(make_control(), self.ctx({"iam": iam_client_with_report([inactive])})).status,
            "Pass",
        )

    def test_root_last_used_recent_fails_old_passes(self):
        recent = report_row(user="<root_account>", password_last_used=days_ago(2))
        old = report_row(user="<root_account>", password_last_used=days_ago(120))
        never = report_row(user="<root_account>")
        self.assertEqual(
            self.module.root_last_used(make_control(), self.ctx({"iam": iam_client_with_report([recent])})).status,
            "Fail",
        )
        self.assertEqual(
            self.module.root_last_used(make_control(), self.ctx({"iam": iam_client_with_report([old])})).status,
            "Pass",
        )
        self.assertEqual(
            self.module.root_last_used(make_control(), self.ctx({"iam": iam_client_with_report([never])})).status,
            "Pass",
        )

    def test_credential_report_cached_and_archived_as_evidence(self):
        client = iam_client_with_report([report_row(user="<root_account>", mfa_active="true")])
        ctx = self.ctx({"iam": client})
        self.module.root_mfa(make_control(), ctx)
        self.module.root_access_keys(make_control(), ctx)
        generate_calls = [name for name, _ in client.calls if name == "generate_credential_report"]
        self.assertEqual(len(generate_calls), 1, "credential report should be collected once per context")
        evidence = ctx.evidence.evidence_dir / "01_identity" / "credential-report.csv"
        self.assertTrue(evidence.exists())


class TestPasswordPolicy(IdentityTestCase):
    def test_missing_policy_is_fail_not_error(self):
        client = FakeClient(responses={"get_account_password_policy": Exception("NoSuchEntity: none configured")})
        result = self.module.password_policy(make_control(), self.ctx({"iam": client}))
        self.assertEqual(result.status, "Fail")

    def test_weak_policy_lists_each_issue(self):
        policy = {"MinimumPasswordLength": 8, "RequireSymbols": False, "RequireNumbers": True}
        client = FakeClient(responses={"get_account_password_policy": {"PasswordPolicy": policy}})
        result = self.module.password_policy(make_control(), self.ctx({"iam": client}))
        self.assertEqual(result.status, "Fail")
        self.assertIn("length 8<14", result.observed_value)
        self.assertIn("no symbols", result.observed_value)
        self.assertNotIn("no numbers", result.observed_value)

    def test_strong_policy_passes(self):
        policy = {
            "MinimumPasswordLength": 16,
            "RequireSymbols": True,
            "RequireNumbers": True,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
        }
        client = FakeClient(responses={"get_account_password_policy": {"PasswordPolicy": policy}})
        result = self.module.password_policy(make_control(), self.ctx({"iam": client}))
        self.assertEqual(result.status, "Pass")

    def test_baseline_threshold_override(self):
        policy = {
            "MinimumPasswordLength": 10,
            "RequireSymbols": True,
            "RequireNumbers": True,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
        }
        client = FakeClient(responses={"get_account_password_policy": {"PasswordPolicy": policy}})
        ctx = self.ctx({"iam": client}, thresholds={"passwordMinLength": 10})
        self.assertEqual(self.module.password_policy(make_control(), ctx).status, "Pass")


class TestUserCredentials(IdentityTestCase):
    def test_user_mfa_flags_each_console_user_without_mfa(self):
        rows = [
            report_row(user="<root_account>", mfa_active="false"),  # root excluded from this check
            report_row(user="alice", password_enabled="true", mfa_active="false"),
            report_row(user="bob", password_enabled="true", mfa_active="true"),
            report_row(user="svc-no-console", password_enabled="false", mfa_active="false"),
        ]
        results = self.module.user_mfa(make_control(), self.ctx({"iam": iam_client_with_report(rows)}))
        self.assertEqual([r.status for r in results], ["Fail"])
        self.assertEqual(results[0].resource_id, "alice")

    def test_user_mfa_all_covered_is_single_pass(self):
        rows = [report_row(user="alice", password_enabled="true", mfa_active="true")]
        results = self.module.user_mfa(make_control(), self.ctx({"iam": iam_client_with_report(rows)}))
        self.assertEqual([r.status for r in results], ["Pass"])

    def test_access_key_rotation_boundary(self):
        rows = [
            report_row(user="stale", access_key_1_active="true", access_key_1_last_rotated=days_ago(91)),
            report_row(user="fresh", access_key_1_active="true", access_key_1_last_rotated=days_ago(89)),
            report_row(user="inactive", access_key_1_active="false", access_key_1_last_rotated=days_ago(400)),
        ]
        results = self.module.access_key_rotation(make_control(), self.ctx({"iam": iam_client_with_report(rows)}))
        self.assertEqual([r.status for r in results], ["Fail"])
        self.assertEqual(results[0].resource_id, "stale:key1")

    def test_unused_credentials_password_and_keys(self):
        rows = [
            report_row(user="ghost", password_enabled="true", password_last_used=days_ago(200)),
            report_row(user="dual", access_key_2_active="true", access_key_2_last_used_date=days_ago(120)),
            report_row(user="active", password_enabled="true", password_last_used=days_ago(3)),
            report_row(user="<root_account>", password_enabled="true", password_last_used=days_ago(500)),
        ]
        results = self.module.unused_credentials(make_control(), self.ctx({"iam": iam_client_with_report(rows)}))
        self.assertEqual({r.resource_id for r in results}, {"ghost", "dual"})
        self.assertTrue(all(r.status == "Fail" for r in results))


def policy_client(documents: dict[str, dict]) -> FakeClient:
    """documents maps policy name -> policy document."""
    policies = [
        {"PolicyName": name, "Arn": f"arn:aws:iam::111122223333:policy/{name}", "DefaultVersionId": "v1"}
        for name in documents
    ]

    def get_policy_version(kwargs):
        name = kwargs["PolicyArn"].rsplit("/", 1)[-1]
        return {"PolicyVersion": {"Document": documents[name]}}

    return FakeClient(
        responses={"get_policy_version": get_policy_version},
        pages={"list_policies": [{"Policies": policies}]},
    )


class TestPolicyChecks(IdentityTestCase):
    def test_star_admin_detects_dict_statement_and_string_action(self):
        documents = {
            "full-admin": {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}},
            "scoped": {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]},
            "deny-all": {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]},
        }
        results = self.module.star_admin_policies(make_control(), self.ctx({"iam": policy_client(documents)}))
        self.assertEqual([r.status for r in results], ["Fail"])
        self.assertIn("full-admin", results[0].observed_value)

    def test_star_admin_clean_passes(self):
        documents = {"scoped": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}}
        result = self.module.star_admin_policies(make_control(), self.ctx({"iam": policy_client(documents)}))
        self.assertEqual(result.status, "Pass")

    def test_privesc_flags_exact_and_wildcard_grants_as_review(self):
        documents = {
            "deployer": {"Statement": [{"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}]},
            "wildcarded": {"Statement": [{"Effect": "Allow", "Action": ["iam:Attach*"], "Resource": "*"}]},
            "admin": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},  # full admin excluded
            "reader": {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]},
        }
        results = self.module.privesc_permissions(make_control(), self.ctx({"iam": policy_client(documents)}))
        flagged = {r.resource_id.rsplit("/", 1)[-1] for r in results}
        self.assertEqual(flagged, {"deployer", "wildcarded"})
        for result in results:
            self.assertEqual(result.status, "Review")
            self.assertEqual(result.confidence, "MEDIUM")

    def test_privesc_clean_passes(self):
        documents = {"reader": {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]}}
        result = self.module.privesc_permissions(make_control(), self.ctx({"iam": policy_client(documents)}))
        self.assertEqual(result.status, "Pass")


class TestAccessAnalyzer(IdentityTestCase):
    def test_active_analyzer_passes(self):
        client = FakeClient(responses={"list_analyzers": {"analyzers": [{"status": "ACTIVE"}]}})
        result = self.module.access_analyzer(make_control(), self.ctx({"accessanalyzer": client}))
        self.assertEqual(result.status, "Pass")

    def test_no_active_analyzer_fails(self):
        client = FakeClient(responses={"list_analyzers": {"analyzers": [{"status": "CREATING"}]}})
        result = self.module.access_analyzer(make_control(), self.ctx({"accessanalyzer": client}))
        self.assertEqual(result.status, "Fail")


if __name__ == "__main__":
    unittest.main()
