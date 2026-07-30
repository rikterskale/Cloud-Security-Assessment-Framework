"""S3 data-protection module checks against faked bucket inventories."""

import json
import tempfile
import unittest

from csaf.clouds.aws.modules.s3 import S3Module
from tests.fakes import FakeClient, make_control, make_ctx


def per_bucket(mapping):
    """Response callable keyed on the Bucket kwarg; Exception values raise."""

    def respond(kwargs):
        return mapping[kwargs["Bucket"]]

    return respond


class S3TestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = S3Module()

    def ctx(self, s3_responses=None, s3control_responses=None, buckets=None):
        responses = dict(s3_responses or {})
        if buckets is not None:
            responses["list_buckets"] = {"Buckets": [{"Name": name} for name in buckets]}
        clients = {"s3": FakeClient(responses=responses)}
        if s3control_responses:
            clients["s3control"] = FakeClient(responses=s3control_responses)
        return make_ctx(self.tmp.name, clients=clients)


class TestAccountPublicAccessBlock(S3TestCase):
    def test_all_four_settings_on_passes(self):
        cfg = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        ctx = self.ctx(s3control_responses={"get_public_access_block": {"PublicAccessBlockConfiguration": cfg}})
        self.assertEqual(self.module.account_public_access_block(make_control(), ctx).status, "Pass")

    def test_partial_settings_fail(self):
        cfg = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        ctx = self.ctx(s3control_responses={"get_public_access_block": {"PublicAccessBlockConfiguration": cfg}})
        self.assertEqual(self.module.account_public_access_block(make_control(), ctx).status, "Fail")

    def test_no_configuration_fails(self):
        ctx = self.ctx(
            s3control_responses={"get_public_access_block": Exception("NoSuchPublicAccessBlockConfiguration")}
        )
        self.assertEqual(self.module.account_public_access_block(make_control(), ctx).status, "Fail")

    def test_unexpected_error_propagates(self):
        ctx = self.ctx(s3control_responses={"get_public_access_block": Exception("Throttled")})
        with self.assertRaisesRegex(Exception, "Throttled"):
            self.module.account_public_access_block(make_control(), ctx)


class TestBucketPublicAccess(S3TestCase):
    def test_policy_public_and_acl_public_each_flagged(self):
        public_acl = {
            "Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]
        }
        private_acl = {"Grants": [{"Grantee": {"ID": "owner"}, "Permission": "FULL_CONTROL"}]}
        ctx = self.ctx(
            buckets=["by-policy", "by-acl", "private"],
            s3_responses={
                "get_bucket_policy_status": per_bucket(
                    {
                        "by-policy": {"PolicyStatus": {"IsPublic": True}},
                        "by-acl": Exception("NoSuchBucketPolicy"),
                        "private": {"PolicyStatus": {"IsPublic": False}},
                    }
                ),
                "get_bucket_acl": per_bucket({"by-policy": private_acl, "by-acl": public_acl, "private": private_acl}),
            },
        )
        results = self.module.bucket_public_access(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"by-policy", "by-acl"})
        self.assertTrue(all(r.status == "Fail" for r in results))

    def test_no_public_buckets_passes(self):
        ctx = self.ctx(
            buckets=["private"],
            s3_responses={
                "get_bucket_policy_status": Exception("NoSuchBucketPolicy"),
                "get_bucket_acl": {"Grants": []},
            },
        )
        result = self.module.bucket_public_access(make_control(), ctx)
        self.assertEqual(result.status, "Pass")

    def test_policy_access_denied_propagates_instead_of_passing(self):
        ctx = self.ctx(
            buckets=["locked"],
            s3_responses={
                "get_bucket_policy_status": Exception("AccessDenied"),
                "get_bucket_acl": {"Grants": []},
            },
        )
        with self.assertRaisesRegex(Exception, "AccessDenied"):
            self.module.bucket_public_access(make_control(), ctx)

    def test_acl_error_propagates_instead_of_passing(self):
        ctx = self.ctx(
            buckets=["locked"],
            s3_responses={
                "get_bucket_policy_status": {"PolicyStatus": {"IsPublic": False}},
                "get_bucket_acl": Exception("ThrottlingException"),
            },
        )
        with self.assertRaisesRegex(Exception, "ThrottlingException"):
            self.module.bucket_public_access(make_control(), ctx)


class TestBucketEncryption(S3TestCase):
    def test_missing_encryption_and_access_denied_are_offenders(self):
        ctx = self.ctx(
            buckets=["encrypted", "plain", "locked"],
            s3_responses={
                "get_bucket_encryption": per_bucket(
                    {
                        "encrypted": {"ServerSideEncryptionConfiguration": {}},
                        "plain": Exception("ServerSideEncryptionConfigurationNotFoundError"),
                        "locked": Exception("AccessDenied"),
                    }
                )
            },
        )
        results = self.module.bucket_encryption(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"plain", "locked(access-denied)"})

    def test_unexpected_error_raises_instead_of_silently_passing(self):
        ctx = self.ctx(
            buckets=["weird"],
            s3_responses={"get_bucket_encryption": Exception("InternalError: try again")},
        )
        with self.assertRaisesRegex(Exception, "InternalError"):
            self.module.bucket_encryption(make_control(), ctx)

    def test_all_encrypted_passes(self):
        ctx = self.ctx(
            buckets=["a", "b"],
            s3_responses={"get_bucket_encryption": {"ServerSideEncryptionConfiguration": {}}},
        )
        self.assertEqual(self.module.bucket_encryption(make_control(), ctx).status, "Pass")


class TestBucketTlsPolicy(S3TestCase):
    @staticmethod
    def policy(statements):
        return {"Policy": json.dumps({"Statement": statements})}

    def test_deny_insecure_transport_passes_including_dict_statement_and_bool(self):
        deny_str = {"Effect": "Deny", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
        deny_bool = {"Effect": "Deny", "Condition": {"Bool": {"aws:SecureTransport": False}}}
        ctx = self.ctx(
            buckets=["list-form", "dict-form"],
            s3_responses={
                "get_bucket_policy": per_bucket(
                    {
                        "list-form": self.policy([deny_str]),
                        "dict-form": {"Policy": json.dumps({"Statement": deny_bool})},
                    }
                )
            },
        )
        self.assertEqual(self.module.bucket_tls_policy(make_control(), ctx).status, "Pass")

    def test_missing_or_non_enforcing_policy_fails_per_bucket(self):
        allow_only = {"Effect": "Allow", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
        ctx = self.ctx(
            buckets=["no-policy", "wrong-policy"],
            s3_responses={
                "get_bucket_policy": per_bucket(
                    {"no-policy": Exception("NoSuchBucketPolicy"), "wrong-policy": self.policy([allow_only])}
                )
            },
        )
        results = self.module.bucket_tls_policy(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"no-policy", "wrong-policy"})
        self.assertTrue(all(r.status == "Fail" for r in results))


class TestBucketListCache(S3TestCase):
    def test_bucket_list_collected_once_per_context(self):
        client = FakeClient(
            responses={
                "list_buckets": {"Buckets": [{"Name": "a"}]},
                "get_bucket_encryption": {"ServerSideEncryptionConfiguration": {}},
                "get_bucket_policy": Exception("NoSuchBucketPolicy"),
            }
        )
        ctx = make_ctx(self.tmp.name, clients={"s3": client})
        self.module.bucket_encryption(make_control(), ctx)
        self.module.bucket_tls_policy(make_control(), ctx)
        list_calls = [name for name, _ in client.calls if name == "list_buckets"]
        self.assertEqual(len(list_calls), 1)


if __name__ == "__main__":
    unittest.main()
