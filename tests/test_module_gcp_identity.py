"""GCP IAM identity module checks against faked GCP REST responses."""

import datetime
import tempfile
import unittest

from csaf.clouds.gcp.modules.identity import CRM_V1, IAM_V1, IdentityModule
from tests.fakes import make_control, make_gcp_ctx

IAM_POLICY_URL = f"{CRM_V1}/projects/proj-1:getIamPolicy"
SA_LIST_URL = f"{IAM_V1}/projects/proj-1/serviceAccounts"


def sa_key_url(email):
    return f"{IAM_V1}/projects/proj-1/serviceAccounts/{email}/keys"


class IdentityTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = IdentityModule()

    def ctx_with_policy(self, bindings, audit_configs=None):
        policy = {"bindings": bindings}
        if audit_configs is not None:
            policy["auditConfigs"] = audit_configs
        return make_gcp_ctx(self.tmp.name, post={IAM_POLICY_URL: policy})

    def ctx_with_sa_keys(self, accounts, keys_by_email):
        get = {sa_key_url(email): {"keys": ks} for email, ks in keys_by_email.items()}
        return make_gcp_ctx(
            self.tmp.name,
            get_list={SA_LIST_URL: accounts},
            get=get,
        )


class TestSaAdminRoles(IdentityTestCase):
    def test_no_privileged_bindings_passes(self):
        ctx = self.ctx_with_policy(
            [{"role": "roles/viewer", "members": ["serviceAccount:x@proj-1.iam.gserviceaccount.com"]}]
        )
        self.assertEqual(self.module.sa_admin_roles(make_control(), ctx).status, "Pass")

    def test_project_sa_with_owner_role_flagged(self):
        member = "serviceAccount:deployer@proj-1.iam.gserviceaccount.com"
        ctx = self.ctx_with_policy([{"role": "roles/owner", "members": [member]}])
        results = self.module.sa_admin_roles(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"deployer@proj-1.iam.gserviceaccount.com"})
        self.assertTrue(all(r.status == "Fail" for r in results))

    def test_default_compute_sa_with_admin_role_flagged(self):
        member = "serviceAccount:123-compute@developer.gserviceaccount.com"
        ctx = self.ctx_with_policy([{"role": "roles/iam.securityAdmin", "members": [member]}])
        results = self.module.sa_admin_roles(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"123-compute@developer.gserviceaccount.com"})

    def test_user_member_ignored(self):
        ctx = self.ctx_with_policy([{"role": "roles/owner", "members": ["user:alice@example.com"]}])
        self.assertEqual(self.module.sa_admin_roles(make_control(), ctx).status, "Pass")


class TestUserManagedSaKeys(IdentityTestCase):
    def test_no_service_accounts_not_applicable(self):
        ctx = self.ctx_with_sa_keys([], {})
        self.assertEqual(self.module.user_managed_sa_keys(make_control(), ctx).status, "NotApplicable")

    def test_no_keys_passes(self):
        ctx = self.ctx_with_sa_keys(
            [{"email": "sa1@proj-1.iam.gserviceaccount.com"}], {"sa1@proj-1.iam.gserviceaccount.com": []}
        )
        self.assertEqual(self.module.user_managed_sa_keys(make_control(), ctx).status, "Pass")

    def test_user_managed_key_flagged(self):
        email = "sa1@proj-1.iam.gserviceaccount.com"
        ctx = self.ctx_with_sa_keys([{"email": email}], {email: [{"name": "key1"}]})
        results = self.module.user_managed_sa_keys(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {email})


class TestSaKeyRotation(IdentityTestCase):
    def test_no_keys_not_applicable(self):
        ctx = self.ctx_with_sa_keys(
            [{"email": "sa1@proj-1.iam.gserviceaccount.com"}], {"sa1@proj-1.iam.gserviceaccount.com": []}
        )
        self.assertEqual(self.module.sa_key_rotation(make_control(), ctx).status, "NotApplicable")

    def test_recent_key_passes(self):
        email = "sa1@proj-1.iam.gserviceaccount.com"
        recent = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        ctx = self.ctx_with_sa_keys([{"email": email}], {email: [{"name": "key1", "validAfterTime": recent}]})
        self.assertEqual(self.module.sa_key_rotation(make_control(), ctx).status, "Pass")

    def test_old_key_flagged(self):
        email = "sa1@proj-1.iam.gserviceaccount.com"
        old = (
            (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=200))
            .isoformat()
            .replace("+00:00", "Z")
        )
        ctx = self.ctx_with_sa_keys([{"email": email}], {email: [{"name": "key1", "validAfterTime": old}]})
        results = self.module.sa_key_rotation(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"key1"})

    def test_unparseable_date_flagged(self):
        email = "sa1@proj-1.iam.gserviceaccount.com"
        ctx = self.ctx_with_sa_keys([{"email": email}], {email: [{"name": "key1", "validAfterTime": "not-a-date"}]})
        results = self.module.sa_key_rotation(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"key1"})


class TestBasicRolesOnUsers(IdentityTestCase):
    def test_no_basic_role_bindings_passes(self):
        ctx = self.ctx_with_policy([{"role": "roles/viewer", "members": ["user:alice@example.com"]}])
        self.assertEqual(self.module.basic_roles_on_users(make_control(), ctx).status, "Pass")

    def test_user_with_editor_role_is_review(self):
        ctx = self.ctx_with_policy([{"role": "roles/editor", "members": ["user:dev@example.com"]}])
        results = self.module.basic_roles_on_users(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"user:dev@example.com"})
        self.assertTrue(all(r.status == "Review" for r in results))

    def test_service_account_member_ignored(self):
        member = "serviceAccount:sa@proj-1.iam.gserviceaccount.com"
        ctx = self.ctx_with_policy([{"role": "roles/owner", "members": [member]}])
        self.assertEqual(self.module.basic_roles_on_users(make_control(), ctx).status, "Pass")


if __name__ == "__main__":
    unittest.main()
