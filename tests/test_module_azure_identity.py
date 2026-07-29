"""Azure RBAC identity module checks against faked ARM responses."""

import tempfile
import unittest

from csaf.clouds.azure.modules.identity import OWNER_ROLE_DEFINITION_ID, IdentityModule
from tests.fakes import make_azure_ctx, make_control

ROLE_DEFS = "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions"
ROLE_ASSIGNMENTS = "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments"


class IdentityTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = IdentityModule()


class TestCustomOwnerRoles(IdentityTestCase):
    def test_no_custom_roles_passes(self):
        ctx = make_azure_ctx(self.tmp.name, get_value={ROLE_DEFS: []})
        self.assertEqual(self.module.custom_owner_roles(make_control(), ctx).status, "Pass")

    def test_narrow_scope_or_no_star_does_not_offend(self):
        roles = [
            {
                "name": "narrow-scope",
                "properties": {
                    "roleName": "narrow-scope",
                    "assignableScopes": ["/subscriptions/sub-1/resourceGroups/rg1"],
                    "permissions": [{"actions": ["*"]}],
                },
            },
            {
                "name": "no-star",
                "properties": {
                    "roleName": "no-star",
                    "assignableScopes": ["/"],
                    "permissions": [{"actions": ["Microsoft.Compute/*/read"]}],
                },
            },
        ]
        ctx = make_azure_ctx(self.tmp.name, get_value={ROLE_DEFS: roles})
        self.assertEqual(self.module.custom_owner_roles(make_control(), ctx).status, "Pass")

    def test_broad_scope_and_star_action_fails(self):
        roles = [
            {
                "name": "sub-admin",
                "properties": {
                    "roleName": "sub-admin",
                    "assignableScopes": ["/subscriptions/sub-1"],
                    "permissions": [{"actions": ["*"]}],
                },
            }
        ]
        ctx = make_azure_ctx(self.tmp.name, get_value={ROLE_DEFS: roles})
        results = self.module.custom_owner_roles(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"sub-admin"})
        self.assertTrue(all(r.status == "Fail" for r in results))


class TestSubscriptionOwnerCount(IdentityTestCase):
    def _assignment(self, scope="/subscriptions/sub-1"):
        return {
            "properties": {
                "roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{OWNER_ROLE_DEFINITION_ID}",
                "scope": scope,
            }
        }

    def test_within_threshold_passes(self):
        ctx = make_azure_ctx(
            self.tmp.name,
            get_value={ROLE_ASSIGNMENTS: [self._assignment(), self._assignment()]},
        )
        self.assertEqual(self.module.subscription_owner_count(make_control(), ctx).status, "Pass")

    def test_over_threshold_is_review(self):
        assignments = [self._assignment() for _ in range(5)]
        ctx = make_azure_ctx(self.tmp.name, get_value={ROLE_ASSIGNMENTS: assignments})
        result = self.module.subscription_owner_count(make_control(), ctx)
        self.assertEqual(result.status, "Review")
        self.assertEqual(result.confidence, "MEDIUM")

    def test_non_owner_and_non_matching_scope_ignored(self):
        other_role = {
            "properties": {"roleDefinitionId": "/providers/.../deadbeef-role", "scope": "/subscriptions/sub-1"}
        }
        rg_scoped_owner = self._assignment(scope="/subscriptions/sub-1/resourceGroups/rg1")
        ctx = make_azure_ctx(self.tmp.name, get_value={ROLE_ASSIGNMENTS: [other_role, rg_scoped_owner]})
        self.assertEqual(self.module.subscription_owner_count(make_control(), ctx).status, "Pass")


if __name__ == "__main__":
    unittest.main()
