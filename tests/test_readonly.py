"""Read-only guardrail: only non-mutating operations may reach the client."""

import unittest

from csaf.clouds.aws.session import READ_ONLY_PREFIXES, ReadOnlyClient, ReadOnlyViolation

MUTATING_OPERATIONS = [
    "create_bucket",
    "delete_user",
    "put_bucket_policy",
    "update_function_code",
    "attach_role_policy",
    "detach_user_policy",
    "run_instances",
    "start_instances",
    "stop_instances",
    "terminate_instances",
    "reboot_instances",
    "modify_instance_attribute",
    "tag_resource",
    "untag_resource",
    "invoke",
    "add_user_to_group",
    "remove_role_from_instance_profile",
    "set_default_policy_version",
    "enable_key_rotation",
    "disable_key",
    "revoke_security_group_ingress",
    "authorize_security_group_ingress",
    "copy_object",
    "restore_object",
    "cancel_key_deletion",
    "schedule_key_deletion",
    "assume_role",
]

READ_OPERATIONS = [
    "describe_instances",
    "list_buckets",
    "get_bucket_policy",
    "head_object",
    "lookup_events",
    "batch_get_item",
    "generate_credential_report",
    "generate_service_last_accessed_details",
    "simulate_principal_policy",
    "simulate_custom_policy",
]


class RecordingClient:
    """Answers any method name so the guard is the only thing blocking calls."""

    meta = {"service": "fake"}  # non-callable attribute, passes through the proxy

    def __getattr__(self, name):
        def call(**kwargs):
            return {"op": name}

        return call

    def get_paginator(self, name):
        return f"paginator:{name}"


class TestReadOnlyGuard(unittest.TestCase):
    def setUp(self):
        self.client = ReadOnlyClient(RecordingClient())

    def test_read_operations_allowed(self):
        for op in READ_OPERATIONS:
            self.assertEqual(getattr(self.client, op)()["op"], op)

    def test_mutating_operations_blocked(self):
        for op in MUTATING_OPERATIONS:
            with self.assertRaises(ReadOnlyViolation, msg=f"guard must block {op}"):
                getattr(self.client, op)()

    def test_paginator_guarded_both_ways(self):
        self.assertEqual(self.client.get_paginator("list_policies"), "paginator:list_policies")
        for op in ("delete_objects", "put_bucket_policy", "create_keys"):
            with self.assertRaises(ReadOnlyViolation):
                self.client.get_paginator(op)

    def test_non_callable_attributes_pass_through(self):
        self.assertEqual(self.client.meta, {"service": "fake"})

    def test_private_attributes_raise_attribute_error(self):
        with self.assertRaises(AttributeError):
            _ = self.client._secret

    def test_violation_is_a_runtime_error(self):
        # Callers that only catch RuntimeError still stop on a violation.
        self.assertTrue(issubclass(ReadOnlyViolation, RuntimeError))

    def test_prefix_list_contains_no_mutating_verbs(self):
        for prefix in READ_ONLY_PREFIXES:
            for verb in ("create", "delete", "put_", "update", "attach", "modify", "run_", "terminate"):
                self.assertFalse(prefix.startswith(verb), f"suspicious read-only prefix: {prefix}")


if __name__ == "__main__":
    unittest.main()
