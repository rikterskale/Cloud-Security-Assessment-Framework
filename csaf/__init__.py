"""Cloud Security Assessment Framework (CSAF).

A read-only, evidence-gathering cloud security posture assessment framework.
It enumerates configuration, evaluates a declarative control catalog, records
one status per selected control, and produces coverage, findings, and reports.

It does not create, modify, or delete cloud resources, and it does not execute
exploitation. Optional non-destructive validation checks are gated behind the
Validation authorization profile.
"""

FRAMEWORK_VERSION = "1.0.0"
SCHEMA_VERSION = "3.0"
CATALOG_SCHEMA_VERSION = "1.0"

__all__ = ["FRAMEWORK_VERSION", "SCHEMA_VERSION", "CATALOG_SCHEMA_VERSION"]
