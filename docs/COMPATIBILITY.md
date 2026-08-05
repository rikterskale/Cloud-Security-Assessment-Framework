# Public schema compatibility policy

CSAF treats `findings.json`, `control-results.jsonl`, `engagement.json`, and their published JSON Schemas as public interfaces.

- A patch release may clarify documentation and add optional report fields.
- A minor release may add optional fields, controls, mappings, or enum values only when older readers can safely ignore them.
- A major release is required to remove/rename a field, change a field's type or meaning, tighten a previously valid input, or alter an exit-code contract.
- Findings and control-result objects carry `SchemaVersion`; coverage carries
  `CoverageSchemaVersion`; engagement, catalog, and baseline interfaces carry
  `schemaVersion`. Consumers must ignore unknown optional fields and reject an
  unsupported major version for the specific interface they consume.

Deprecated fields remain emitted for at least one minor release and are listed in `CHANGELOG.md` with their removal target. Engagement inputs fail closed: a deprecated authorization field is never silently reinterpreted.
