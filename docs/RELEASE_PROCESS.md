# CSAF release process

1. Update `CHANGELOG.md`, compatibility notes, and generated CLI reference.
2. Run CI, container certification, and the Windows novice-guide validation.
   The `novice-guides` CI matrix executes the canonical guide contract on both
   Ubuntu and Windows; its front matter should be refreshed to the release tag
   commit as part of this step.
3. Create and push an annotated tag matching `pyproject.toml`, for example `git tag -a v1.0.0 -m "CSAF v1.0.0" && git push origin v1.0.0`.
4. The tag-triggered Release workflow builds wheel/sdist artifacts, checksums, a CycloneDX SBOM, GitHub provenance/SBOM attestations, and a GitHub Release.
5. Verify release artifacts with `gh attestation verify` and record any deprecation notices in the next release notes.

Container publication is not automated by the workflows currently in this
repository. If a separately reviewed publication job is introduced, it must
publish immutable version and digest references and must not use `latest` as
the sole deployment reference.
