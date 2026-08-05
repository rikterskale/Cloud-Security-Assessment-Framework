# CSAF release process

1. Update `CHANGELOG.md`, compatibility notes, and generated CLI reference.
2. Run CI, container certification, and the Windows novice-guide validation.
3. Create and push an annotated tag matching `pyproject.toml`, for example `git tag -a v1.0.0 -m "CSAF v1.0.0" && git push origin v1.0.0`.
4. The tag-triggered Release workflow builds wheel/sdist artifacts, checksums, a CycloneDX SBOM, GitHub provenance/SBOM attestations, and a GitHub Release.
5. Verify release artifacts with `gh attestation verify` and record any deprecation notices in the next release notes.

Container publication is deliberately a separate, explicitly reviewed release job. It publishes only immutable version and digest references; never `latest` as the sole deployment reference.
