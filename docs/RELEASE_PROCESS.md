# CSAF release process

1. Update `CHANGELOG.md`, compatibility notes, and generated CLI reference.
2. Confirm the distribution name is `cloud-saf` (never publish as PyPI `csaf`).
   Configure PyPI Trusted Publishing for this GitHub repository before the
   first tag.
3. Run CI, container certification, and the novice-guide validation.
   Refresh novice-guide front matter to the release tag commit.
4. Create and push an annotated tag matching `pyproject.toml`, for example `git tag -a v1.1.0 -m "CSAF v1.1.0" && git push origin v1.1.0`.
5. The tag-triggered Release workflow builds wheel/sdist artifacts, checksums, a CycloneDX SBOM, GitHub provenance/SBOM attestations, a GitHub Release, a PyPI publish, and a GHCR image tagged with the version (not `latest` alone).
6. Verify release artifacts with `gh attestation verify <file> --repo rikterskale/Cloud-Security-Assessment-Framework` and `cosign`/attestation for the GHCR digest.
7. Record any deprecation notices in the next release notes.

Install from a tag:

```bash
pipx install cloud-saf==1.1.0
# or
brew install --HEAD Formula/cloud-saf.rb
```
