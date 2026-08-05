# Container support and certification

CSAF has two supported production container targets:

| Target | Dockerfile | Runtime | Supported capabilities |
| --- | --- | --- | --- |
| Linux (`linux/amd64`, `linux/arm64` when built for that architecture) | `Dockerfile` | Linux Docker daemon | AWS, Azure, GCP, Kubernetes, all CSAF console commands, offline self-check, reports, plugins |
| Windows Server 2022 (`windows/amd64`) | `Dockerfile.windows` | Windows Server 2022-compatible Docker daemon | The same CSAF capabilities and provider SDKs |

The images install the repository's hash-locked `requirements-lock.txt`, which
contains the core runtime and every optional cloud-provider SDK. They install
the CSAF distribution itself with `--no-deps --no-build-isolation`, so no
additional build dependency is downloaded and the image has exactly that
locked dependency set. They intentionally do not contain cloud credentials;
pass read-only credentials at runtime using the provider's supported workload
identity or secret mechanism.

## Important platform boundary

A container shares its host kernel. No one image can provide both native
Windows and native Linux execution. Build and publish the two images under the
same tag as an OCI multi-platform release, then Docker selects the matching
image for the host. The CSAF application capability set is identical in both
images; OS-specific host operations remain native to their respective image.

## Run a certified offline check

Linux / PowerShell:

```powershell
docker build -t csaf:local .
New-Item -ItemType Directory -Force out | Out-Null
foreach ($cloud in 'aws', 'azure', 'gcp', 'k8s') {
  docker run --rm --read-only --cap-drop ALL --tmpfs /tmp --user "$(id -u):$(id -g)" -v "${PWD}/out:/work/out" csaf:local --self-check --cloud $cloud --output-dir /work/out
}
```

On a Linux host, `--user` aligns the container process with the host directory
owner so the non-root image can write reports. Omit it on Docker Desktop if
your file-sharing configuration does not support Unix UID/GID mapping.

The self-check deliberately returns exit code `2` because its synthetic
posture includes one `NotTested` control. It is a successful certification run
when the command produces the report artifacts.

Windows containers (run from PowerShell against a Windows-container daemon):

```powershell
docker build -f Dockerfile.windows -t csaf:windows-local .
New-Item -ItemType Directory -Force out | Out-Null
foreach ($cloud in 'aws', 'azure', 'gcp', 'k8s') {
  docker run --rm -v "${PWD}\out:C:\work\out" csaf:windows-local --self-check --cloud $cloud --output-dir C:\work\out
}
```

## Production deployment requirements

- Pin the `FROM` image to an approved digest in your release branch and rebuild
  when the base image is patched.
- Run as the supplied unprivileged user; do not pass Docker socket mounts or
  privileged mode. The Linux command above also drops Linux capabilities.
- Mount a dedicated writable output directory. Keep the root filesystem
  read-only where the platform supports it.
- Use least-privilege, read-only cloud identities and treat output reports as
  sensitive assessment data.

## Certification gates

`.github/workflows/container.yml` builds the Linux image, runs a hardened
`--self-check` for AWS, Azure, GCP, and Kubernetes, and verifies a report from
each provider. The standard cross-OS job runs the complete application test
suite on native Windows, while the Windows-container job is intentionally
targeted at a Windows-container-capable self-hosted runner: hosted Linux Docker
daemons cannot validate Windows containers.
