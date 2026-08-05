# syntax=docker/dockerfile:1.7
# CSAF Linux runtime image.  Build with Docker BuildKit for cache mounts.
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="Cloud Security Assessment Framework" \
      org.opencontainers.image.description="Read-only multi-cloud security posture assessment" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/home/csaf/.local/bin:${PATH}"

WORKDIR /opt/csaf

# The lock includes the core and every supported provider SDK (AWS, Azure,
# GCP, and Kubernetes).  Install it before the source to maximize layer reuse.
COPY requirements-lock.txt ./
RUN python -m pip install --require-hashes -r requirements-lock.txt

COPY pyproject.toml README.md LICENSE invoke_assessment.py sign_engagement.py ./
COPY csaf ./csaf
RUN python -m pip install --no-deps --no-build-isolation . \
    && addgroup --system --gid 10001 csaf \
    && adduser --system --uid 10001 --ingroup csaf --home /home/csaf csaf \
    && mkdir -p /work/out \
    && chown -R csaf:csaf /home/csaf /work

WORKDIR /work
USER 10001:10001

# Mount a host directory at /work/out to retain assessment artifacts.
VOLUME ["/work/out"]
ENTRYPOINT ["csaf-assess"]
CMD ["--help"]
