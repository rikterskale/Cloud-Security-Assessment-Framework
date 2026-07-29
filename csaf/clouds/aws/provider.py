"""AWS provider: orchestrates read-only modules across regions."""

from __future__ import annotations

from ...catalog import Control
from ..base import CheckContext, attestation_results
from .modules import MODULE_REGISTRY

# Modules whose APIs are account-global; evaluated once.
GLOBAL_MODULES = {"identity", "s3"}
# Modules evaluated per authorized region.
REGIONAL_MODULES = {"compute", "network", "logging", "kms", "rds", "secrets"}


class AwsProvider:
    def __init__(self, session, baseline, evidence, logger, engagement, profile: str):
        self.session = session
        self.baseline = baseline
        self.evidence = evidence
        self.logger = logger
        self.engagement = engagement
        self.profile = profile
        self.account_id = session.account_id
        self._module_instances: dict[str, object] = {}
        self._global_cache: dict = {}

    def _module(self, name: str):
        if name not in self._module_instances:
            self._module_instances[name] = MODULE_REGISTRY[name]()
        return self._module_instances[name]

    def _context(self, region: str, cache: dict) -> CheckContext:
        return CheckContext(
            cloud="AWS",
            account_id=self.account_id,
            region=region,
            profile=self.profile,
            baseline=self.baseline,
            evidence=self.evidence,
            logger=self.logger,
            engagement=self.engagement,
            session=self.session,
            cache=cache,
        )

    def evaluate(self, controls: list[Control], regions: list[str]) -> list:
        results = []
        grouped: dict[str, list[Control]] = {}
        for control in controls:
            grouped.setdefault(control.module, []).append(control)

        for module_name, module_controls in grouped.items():
            if module_name == "attestation":
                results.extend(self._attestations(module_controls))
                continue
            if module_name not in MODULE_REGISTRY:
                self.logger.warn("provider", f"No provider module '{module_name}'; controls not tested.")
                continue

            module = self._module(module_name)
            if module_name in GLOBAL_MODULES:
                ctx = self._context("global", self._global_cache)
                for control in module_controls:
                    self.logger.info(module_name, f"Evaluating {control.id} (global)", controlId=control.id)
                    results.extend(module.evaluate(control, ctx))
            else:
                for region in regions:
                    ctx = self._context(region, {})
                    for control in module_controls:
                        self.logger.info(module_name, f"Evaluating {control.id} ({region})", controlId=control.id)
                        results.extend(module.evaluate(control, ctx))
        return results

    def _attestations(self, controls: list[Control]) -> list:
        return attestation_results(controls, self.engagement, "AWS", self.account_id)
