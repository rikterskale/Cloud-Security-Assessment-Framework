"""AWS provider: orchestrates read-only modules across regions."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from ...catalog import Control
from ..base import CheckContext, attestation_results
from .modules import MODULE_REGISTRY

# Modules whose APIs are account-global; evaluated once.
GLOBAL_MODULES = {"identity", "s3"}
# Modules evaluated per authorized region.
REGIONAL_MODULES = {"compute", "network", "logging", "kms", "rds", "secrets"}


class AwsProvider:
    def __init__(self, session, baseline, evidence, logger, engagement, profile: str, max_workers: int = 1,
                 progress_callback=None):
        """``max_workers`` parallelizes regional-module evaluation across regions.

        Defaults to 1 (fully sequential, identical to earlier releases). Each
        worker gets its own per-region ``CheckContext.cache``, so there is no
        shared mutable state between regions to guard; module instances are
        stateless and safely reused across threads.
        """
        self.session = session
        self.baseline = baseline
        self.evidence = evidence
        self.logger = logger
        self.engagement = engagement
        self.profile = profile
        self.max_workers = max(1, max_workers)
        self.progress_callback = progress_callback
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

        regional_groups: dict[str, list[Control]] = {}
        for module_name, module_controls in grouped.items():
            if module_name == "attestation":
                results.extend(self._attestations(module_controls))
                continue
            if module_name not in MODULE_REGISTRY:
                self.logger.warn("provider", f"No provider module '{module_name}'; controls not tested.")
                continue
            if module_name in GLOBAL_MODULES:
                module = self._module(module_name)
                ctx = self._context("global", self._global_cache)
                for control in module_controls:
                    self.logger.info(module_name, f"Evaluating {control.id} (global)", controlId=control.id)
                    results.extend(module.evaluate(control, ctx))
            else:
                regional_groups[module_name] = module_controls

        if regional_groups and regions:
            # Pre-create module instances before threading starts: avoids a
            # check-then-set race in ``_module`` across worker threads.
            for name in regional_groups:
                self._module(name)

            worker_count = min(self.max_workers, len(regions))
            if worker_count <= 1:
                for region in regions:
                    results.extend(self._evaluate_region(region, regional_groups))
            else:
                with ThreadPoolExecutor(max_workers=worker_count) as executor:
                    for region_results in executor.map(
                        self._evaluate_region, regions, [regional_groups] * len(regions)
                    ):
                        results.extend(region_results)

        return results

    def _evaluate_region(self, region: str, regional_groups: dict[str, list[Control]]) -> list:
        region_results = []
        cache: dict = {}
        control_total = sum(len(controls) for controls in regional_groups.values())
        # Coarse per-region heartbeat so a long multi-region run shows progress
        # without needing DEBUG-level per-control lines.
        self.logger.info(
            "progress",
            f"AWS region {region}: evaluating {control_total} control(s) across {len(regional_groups)} module(s).",
        )
        for module_name, module_controls in regional_groups.items():
            module = self._module_instances[module_name]
            ctx = self._context(region, cache)
            for control in module_controls:
                self.logger.info(module_name, f"Evaluating {control.id} ({region})", controlId=control.id)
                region_results.extend(module.evaluate(control, ctx))
        if self.progress_callback:
            self.progress_callback(region)
        return region_results

    def _attestations(self, controls: list[Control]) -> list:
        return attestation_results(controls, self.engagement, "AWS", self.account_id)
