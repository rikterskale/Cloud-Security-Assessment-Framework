"""Azure provider: orchestrates read-only modules at subscription scope.

Unlike AWS, ARM collection endpoints return resources across every location in
the subscription, so all modules are evaluated once at "global" scope.

Concurrency: evaluation is intentionally sequential. AWS parallelizes across
independent *regions* (each with its own isolated cache); a subscription has no
equivalent partition, so the only parallel unit here would be modules, which
share one memoization cache and one ARM session whose client is not guaranteed
thread-safe. CSAF therefore keeps this provider single-threaded by design (a
safe default) rather than adding unverified parallelism. See README
"Concurrency model".
"""

from __future__ import annotations

from ...catalog import Control
from ..base import CheckContext, attestation_results
from .modules import MODULE_REGISTRY


class AzureProvider:
    def __init__(self, session, baseline, evidence, logger, engagement, profile: str):
        self.session = session
        self.baseline = baseline
        self.evidence = evidence
        self.logger = logger
        self.engagement = engagement
        self.profile = profile
        self.account_id = session.subscription_id
        self._module_instances: dict[str, object] = {}
        self._cache: dict = {}

    def _module(self, name: str):
        if name not in self._module_instances:
            self._module_instances[name] = MODULE_REGISTRY[name]()
        return self._module_instances[name]

    def _context(self) -> CheckContext:
        return CheckContext(
            cloud="Azure",
            account_id=self.account_id,
            region="global",
            profile=self.profile,
            baseline=self.baseline,
            evidence=self.evidence,
            logger=self.logger,
            engagement=self.engagement,
            session=self.session,
            cache=self._cache,
        )

    def evaluate(self, controls: list[Control], regions: list[str]) -> list:
        results = []
        grouped: dict[str, list[Control]] = {}
        for control in controls:
            grouped.setdefault(control.module, []).append(control)

        ctx = self._context()
        for module_name, module_controls in grouped.items():
            if module_name == "attestation":
                results.extend(attestation_results(module_controls, self.engagement, "Azure", self.account_id))
                continue
            if module_name not in MODULE_REGISTRY:
                self.logger.warn("provider", f"No provider module '{module_name}'; controls not tested.")
                continue
            module = self._module(module_name)
            for control in module_controls:
                self.logger.info(module_name, f"Evaluating {control.id} (subscription)", controlId=control.id)
                results.extend(module.evaluate(control, ctx))
        return results
