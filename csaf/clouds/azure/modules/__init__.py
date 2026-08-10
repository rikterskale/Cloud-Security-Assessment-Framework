"""Azure assessment modules."""

from csaf.plugins import discover_plugin_modules

from .compute import ComputeModule
from .defender import DefenderModule
from .identity import IdentityModule
from .keyvault import KeyVaultModule
from .monitor import MonitorModule
from .network import NetworkModule
from .secret_discovery import SecretDiscoveryModule
from .sql import SqlModule
from .storage import StorageModule

# Built-in modules, keyed by catalog ``module``. Third-party distributions can
# add entries via the "csaf.modules.azure" entry-point group (see csaf/plugins.py).
_BUILTIN_MODULE_REGISTRY = {
    "identity": IdentityModule,
    "defender": DefenderModule,
    "storage": StorageModule,
    "network": NetworkModule,
    "compute": ComputeModule,
    "monitor": MonitorModule,
    "sql": SqlModule,
    "keyvault": KeyVaultModule,
    "secret_discovery": SecretDiscoveryModule,
}

MODULE_REGISTRY = discover_plugin_modules("csaf.modules.azure", _BUILTIN_MODULE_REGISTRY)

__all__ = ["MODULE_REGISTRY"]
