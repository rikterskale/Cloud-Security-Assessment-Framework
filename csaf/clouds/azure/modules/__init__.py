"""Azure assessment modules."""

from .compute import ComputeModule
from .defender import DefenderModule
from .identity import IdentityModule
from .keyvault import KeyVaultModule
from .monitor import MonitorModule
from .network import NetworkModule
from .sql import SqlModule
from .storage import StorageModule

# Maps catalog ``module`` keys to their implementation.
MODULE_REGISTRY = {
    "identity": IdentityModule,
    "defender": DefenderModule,
    "storage": StorageModule,
    "network": NetworkModule,
    "compute": ComputeModule,
    "monitor": MonitorModule,
    "sql": SqlModule,
    "keyvault": KeyVaultModule,
}

__all__ = ["MODULE_REGISTRY"]
