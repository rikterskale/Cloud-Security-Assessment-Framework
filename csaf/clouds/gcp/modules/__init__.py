"""GCP assessment modules."""

from .compute import ComputeModule
from .identity import IdentityModule
from .kms import KmsModule
from .logging_audit import LoggingModule
from .network import NetworkModule
from .sql import SqlModule
from .storage import StorageModule

# Maps catalog ``module`` keys to their implementation.
MODULE_REGISTRY = {
    "identity": IdentityModule,
    "storage": StorageModule,
    "network": NetworkModule,
    "compute": ComputeModule,
    "logging": LoggingModule,
    "kms": KmsModule,
    "sql": SqlModule,
}

__all__ = ["MODULE_REGISTRY"]
