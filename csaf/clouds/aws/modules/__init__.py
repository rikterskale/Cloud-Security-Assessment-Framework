"""AWS assessment modules."""

from .compute import ComputeModule
from .identity import IdentityModule
from .kms import KmsModule
from .logging_audit import LoggingModule
from .network import NetworkModule
from .rds import RdsModule
from .s3 import S3Module
from .secrets import SecretsModule

# Maps catalog ``module`` keys to their implementation.
MODULE_REGISTRY = {
    "identity": IdentityModule,
    "s3": S3Module,
    "compute": ComputeModule,
    "network": NetworkModule,
    "logging": LoggingModule,
    "kms": KmsModule,
    "rds": RdsModule,
    "secrets": SecretsModule,
}

__all__ = ["MODULE_REGISTRY"]
