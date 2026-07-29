"""AWS assessment modules."""

from csaf.plugins import discover_plugin_modules

from .compute import ComputeModule
from .identity import IdentityModule
from .kms import KmsModule
from .logging_audit import LoggingModule
from .network import NetworkModule
from .rds import RdsModule
from .s3 import S3Module
from .secrets import SecretsModule

# Built-in modules, keyed by catalog ``module``. Third-party distributions can
# add entries via the "csaf.modules.aws" entry-point group (see csaf/plugins.py).
_BUILTIN_MODULE_REGISTRY = {
    "identity": IdentityModule,
    "s3": S3Module,
    "compute": ComputeModule,
    "network": NetworkModule,
    "logging": LoggingModule,
    "kms": KmsModule,
    "rds": RdsModule,
    "secrets": SecretsModule,
}

MODULE_REGISTRY = discover_plugin_modules("csaf.modules.aws", _BUILTIN_MODULE_REGISTRY)

__all__ = ["MODULE_REGISTRY"]
