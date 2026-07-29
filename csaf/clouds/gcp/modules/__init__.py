"""GCP assessment modules."""

from csaf.plugins import discover_plugin_modules

from .compute import ComputeModule
from .identity import IdentityModule
from .kms import KmsModule
from .logging_audit import LoggingModule
from .network import NetworkModule
from .sql import SqlModule
from .storage import StorageModule

# Built-in modules, keyed by catalog ``module``. Third-party distributions can
# add entries via the "csaf.modules.gcp" entry-point group (see csaf/plugins.py).
_BUILTIN_MODULE_REGISTRY = {
    "identity": IdentityModule,
    "storage": StorageModule,
    "network": NetworkModule,
    "compute": ComputeModule,
    "logging": LoggingModule,
    "kms": KmsModule,
    "sql": SqlModule,
}

MODULE_REGISTRY = discover_plugin_modules("csaf.modules.gcp", _BUILTIN_MODULE_REGISTRY)

__all__ = ["MODULE_REGISTRY"]
