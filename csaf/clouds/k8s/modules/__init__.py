"""Kubernetes assessment modules."""

from csaf.plugins import discover_plugin_modules

from .network import NetworkModule
from .pods import PodsModule
from .rbac import RbacModule

# Built-in modules, keyed by catalog ``module``. Third-party distributions can
# add entries via the "csaf.modules.k8s" entry-point group (see csaf/plugins.py).
_BUILTIN_MODULE_REGISTRY = {
    "rbac": RbacModule,
    "pods": PodsModule,
    "network": NetworkModule,
}

MODULE_REGISTRY = discover_plugin_modules("csaf.modules.k8s", _BUILTIN_MODULE_REGISTRY)

__all__ = ["MODULE_REGISTRY"]
