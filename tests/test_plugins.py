"""Plugin module discovery: merging built-ins with installed entry points."""

import unittest
from unittest import mock

from csaf.plugins import discover_plugin_modules


class FakeEntryPoint:
    """Stand-in for importlib.metadata.EntryPoint (name/value/load())."""

    def __init__(self, name, value, loaded=None, load_error=None):
        self.name = name
        self.value = value
        self._loaded = loaded
        self._load_error = load_error

    def load(self):
        if self._load_error is not None:
            raise self._load_error
        return self._loaded


class Sentinel:
    """Distinct object used as a stand-in "module class" in tests."""


class TestDiscoverPluginModules(unittest.TestCase):
    def test_no_entry_points_returns_builtins_unchanged(self):
        with mock.patch("csaf.plugins.entry_points", return_value=[]):
            registry = discover_plugin_modules("csaf.modules.aws", {"identity": Sentinel})
        self.assertEqual(registry, {"identity": Sentinel})

    def test_new_plugin_module_is_added(self):
        plugin = FakeEntryPoint("extra", "pkg.mod:ExtraModule", loaded=Sentinel)
        with mock.patch("csaf.plugins.entry_points", return_value=[plugin]):
            registry = discover_plugin_modules("csaf.modules.aws", {"identity": Sentinel})
        self.assertIn("extra", registry)
        self.assertIs(registry["extra"], Sentinel)
        self.assertIn("identity", registry)  # built-in untouched

    def test_builtin_wins_on_name_collision(self):
        builtin_marker = Sentinel()
        plugin_marker = Sentinel()
        plugin = FakeEntryPoint("identity", "pkg.mod:EvilIdentityModule", loaded=plugin_marker)
        with mock.patch("csaf.plugins.entry_points", return_value=[plugin]):
            with self.assertWarns(UserWarning):
                registry = discover_plugin_modules("csaf.modules.aws", {"identity": builtin_marker})
        self.assertIs(registry["identity"], builtin_marker)  # not overwritten

    def test_broken_plugin_load_does_not_break_other_plugins_or_builtins(self):
        good = FakeEntryPoint("good", "pkg.mod:Good", loaded=Sentinel)
        bad = FakeEntryPoint("bad", "pkg.mod:Bad", load_error=ImportError("no such module"))
        with mock.patch("csaf.plugins.entry_points", return_value=[bad, good]):
            with self.assertWarns(UserWarning):
                registry = discover_plugin_modules("csaf.modules.aws", {"identity": Sentinel})
        self.assertIn("good", registry)
        self.assertNotIn("bad", registry)
        self.assertIn("identity", registry)

    def test_entry_points_lookup_failure_falls_back_to_builtins(self):
        with mock.patch("csaf.plugins.entry_points", side_effect=RuntimeError("corrupt metadata")):
            with self.assertWarns(UserWarning):
                registry = discover_plugin_modules("csaf.modules.aws", {"identity": Sentinel})
        self.assertEqual(registry, {"identity": Sentinel})

    def test_real_registries_unaffected_with_no_plugins_installed(self):
        # Integration-style check against the actual built-in registries: no
        # third-party package declares these groups in this environment, so
        # every built-in module must still be present and nothing extra added.
        import csaf.clouds.aws.modules as aws_modules
        import csaf.clouds.azure.modules as azure_modules
        import csaf.clouds.gcp.modules as gcp_modules

        self.assertEqual(set(aws_modules.MODULE_REGISTRY), set(aws_modules._BUILTIN_MODULE_REGISTRY))
        self.assertEqual(set(azure_modules.MODULE_REGISTRY), set(azure_modules._BUILTIN_MODULE_REGISTRY))
        self.assertEqual(set(gcp_modules.MODULE_REGISTRY), set(gcp_modules._BUILTIN_MODULE_REGISTRY))


if __name__ == "__main__":
    unittest.main()
