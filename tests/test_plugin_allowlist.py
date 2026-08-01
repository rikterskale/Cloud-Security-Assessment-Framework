"""Optional plugin allowlist / trust model (roadmap #13)."""

import os
import unittest
from unittest import mock

from csaf.plugins import ALLOWLIST_ENV, discover_plugin_modules


class FakeEntryPoint:
    def __init__(self, name, value, loaded=None):
        self.name = name
        self.value = value
        self._loaded = loaded

    def load(self):
        return self._loaded


class Sentinel:
    pass


class TestPluginAllowlist(unittest.TestCase):
    def _discover(self, entry_points, env):
        with (
            mock.patch("csaf.plugins.entry_points", return_value=entry_points),
            mock.patch.dict(os.environ, env, clear=False),
        ):
            return discover_plugin_modules("csaf.modules.aws", {"identity": Sentinel})

    def test_no_allowlist_loads_all(self):
        # Ensure the env var is unset for this case.
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ALLOWLIST_ENV, None)
            registry = self._discover([FakeEntryPoint("extra", "p:M", loaded=Sentinel)], {})
        self.assertIn("extra", registry)

    def test_allowlist_permits_named_plugin(self):
        registry = self._discover([FakeEntryPoint("extra", "p:M", loaded=Sentinel)], {ALLOWLIST_ENV: "extra,other"})
        self.assertIn("extra", registry)

    def test_allowlist_blocks_unlisted_plugin(self):
        with self.assertWarns(UserWarning):
            registry = self._discover(
                [FakeEntryPoint("sneaky", "p:M", loaded=Sentinel)], {ALLOWLIST_ENV: "trusted_only"}
            )
        self.assertNotIn("sneaky", registry)
        self.assertIn("identity", registry)  # built-ins always present

    def test_empty_allowlist_blocks_everything(self):
        with self.assertWarns(UserWarning):
            registry = self._discover([FakeEntryPoint("extra", "p:M", loaded=Sentinel)], {ALLOWLIST_ENV: ""})
        self.assertNotIn("extra", registry)
        self.assertEqual(set(registry), {"identity"})


if __name__ == "__main__":
    unittest.main()
