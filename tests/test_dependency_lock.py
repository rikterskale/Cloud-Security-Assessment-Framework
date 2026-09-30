"""Check dependency closure across the supported Python and OS environments."""

import unittest
from importlib.metadata import PackageNotFoundError, requires
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parent.parent


class TestDependencyLock(unittest.TestCase):
    def test_conditional_dependencies_are_locked_for_every_supported_environment(self):
        locked = {}
        for line in (ROOT / "requirements-lock.txt").read_text(encoding="utf-8").splitlines():
            if line and not line[0].isspace() and "==" in line and not line.startswith("#"):
                requirement = Requirement(line.rstrip("\\").strip())
                locked[canonicalize_name(requirement.name)] = requirement

        # These distributions supply the Windows and Python 3.10 regression cases.
        for name in ("aiohttp", "keyring", "build"):
            self.assertIsNotNone(requires(name), f"Install the shared lock before testing {name}")

        for name, parent in locked.items():
            try:
                dependencies = requires(name) or []
            except PackageNotFoundError:
                # An OS-specific locked package may not be installed on this host.
                continue
            for python in ("3.10", "3.11", "3.12", "3.13", "3.14"):
                for os_name, platform, system in (
                    ("nt", "win32", "Windows"),
                    ("posix", "linux", "Linux"),
                    ("posix", "darwin", "Darwin"),
                ):
                    environment = default_environment()
                    environment.update(
                        python_version=python,
                        python_full_version=python + ".0",
                        os_name=os_name,
                        sys_platform=platform,
                        platform_system=system,
                    )
                    if parent.marker and not parent.marker.evaluate(environment):
                        continue
                    for text in dependencies:
                        dependency = Requirement(text)
                        active = not dependency.marker or any(
                            dependency.marker.evaluate(dict(environment, extra=extra))
                            for extra in {"", *parent.extras}
                        )
                        if not active:
                            continue
                        with self.subTest(parent=name, dependency=text, python=python, os=platform):
                            key = canonicalize_name(dependency.name)
                            self.assertIn(key, locked, "Hash installs require every active dependency pinned")
                            pin = locked[key]
                            self.assertTrue(not pin.marker or pin.marker.evaluate(environment))
                            version = next(iter(pin.specifier)).version
                            self.assertIn(version, dependency.specifier)
