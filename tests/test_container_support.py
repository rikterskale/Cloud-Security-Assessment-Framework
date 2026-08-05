"""Contract tests for the supported hardened container targets."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestContainerSupport(unittest.TestCase):
    def test_linux_image_installs_all_locked_capabilities_as_non_root(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        for token in (
            "python:3.12-slim-bookworm",
            "--require-hashes -r requirements-lock.txt",
            "python -m pip install --no-deps --no-build-isolation .",
            "USER 10001:10001",
            'ENTRYPOINT ["csaf-assess"]',
        ):
            self.assertIn(token, dockerfile)

    def test_windows_image_has_equivalent_locked_runtime(self):
        dockerfile = (ROOT / "Dockerfile.windows").read_text(encoding="utf-8")
        for token in (
            "python:3.12-windowsservercore-ltsc2022",
            "--require-hashes -r requirements-lock.txt",
            "python -m pip install --no-deps --no-build-isolation .",
            "USER ContainerUser",
            'ENTRYPOINT ["csaf-assess.exe"]',
        ):
            self.assertIn(token, dockerfile)

    def test_container_certification_and_platform_boundary_are_documented(self):
        documentation = (ROOT / "docs" / "CONTAINER_SUPPORT.md").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "container.yml").read_text(encoding="utf-8")
        self.assertIn("No one image can provide both native", documentation)
        self.assertIn("--cap-drop ALL", documentation)
        self.assertIn("Linux container capability certification", workflow)
        self.assertIn("Windows container capability certification", workflow)


if __name__ == "__main__":
    unittest.main()
