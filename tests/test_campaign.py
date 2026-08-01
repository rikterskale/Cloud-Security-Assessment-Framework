"""Signed, replayable assessment campaigns (OFF-FEAT-001)."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from csaf.campaign import (
    build_campaign,
    main,
    sign_campaign,
    to_run_config,
    validate_campaign,
    verify_campaign,
)

KEY = b"campaign-key"


class TestCampaignModel(unittest.TestCase):
    def test_build_and_validate(self):
        c = build_campaign(campaign_id="ENG-1", cloud="aws", regions=["us-east-1"], self_check=True, export=["sarif"])
        self.assertEqual(validate_campaign(c), [])
        self.assertTrue(c["selfCheck"])
        self.assertEqual(c["export"], ["sarif"])

    def test_build_rejects_bad_values(self):
        with self.assertRaises(ValueError):
            build_campaign(campaign_id="x", cloud="oracle")
        with self.assertRaises(ValueError):
            build_campaign(campaign_id="x", export=["pdf"])

    def test_sign_and_verify_roundtrip(self):
        c = sign_campaign(build_campaign(campaign_id="ENG-1"), KEY)
        self.assertTrue(verify_campaign(c, KEY))
        self.assertFalse(verify_campaign(c, b"other-key"))

    def test_tamper_after_signing_fails(self):
        c = sign_campaign(build_campaign(campaign_id="ENG-1", profile="Assessment"), KEY)
        c["profile"] = "AdversarySimulation"  # silent edit after signing
        self.assertFalse(verify_campaign(c, KEY))

    def test_to_run_config(self):
        c = build_campaign(campaign_id="ENG-1", cloud="gcp", profile="Inventory", self_check=True, export=["oscal"])
        config = to_run_config(c, output_dir="out", log_level="ERROR")
        self.assertEqual(config.cloud, "gcp")
        self.assertEqual(config.profile, "Inventory")
        self.assertTrue(config.self_check)
        self.assertEqual(config.export, ["oscal"])
        self.assertEqual(config.output_dir, "out")


class TestCampaignCli(unittest.TestCase):
    def test_create_sign_verify_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            campaign_path = Path(tmp) / "c.json"
            key_file = Path(tmp) / "k.key"
            key_file.write_bytes(KEY)

            with redirect_stdout(io.StringIO()):
                rc = main(
                    [
                        "create",
                        str(campaign_path),
                        "--campaign-id",
                        "ENG-42",
                        "--self-check",
                        "--key-file",
                        str(key_file),
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertIn("signature", json.loads(campaign_path.read_text()))

            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["verify", str(campaign_path), "--key-file", str(key_file)]), 0)

            # Reproducible offline run from the signed campaign.
            out = Path(tmp) / "runs"
            with redirect_stdout(io.StringIO()) as buf:
                rc = main(
                    [
                        "run",
                        str(campaign_path),
                        "--key-file",
                        str(key_file),
                        "--output-dir",
                        str(out),
                        "--log-level",
                        "ERROR",
                    ]
                )
            # self-check completes with exit 0 or 2 (partial coverage is normal).
            self.assertIn(rc, (0, 2))
            self.assertIn("Output written", buf.getvalue())
            run_dirs = [p for p in out.iterdir() if p.is_dir()]
            self.assertEqual(len(run_dirs), 1)
            self.assertTrue((run_dirs[0] / "manifest.json").is_file())

    def test_run_refuses_tampered_campaign(self):
        with tempfile.TemporaryDirectory() as tmp:
            campaign_path = Path(tmp) / "c.json"
            key_file = Path(tmp) / "k.key"
            key_file.write_bytes(KEY)
            signed = sign_campaign(build_campaign(campaign_id="ENG-9", self_check=True), KEY)
            signed["profile"] = "AdversarySimulation"  # tamper
            campaign_path.write_text(json.dumps(signed), encoding="utf-8")
            with redirect_stdout(io.StringIO()) as buf:
                rc = main(
                    ["run", str(campaign_path), "--key-file", str(key_file), "--output-dir", str(Path(tmp) / "o")]
                )
            self.assertEqual(rc, 1)
            self.assertIn("does not verify", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
