"""Continuous drift monitoring (OFF-FEAT-006)."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from csaf.monitor import append_history, compute_drift, deliver_webhook, main, should_alert


def rec(fid, sev="HIGH", control="CIS-1.1", resource="r"):
    return {"FindingId": fid, "Severity": sev, "ControlId": control, "ResourceId": resource, "Title": "t"}


class TestDrift(unittest.TestCase):
    def test_new_and_resolved(self):
        prev = [rec("F-1"), rec("F-2", "LOW")]
        curr = [rec("F-2", "LOW"), rec("F-3", "CRITICAL")]
        drift = compute_drift(prev, curr)
        self.assertEqual(drift["counts"], {"new": 1, "resolved": 0, "persisted": 1, "unverified": 1})
        self.assertEqual(drift["new"][0]["FindingId"], "F-3")
        self.assertEqual(drift["unverified"][0]["FindingId"], "F-1")
        self.assertEqual(drift["highestNewSeverity"], "CRITICAL")

    def test_no_change(self):
        same = [rec("F-1"), rec("F-2")]
        drift = compute_drift(same, same)
        self.assertEqual(drift["counts"], {"new": 0, "resolved": 0, "persisted": 2, "unverified": 0})

    def test_should_alert_modes(self):
        drift = compute_drift([rec("F-1")], [rec("F-2")])  # 1 new, 1 resolved
        self.assertTrue(should_alert(drift, "new"))
        self.assertFalse(should_alert(drift, "resolved"))
        self.assertTrue(should_alert(drift, "any"))
        self.assertFalse(should_alert(drift, "none"))
        clean = compute_drift([rec("F-1")], [rec("F-1")])
        self.assertFalse(should_alert(clean, "new"))

    def test_completed_scope_proves_resolution_and_enables_alert(self):
        previous = {**rec("F-1"), "Cloud": "AWS", "AccountId": "1", "Region": "global"}
        result = {"Cloud": "AWS", "AccountId": "1", "Region": "global", "ControlId": "CIS-1.1", "Status": "Pass"}
        drift = compute_drift([previous], [], control_results=[result])
        self.assertEqual(drift["counts"]["resolved"], 1)
        self.assertTrue(should_alert(drift, "resolved"))

    def test_unverified_removal_triggers_any_alert(self):
        drift = compute_drift([rec("F-1")], [])
        self.assertTrue(should_alert(drift, "any"))
        self.assertFalse(should_alert(drift, "resolved"))

    def test_should_alert_rejects_bad_mode(self):
        with self.assertRaises(ValueError):
            should_alert(compute_drift([], []), "bogus")

    def test_history_and_hmac_dry_run_are_network_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "history.jsonl"
            append_history(history, compute_drift([], []))
            self.assertEqual(json.loads(history.read_text())["counts"]["new"], 0)
            result = deliver_webhook("https://example.invalid", {"ok": True}, auth="hmac", secret=b"key", dry_run=True)
            self.assertFalse(result["delivered"])
            self.assertEqual(result["headers"]["X-CSAF-Signature-256"], "<redacted>")


class TestDriftCli(unittest.TestCase):
    def _write(self, tmp, name, records):
        path = Path(tmp) / name
        path.write_text(json.dumps(records), encoding="utf-8")
        return str(path)

    def test_cli_alerts_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            prev = self._write(tmp, "prev.json", [rec("F-1")])
            curr = self._write(tmp, "curr.json", [rec("F-1"), rec("F-9", "CRITICAL")])
            out = str(Path(tmp) / "drift.json")
            with redirect_stdout(io.StringIO()) as buf:
                rc = main(["--previous", prev, "--current", curr, "--alert-on", "new", "--out", out])
            self.assertEqual(rc, 1)  # new finding -> alert -> non-zero
            self.assertIn("ALERT", buf.getvalue())
            self.assertEqual(json.loads(Path(out).read_text())["counts"]["new"], 1)

    def test_cli_no_alert_when_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            same = [rec("F-1")]
            prev = self._write(tmp, "p.json", same)
            curr = self._write(tmp, "c.json", same)
            with redirect_stdout(io.StringIO()) as buf:
                rc = main(["--previous", prev, "--current", curr, "--alert-on", "new"])
            self.assertEqual(rc, 0)
            self.assertIn("[OK]", buf.getvalue())

    def test_cli_uses_matching_technical_evidence_and_rejects_stale_evidence(self):
        previous = {**rec("F-1"), "Cloud": "AWS", "AccountId": "1", "Region": "global"}
        result = {"Cloud": "AWS", "AccountId": "1", "Region": "global", "ControlId": "CIS-1.1", "Status": "Pass"}
        for technical_findings, expected in (([], 1), ([rec("stale")], 0)):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as tmp:
                prev = self._write(tmp, "prev.json", [previous])
                curr = self._write(tmp, "current.json", [])
                self._write(
                    tmp,
                    "technical-report.json",
                    {"Context": {"profile": "Assessment"}, "Findings": technical_findings, "ControlResults": [result]},
                )
                with redirect_stdout(io.StringIO()):
                    code = main(["--previous", prev, "--current", curr, "--alert-on", "resolved"])
                self.assertEqual(code, expected)


if __name__ == "__main__":
    unittest.main()
