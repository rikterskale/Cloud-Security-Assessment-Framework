"""Multi-account aggregation + cross-scope analysis (OFF-FEAT-005)."""

import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from csaf.aggregate import aggregate_runs, main


def make_run(root: Path, name, cloud, account, findings):
    run = root / name
    run.mkdir()
    (run / "manifest.json").write_text(
        json.dumps({"Cloud": cloud, "AccountScope": account, "AssessmentProfile": "Assessment"}),
        encoding="utf-8",
    )
    (run / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    return run


def finding(fid, control, sev="HIGH", title="t", resource="r"):
    return {"FindingId": fid, "ControlId": control, "Severity": sev, "Title": title, "ResourceId": resource}


class TestAggregate(unittest.TestCase):
    def test_aggregate_and_cross_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = make_run(root, "a", "AWS", "111", [finding("F1", "CIS-1.1", "CRITICAL"), finding("F2", "CIS-2.1")])
            b = make_run(root, "b", "AWS", "222", [finding("F3", "CIS-1.1", "HIGH")])
            agg = aggregate_runs([a, b])
            self.assertEqual(agg["scopeCount"], 2)
            self.assertEqual(agg["totalFindings"], 3)
            self.assertEqual(agg["severityTotals"]["CRITICAL"], 1)
            # CIS-1.1 fails in both scopes -> cross-scope.
            cross = {c["controlId"]: c for c in agg["crossScopeControls"]}
            self.assertIn("CIS-1.1", cross)
            self.assertEqual(cross["CIS-1.1"]["scopeCount"], 2)
            self.assertNotIn("CIS-2.1", cross)  # only one scope
            # combined findings are tagged with scope.
            self.assertTrue(all("Scope" in f for f in agg["combinedFindings"]))

    def test_missing_files_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty"
            empty.mkdir()
            with self.assertRaises(FileNotFoundError):
                aggregate_runs([empty])

    def test_write_and_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = make_run(root, "a", "AWS", "111", [finding("F1", "CIS-1.1")])
            b = make_run(root, "b", "GCP", "proj", [finding("F2", "CIS-1.1")])
            out = root / "agg"
            with redirect_stdout(io.StringIO()) as buf:
                rc = main([str(a), str(b), "--out", str(out)])
            self.assertEqual(rc, 0)
            self.assertIn("Aggregated 2 scope", buf.getvalue())
            data = json.loads((out / "aggregate.json").read_text())
            self.assertEqual(data["scopeCount"], 2)
            rows = list(csv.reader((out / "aggregate.csv").read_text().splitlines()))
            self.assertEqual(rows[0][0], "Scope")
            self.assertEqual(len(rows), 3)  # header + 2 scopes


if __name__ == "__main__":
    unittest.main()
