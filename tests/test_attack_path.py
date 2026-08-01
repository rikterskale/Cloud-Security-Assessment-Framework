"""Read-only IAM attack-path analysis (OFF-FEAT-002)."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from csaf.attack_path import analyze_iam, is_admin, main, privesc_primitives


def user(name, *statements, can_assume=None):
    p = {"name": name, "type": "user", "statements": list(statements)}
    if can_assume:
        p["canAssume"] = can_assume
    return p


def role(name, *statements):
    return {"name": name, "type": "role", "statements": list(statements)}


def allow(actions, resources=("*",)):
    return {"effect": "Allow", "actions": list(actions), "resources": list(resources)}


class TestPrimitives(unittest.TestCase):
    def test_is_admin_wildcards(self):
        self.assertTrue(is_admin(user("a", allow(["*"]))))
        self.assertTrue(is_admin(user("a", allow(["iam:*"]))))
        self.assertFalse(is_admin(user("a", allow(["s3:GetObject"]))))

    def test_privesc_detection_wildcard(self):
        held = privesc_primitives(user("a", allow(["iam:CreateAccessKey"])))
        self.assertIn("iam:CreateAccessKey", held)
        # service wildcard covers privesc primitives
        held2 = privesc_primitives(user("a", allow(["iam:*"])))
        self.assertIn("iam:PassRole", held2)
        self.assertEqual(privesc_primitives(user("a", allow(["s3:GetObject"]))), [])


class TestAnalysis(unittest.TestCase):
    def test_direct_admin(self):
        report = analyze_iam({"principals": [user("root", allow(["*"]))]})
        self.assertEqual(report["adminPrincipals"], ["root"])
        self.assertTrue(any(p["reaches"] == "admin" and p["path"] == ["root"] for p in report["paths"]))

    def test_direct_privesc(self):
        report = analyze_iam({"principals": [user("dev", allow(["iam:AttachUserPolicy"]))]})
        path = next(p for p in report["paths"] if p["source"] == "dev")
        self.assertEqual(path["reaches"], "privesc")
        self.assertEqual(path["severity"], "HIGH")

    def test_assume_chain_to_admin(self):
        snap = {
            "principals": [
                user("alice", allow(["sts:AssumeRole"], ["role/deployer"])),
                role("deployer", allow(["*"])),
            ]
        }
        report = analyze_iam(snap)
        chain = next(p for p in report["paths"] if p["source"] == "alice" and p["reaches"] == "admin")
        self.assertEqual(chain["path"], ["alice", "deployer"])
        self.assertEqual(chain["severity"], "CRITICAL")

    def test_explicit_can_assume_edge(self):
        snap = {
            "principals": [
                user("bob", allow(["s3:GetObject"]), can_assume=["power"]),
                role("power", allow(["iam:PutRolePolicy"])),
            ]
        }
        report = analyze_iam(snap)
        self.assertTrue(
            any(
                p["source"] == "bob" and p["path"] == ["bob", "power"] and p["reaches"] == "privesc"
                for p in report["paths"]
            )
        )

    def test_no_paths_for_readonly(self):
        report = analyze_iam({"principals": [user("ro", allow(["s3:GetObject", "ec2:Describe*"]))]})
        self.assertEqual(report["pathCount"], 0)

    def test_cli_fail_on_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            snap = Path(tmp) / "snap.json"
            snap.write_text(json.dumps({"principals": [user("root", allow(["*"]))]}), encoding="utf-8")
            out = Path(tmp) / "report.json"
            with redirect_stdout(io.StringIO()) as buf:
                rc = main([str(snap), "--out", str(out), "--fail-on-path"])
            self.assertEqual(rc, 1)
            self.assertIn("escalation path", buf.getvalue())
            self.assertEqual(json.loads(out.read_text())["adminPrincipals"], ["root"])
            # clean snapshot exits 0
            snap.write_text(json.dumps({"principals": [user("ro", allow(["s3:GetObject"]))]}), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(snap), "--fail-on-path"]), 0)


if __name__ == "__main__":
    unittest.main()
