"""Read-only IAM attack-path / privilege-escalation analysis (OFF-FEAT-002).

Given an IAM **snapshot** — principals (users/roles), their allow statements,
and who may assume which role — this module reasons about privilege-escalation
*paths* purely as graph analysis. It answers "who can reach administrative
privilege, and how" from configuration alone. It performs **no cloud calls and
no exploitation**; it only reads a snapshot the operator already collected with
read-only permissions and reports potential paths, exactly like the rest of
CSAF's posture assessment.

Snapshot shape (JSON)::

    {
      "principals": [
        {
          "name": "alice",
          "type": "user",                     # "user" or "role"
          "statements": [
            {"effect": "Allow", "actions": ["sts:AssumeRole"], "resources": ["role/deployer"]}
          ],
          "canAssume": ["deployer"]            # optional explicit assume edges
        },
        {"name": "deployer", "type": "role",
         "statements": [{"effect": "Allow", "actions": ["*"], "resources": ["*"]}]}
      ]
    }

The analysis is intentionally conservative and well-documented: it flags
administrative principals, a small set of widely-recognized privilege-escalation
IAM primitives, and assume-role chains that reach either. It is an aid for
defenders to prioritize least-privilege work, not an exploitation tool.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from pathlib import Path

# Widely-recognized IAM privilege-escalation primitives (defensive reference).
# Holding any of these (Allow) lets a principal grant itself more privilege.
PRIVESC_ACTIONS = {
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:CreateAccessKey",
    "iam:UpdateLoginProfile",
    "iam:CreateLoginProfile",
    "iam:UpdateAssumeRolePolicy",
    "iam:AddUserToGroup",
    "iam:PassRole",
}

ADMIN_ACTIONS = {"*", "*:*", "iam:*"}


def _action_matches(granted: str, needed: str) -> bool:
    """Wildcard-aware IAM action match (supports '*' and 'service:*')."""
    granted = granted.strip()
    if granted in ("*", "*:*"):
        return True
    if granted.endswith(":*"):
        return needed.lower().startswith(granted[:-1].lower())
    return granted.lower() == needed.lower()


def _allow_statements(principal: dict) -> list[dict]:
    return [s for s in principal.get("statements", []) if str(s.get("effect", "Allow")).lower() == "allow"]


def _granted_actions(principal: dict) -> list[str]:
    actions = []
    for statement in _allow_statements(principal):
        actions.extend(statement.get("actions", []))
    return actions


def is_admin(principal: dict) -> bool:
    """True when the principal has an Allow of a full-admin action on any resource."""
    for statement in _allow_statements(principal):
        actions = [a.strip() for a in statement.get("actions", [])]
        if any(a in ADMIN_ACTIONS for a in actions):
            return True
    return False


def privesc_primitives(principal: dict) -> list[str]:
    """Return the privilege-escalation primitives this principal holds."""
    granted = _granted_actions(principal)
    held = sorted({p for p in PRIVESC_ACTIONS if any(_action_matches(g, p) for g in granted)})
    return held


def _assume_edges(principals: dict[str, dict]) -> dict[str, set[str]]:
    """Build principal -> set(role) assume-role edges."""
    role_names = {name for name, p in principals.items() if p.get("type") == "role"}
    edges: dict[str, set[str]] = {name: set() for name in principals}
    for name, principal in principals.items():
        # Explicit edges.
        for target in principal.get("canAssume", []):
            if target in principals:
                edges[name].add(target)
        # Derived from sts:AssumeRole statements.
        for statement in _allow_statements(principal):
            actions = statement.get("actions", [])
            if not any(_action_matches(a, "sts:AssumeRole") for a in actions):
                continue
            resources = statement.get("resources", [])
            for resource in resources:
                if resource == "*":
                    edges[name].update(role_names - {name})
                else:
                    # Match a role by suffix (e.g. "role/deployer" or "deployer").
                    target = resource.split("/")[-1]
                    if target in role_names:
                        edges[name].add(target)
    return edges


def analyze_iam(snapshot: dict) -> dict:
    """Return an attack-path report from an IAM snapshot."""
    principals = {p["name"]: p for p in snapshot.get("principals", [])}
    edges = _assume_edges(principals)

    paths: list[dict] = []

    def record(source: str, chain: list[str], reaches: str, severity: str, detail: str) -> None:
        paths.append({"source": source, "path": chain, "reaches": reaches, "severity": severity, "detail": detail})

    for source, principal in principals.items():
        # Direct: the principal itself is admin or holds a privesc primitive.
        if is_admin(principal):
            record(source, [source], "admin", "CRITICAL", f"{source} already holds administrative privilege")
        else:
            held = privesc_primitives(principal)
            if held:
                record(source, [source], "privesc", "HIGH", f"{source} holds privilege-escalation actions: {held}")

        # Assume-role chains (BFS) reaching admin / privesc.
        visited = {source}
        queue: deque[list[str]] = deque([[source]])
        while queue:
            chain = queue.popleft()
            for target in sorted(edges.get(chain[-1], set())):
                if target in visited:
                    continue
                visited.add(target)
                new_chain = chain + [target]
                target_principal = principals[target]
                if is_admin(target_principal):
                    record(
                        source,
                        new_chain,
                        "admin",
                        "CRITICAL",
                        f"{source} can assume its way to admin role {target}",
                    )
                else:
                    held = privesc_primitives(target_principal)
                    if held:
                        record(
                            source,
                            new_chain,
                            "privesc",
                            "HIGH",
                            f"{source} can assume {target}, which holds privilege-escalation actions: {held}",
                        )
                queue.append(new_chain)

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    paths.sort(key=lambda p: (severity_rank.get(p["severity"], 9), len(p["path"]), p["source"]))

    return {
        "principalCount": len(principals),
        "adminPrincipals": sorted(n for n, p in principals.items() if is_admin(p)),
        "pathCount": len(paths),
        "paths": paths,
        "note": "Read-only privilege-escalation analysis over a provided IAM snapshot. No cloud calls performed.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze read-only IAM snapshot for privilege-escalation paths (no cloud calls)."
    )
    parser.add_argument("snapshot", help="Path to an IAM snapshot JSON file.")
    parser.add_argument("--out", default=None, help="Optional path to write the attack-path report JSON.")
    parser.add_argument("--fail-on-path", action="store_true", help="Exit non-zero when any path is found.")
    args = parser.parse_args(argv)

    snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    report = analyze_iam(snapshot)
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"{report['pathCount']} escalation path(s) across {report['principalCount']} principal(s).")
    for path in report["paths"]:
        print(f"  [{path['severity']}] {' -> '.join(path['path'])} :: {path['detail']}")
    return 1 if (args.fail_on_path and report["pathCount"]) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
