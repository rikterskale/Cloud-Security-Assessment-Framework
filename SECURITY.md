# Security Policy

CSAF is a **read-only** cloud security assessment tool. This policy covers
vulnerabilities in CSAF itself — for example, a bug that would let CSAF issue
a mutating cloud API call, bypass an authorization/engagement check, or leak
collected evidence.

## Reporting a vulnerability

Please report suspected security issues privately rather than opening a
public GitHub issue. Use GitHub's private vulnerability reporting for this
repository (**Security** tab → **Report a vulnerability**), which opens a
private advisory visible only to maintainers until a fix is ready.

Include, where possible:

- The affected file(s), function(s), or control ID(s).
- Whether the issue could allow a mutating cloud API call, an authorization
  bypass (engagement scope/window/approval), or exposure of collected
  evidence.
- A minimal reproduction (a synthetic `--self-check` scenario is ideal, since
  it requires no cloud credentials).

## Scope

In scope:

- The `csaf/` framework core and any `csaf/clouds/<cloud>/` provider.
- The CLI (`invoke_assessment.py`) and preflight script (`test_dependencies.py`).
- The read-only guardrails (`ReadOnlyClient`, `ArmSession`, `GcpSession`,
  `ReadOnlyApiClient`) and the engagement authorization checks
  (`csaf/engagement.py`).

Out of scope:

- The reference methodology documents under `reference/` (documentation only,
  not executed code).
- Misconfiguration of the *credentials* an operator supplies to CSAF (e.g.
  using an overly broad IAM policy instead of the recommended `ReadOnlyAccess`
  / `SecurityAudit` policy) — CSAF's guardrail is defense-in-depth, not a
  substitute for least-privilege credentials.

## Disclosure

We ask for a reasonable opportunity to investigate and release a fix before
any public disclosure. There is no fixed SLA at this project's current stage,
but reports will be acknowledged as soon as practical.
