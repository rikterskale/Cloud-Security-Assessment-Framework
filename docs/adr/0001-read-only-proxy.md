# ADR 0001: enforce read-only provider access

CSAF provider sessions expose only enumerating/read APIs and reject mutating operations. This is a runtime guardrail in addition to least-privilege cloud credentials. The trade-off is that validation stays non-destructive; this is intentional because evidence collection must not change assessed state.
