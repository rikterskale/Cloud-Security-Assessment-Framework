# ADR 0002: signed engagements fail closed

Validation and AdversarySimulation require a signed, time-bounded engagement with explicit account and scope authorization. HMAC is retained for existing operator workflows; external Cosign verification is additive for third-party evidence hand-off. Missing or invalid authorization never falls back to a run.
