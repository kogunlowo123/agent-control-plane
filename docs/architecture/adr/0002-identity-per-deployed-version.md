# ADR-0002: One fabric identity per deployed version

- Status: Accepted
- Date: 2026-10-14

## Context

agent-identity-fabric binds an identity to a workload (issuer, service
account subject, audience) and an allow list of image digests, and its
registration is immutable. Agent upgrades change the image digest. Options:
register one identity per agent with an empty digest list (weak: any image
running as the service account could attest), update registrations in place
(not supported, and loses the audit meaning of "this build was approved"),
or register a new identity per deployed version.

## Decision

- When a revision with a new version becomes current, the control plane
  registers `spiffe://<td>/agent/<agent-ns>/<deployment>-<version>` bound to
  the deployment's service account and that version's digest, with the
  agent's mandate and the version's scopes.
- The previous identity is recorded as superseded and revoked only after the
  new rollout reports Available, so in-flight pods of the old version keep
  working during a rolling update. Failed revocations are retried on later
  reconciles.
- Scaling or re-applying the same version keeps the identity. Registration
  is idempotent (409 → look up and reuse); a trust-domain mismatch fails the
  apply.

## Consequences

- Credentials prove both who the agent is and which approved build it is.
- Identity count grows with releases; revoked identities remain as audit
  records in the fabric.
