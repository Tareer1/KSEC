# Security Policy

KSEC is security software: it orchestrates offensive and defensive tools, so
its own security posture matters. Authorization, scope, RBAC and audit
controls are enforced by the core, never by the UI alone.

## Supported versions

Only the latest release is supported. KSEC is pre-1.0; expect rapid change.

## Reporting a vulnerability

Do **not** open a public issue for security vulnerabilities. Report them
privately to the maintainers by opening a draft security advisory on GitHub
or contacting the repository maintainers directly.

Please include:

- The affected component and version
- A description of the issue and its impact
- Reproduction steps (do not include real credentials or third-party targets)
- Suggested fix if you have one

## Security expectations

- KSEC is intended for **authorized** security work only.
- Out-of-scope targets are blocked by the policy engine.
- Secrets are never logged; logs are redacted.
- Evidence is hash-protected and verified on demand.
- Audit records are append-only.

## Safe development rules

- Never bypass authorization, scope, RBAC or audit controls.
- Never execute unvalidated shell strings; commands are built as argument lists.
- Never install software from untrusted sources without approval and verification.
- Never store secrets in the repository.