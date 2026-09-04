# KSEC — Security Model

Mirrors `specs/06-security-rbac-safety.md`. KSEC's security posture rests
on four layers: **identity**, **authorization**, **scope/policy**, and
**safe execution**. Every execution path passes through all of them.

## 1. Identity and sessions

- Users are stored with **scrypt** password hashes (per-user salt) — never
  plaintext.
- A user acts inside a **session** bound to one of five workspaces:
  `RED_TEAM`, `BLUE_TEAM`, `RESEARCH_OSINT`, `ADVERSARY_SIMULATION`,
  `LEARN_WORK`. Sessions have a lifecycle (active → paused → closed).
- Privileged commands (`--user` + optional `--password`) authenticate the
  acting principal on each invocation.

## 2. Roles and permissions

17 permissions, four seeded roles:

| Role | Description | Representative permissions |
|---|---|---|
| `admin` | Full platform administration | all permissions, incl. `users.manage`, `roles.manage`, `config.manage`, `plugin.manage` |
| `operator` | Run authorized security workflows | `assess.run`, `recon.run`, `tools.list`, `findings.manage`, `evidence.manage`, `cases.manage`, `report.generate`, `intel.use` |
| `auditor` | Read-only audit and review | `audit.read`, `report.generate`, `tools.list` |
| `learner` | Curriculum only | `learning.use` |

Permission checks happen in the service layer (`ctx.rbac.require(...)`),
so bypassing the CLI does not bypass the model.

## 3. Engagements, scope and policy

- Every operational target belongs to an **engagement** with explicit
  **authorization/scope rules** — allow (`example.com`) or deny
  (`10.0.0.0/8`) — matched by exact host, domain or CIDR.
- The policy engine returns one of:
  `ALLOW`, `DENY`, `REQUIRE_CONFIRMATION`, `REQUIRE_PRIVILEGE`,
  `REQUIRE_AUTHORIZATION`. Out-of-scope targets are refused with a handled
  error (`REQUIRE_AUTHORIZATION`) — live tools are never invoked.
- Dry-runs (`--dry-run`) perform the same policy resolution and report it
  per step, so a plan is safe to review before execution.

## 4. Safe execution

- Commands are built as **argv lists** (no shell, no string interpolation
  into a shell) — injection-resistant by construction.
- Adapters run with timeouts via the execution engine; scheduler concurrency
  is bounded.
- Tools are only installed through the controlled installer
  (`ksec tools install`, approval + verification). The env fingerprint
  (`ksec env`) reports tool presence without executing them.

## 5. Audit

- An **append-only audit log** records identity + action + target +
  correlation_id for every significant operation. Audit entries cannot be
  edited or deleted through the application.

## 6. Data integrity

- Evidence is stored with a **SHA-256** digest and can be re-verified
  (`ksec evidence verify`); evidence content is kept intact.
- Backups carry an integrity hash, verified on `ksec backup verify` and
  required before `ksec backup restore` and `ksec update check` rollback
  readiness.
- Findings carry deterministic, versioned risk scores
  (`ksec finding create --risk`).

## 7. Plugins

- Plugins declare capabilities and permissions in a **manifest** and are
  classified by **trust level**
  (`CORE_TRUSTED` → `VERIFIED` → `LOCAL` → `THIRD_PARTY` → `UNTRUSTED` →
  `BLOCKED`).
- Installed plugins load **disabled** and require explicit approval
  (`plugin.manage`); the scheduler re-checks plugin status at execution
  time (a disabled/blocked plugin cannot run even if still registered).
- `ksec plugin check` validates manifest, hash and health. See
  `plugins/README.md`.

## 8. Safety knobs (config `[safety]`)

| Setting | Effect |
|---|---|
| `require_authorization` | Demand a matching engagement scope for every execution |
| `safe_mode` | Extra confirmation / restriction on higher-risk actions |
| `read_only` | Block state-changing operations |

## 9. Failure handling

User errors are **handled KSEC errors** with a stable code +
correlation_id; they never leak stack traces, and `--verbose` exposes the
structured error to the operator. Secrets are redacted from logs
(`ksec.log` never contains passwords or API keys).
