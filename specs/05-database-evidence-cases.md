Boss, **PDF 5** KSEC ka **Database + Shared State + Evidence + Case Management** hai. Ismein multi-terminal shared data, exact entities/relationships, evidence chain-of-custody, cases, findings, migrations, retention, integrity aur recovery ko implementation-ready level par lock kiya gaya hai.

# KSEC — DATABASE, SHARED STATE, EVIDENCE & CASE MANAGEMENT

**Version:** 1.0
**Status:** Build-Ready / Final Specification
**Platform:** Kali Linux
**Architecture:** Single KSEC Core + Multi-Terminal Shared State
**AI Dependency:** None

---

# 1. PURPOSE

This document defines the complete persistence, database, shared-state, evidence, finding, case-management, and data-integrity architecture of KSEC.

The system must support:

* One KSEC installation
* One shared backend/core
* One user operating five terminals simultaneously
* Up to five people using separate terminals/workspaces
* Independent sessions
* Shared authorized engagement data
* Role-aware data access
* Concurrent jobs
* Evidence preservation
* Finding management
* Case management
* Auditability
* Reproducibility
* Backup and recovery
* Offline operation
* Database migrations
* Data retention
* Privacy controls

---

# 2. MASTER DATA PRINCIPLE

KSEC must maintain one authoritative shared state.

```text
                    KSEC CORE
                       │
                SHARED DATABASE
                       │
       ┌───────────────┼───────────────┐
       ↓               ↓               ↓
   TERMINAL 1      TERMINAL 2      TERMINAL 3
   RED TEAM        BLUE TEAM       RESEARCH
       │               │               │
       ↓               ↓               ↓
   TERMINAL 4      TERMINAL 5
   ADVERSARY       LEARN + WORK
```

All sessions operate against the same authoritative data model while maintaining session-specific state.

---

# 3. DATA OWNERSHIP PRINCIPLE

Every object must have explicit ownership and access context.

Relevant dimensions:

```text
User
Role
Workspace
Session
Engagement
Case
Asset
Finding
Evidence
Job
Workflow
```

KSEC must never assume that shared data means unrestricted access.

---

# 4. DATABASE ARCHITECTURE

The database layer must support:

* Transactional writes
* Referential integrity
* Unique identifiers
* Foreign keys
* Constraints
* Indexing
* Transactions
* Migrations
* Backups
* Recovery
* Concurrent access
* Auditability

The implementation may use an appropriate relational database architecture suitable for local Kali deployment.

The logical schema defined in this document is authoritative regardless of the selected database engine.

---

# 5. IDENTIFIER STANDARD

Every persistent entity must have a globally unique immutable identifier.

Recommended format:

```text
UUID
```

Example:

```text
550e8400-e29b-41d4-a716-446655440000
```

IDs must never be reused.

---

# 6. TIMESTAMP STANDARD

All persistent timestamps must use a consistent machine-readable format.

Recommended:

```text
UTC
ISO 8601
```

The UI may display timestamps in local time.

Original timestamps must never be overwritten.

---

# 7. CORE ENTITY MODEL

The minimum authoritative data model contains:

```text
Users
Roles
Permissions
Workspaces
Sessions
SessionRoles
Engagements
Authorizations
Targets
Assets
Services
Findings
Evidence
Cases
Events
Alerts
IOCs
ThreatActors
Campaigns
TTPs
Workflows
Jobs
ToolRuns
Reports
Controls
Policies
AuditLogs
Notifications
Plugins
Integrations
Backups
Configs
LearningProfiles
Lessons
Exercises
LearningProgress
Assessments
```

---

# 8. USER ENTITY

Required fields:

```text
user_id
username
display_name
status
role_id
created_at
updated_at
last_login_at
```

Optional:

```text
email
preferences
timezone
language
```

Passwords and authentication secrets must never be stored as plaintext.

---

# 9. ROLE ENTITY

Roles define permissions.

Required operational roles include:

```text
ADMIN
RED_TEAM
BLUE_TEAM
RESEARCH
ADVERSARY_SIMULATION
LEARN_WORK
AUDITOR
```

A user may have multiple permitted roles where policy allows.

Workspace access and operational permissions must still be evaluated independently.

---

# 10. PERMISSION ENTITY

Permissions must be granular.

Examples:

```text
asset.read
asset.create
finding.read
finding.create
evidence.read
evidence.create
case.create
workflow.execute
tool.execute
tool.install
report.create
learning.access
admin.configure
```

High-risk actions require additional policy evaluation.

---

# 11. WORKSPACE ENTITY

Required workspaces:

```text
RED_TEAM
BLUE_TEAM
RESEARCH_OSINT
ADVERSARY_SIMULATION
LEARN_WORK
```

Workspace data:

```text
workspace_id
name
type
owner
policy
status
created_at
updated_at
```

---

# 12. SESSION ENTITY

Every terminal interaction receives a session.

Fields:

```text
session_id
user_id
workspace_id
terminal_id
status
created_at
started_at
last_activity_at
closed_at
configuration
```

Session states:

```text
CREATED
INITIALIZING
READY
ACTIVE
PAUSED
DISCONNECTED
RECOVERING
CLOSED
FAILED
```

---

# 13. TERMINAL ENTITY

Each logical KSEC terminal must have a unique identity.

Example:

```text
terminal_id
terminal_name
workspace
assigned_user
status
last_seen
```

Default terminal assignments:

```text
Terminal 1 → Red Team
Terminal 2 → Blue Team
Terminal 3 → Research
Terminal 4 → Adversary Simulation
Terminal 5 → Learn + Work
```

Assignments must remain configurable.

---

# 14. MULTI-TERMINAL DATA MODEL

One user may have:

```text
User A
 ├── Session 1 → Red Team
 ├── Session 2 → Blue Team
 ├── Session 3 → Research
 ├── Session 4 → Adversary Simulation
 └── Session 5 → Learn + Work
```

Five users may instead have:

```text
User A → Terminal 1
User B → Terminal 2
User C → Terminal 3
User D → Terminal 4
User E → Terminal 5
```

Both models must use the same KSEC core.

---

# 15. ENGAGEMENT ENTITY

An engagement represents an authorized security activity.

Fields:

```text
engagement_id
name
description
owner
status
start_time
end_time
authorization_id
scope_definition
rules_of_engagement
environment_snapshot
created_at
updated_at
```

Status:

```text
DRAFT
AUTHORIZED
ACTIVE
PAUSED
COMPLETED
CANCELLED
CLOSED
```

---

# 16. AUTHORIZATION ENTITY

Authorization records must be separate from targets.

Fields:

```text
authorization_id
engagement_id
authority_type
authorized_by
authorization_reference
valid_from
valid_until
scope
restrictions
status
created_at
```

This prevents a target from being considered authorized merely because it exists in the database.

---

# 17. TARGET ENTITY

A target is an object defined within an engagement.

Possible target types:

```text
IP
CIDR
DOMAIN
URL
HOST
DEVICE
APPLICATION
API
CLOUD_ASSET
CONTAINER
LAB_TARGET
```

Fields:

```text
target_id
engagement_id
type
value
scope_status
owner
criticality
created_at
updated_at
```

---

# 18. ASSET ENTITY

Assets represent normalized discovered or known infrastructure.

Fields:

```text
asset_id
asset_type
canonical_identifier
hostname
ip
domain
owner
criticality
environment
source
confidence
first_seen
last_seen
status
```

Asset types may include:

```text
HOST
IP
DOMAIN
SUBDOMAIN
URL
SERVICE
APPLICATION
DEVICE
CLOUD_RESOURCE
CONTAINER
KUBERNETES_RESOURCE
WIRELESS_DEVICE
```

---

# 19. ASSET RELATIONSHIPS

KSEC must support relationships such as:

```text
Domain
 ↓
Subdomain
 ↓
IP
 ↓
Host
 ↓
Port
 ↓
Service
 ↓
Application
 ↓
Finding
```

Relationships may include:

```text
RESOLVES_TO
HOSTS
RUNS
BELONGS_TO
DEPENDS_ON
USES
RELATED_TO
DISCOVERED_BY
```

---

# 20. SERVICE ENTITY

Fields:

```text
service_id
asset_id
protocol
port
service_name
product
version
banner
state
source
confidence
first_seen
last_seen
```

Services may be discovered by multiple tools.

Duplicate observations must be correlated.

---

# 21. FINDING ENTITY

A finding represents a security observation requiring analysis.

Fields:

```text
finding_id
engagement_id
asset_id
title
description
category
severity
risk_score
confidence
status
source
first_detected
last_confirmed
created_by
created_at
updated_at
```

---

# 22. FINDING STATUS

Supported states:

```text
NEW
TRIAGED
CONFIRMED
FALSE_POSITIVE
ACCEPTED_RISK
REMEDIATION_REQUIRED
REMEDIATION_IN_PROGRESS
REMEDIATED
VERIFIED
CLOSED
```

---

# 23. FINDING SEVERITY

Minimum values:

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

Severity and risk score must remain separate concepts.

---

# 24. FINDING CONFIDENCE

Confidence values:

```text
VERY_LOW
LOW
MEDIUM
HIGH
VERY_HIGH
```

Confidence reflects evidence quality and certainty, not impact.

---

# 25. FINDING SOURCE PROVENANCE

Every finding must identify:

```text
Source Tool
Tool Version
Adapter
Parser
Job
Session
Workflow
Target
Timestamp
Evidence References
```

---

# 26. EVIDENCE ENTITY

Evidence is immutable or append-only by default.

Fields:

```text
evidence_id
engagement_id
case_id
finding_id
source_type
source_identifier
tool_run_id
session_id
job_id
target_id
captured_at
storage_reference
content_hash
hash_algorithm
classification
chain_status
created_by
```

---

# 27. EVIDENCE TYPES

Examples:

```text
RAW_TOOL_OUTPUT
SCREENSHOT
LOG
NETWORK_OBSERVATION
FILE
COMMAND_OUTPUT
CONFIGURATION
TIMELINE_EVENT
DOCUMENT
HASH
IOC
REPORT_EXCERPT
```

---

# 28. EVIDENCE IMMUTABILITY

Once evidence is finalized:

* Content must not be silently modified.
* Hash must remain verifiable.
* Original timestamp must remain.
* Provenance must remain.
* Chain-of-custody events must be recorded.

Corrections must create new records rather than silently replacing the original.

---

# 29. EVIDENCE HASHING

Evidence should be hashed using a supported cryptographic hash algorithm.

Example:

```text
SHA-256
```

Stored information:

```text
hash_algorithm
content_hash
```

KSEC must support future hash algorithms through versioned configuration.

---

# 30. CHAIN OF CUSTODY

Every evidence transfer or state change must be recorded.

Example:

```text
CAPTURED
 ↓
IMPORTED
 ↓
VERIFIED
 ↓
REVIEWED
 ↓
REFERENCED
 ↓
ARCHIVED
```

Each event contains:

```text
event_id
evidence_id
actor
timestamp
action
previous_state
new_state
reason
metadata
```

---

# 31. EVIDENCE VERIFICATION

Command:

```bash
ksec evidence verify EVIDENCE_ID
```

Output:

```text
Evidence:
VERIFIED

Hash:
MATCH

Provenance:
VALID

Chain:
INTACT
```

Mismatch:

```text
INTEGRITY FAILURE
```

must trigger a high-priority audit event.

---

# 32. CASE ENTITY

Cases group related security investigations.

Fields:

```text
case_id
case_number
title
description
type
priority
status
owner
created_at
updated_at
closed_at
```

---

# 33. CASE TYPES

Examples:

```text
SECURITY_ASSESSMENT
INCIDENT
DFIR
THREAT_INTELLIGENCE
VULNERABILITY
DETECTION_VALIDATION
ADVERSARY_SIMULATION
RESEARCH
LEARNING_EXERCISE
```

---

# 34. CASE STATUS

```text
OPEN
INVESTIGATING
CONTAINMENT
REMEDIATION
VERIFICATION
RESOLVED
CLOSED
ARCHIVED
```

---

# 35. CASE RELATIONSHIPS

A case may contain:

```text
Assets
Findings
Evidence
Events
Alerts
IOCs
Threat Actors
Campaigns
Reports
Tasks
Notes
Remediation
Verification
```

Relationship example:

```text
Case
 ├── Asset
 ├── Finding
 │    ├── Evidence
 │    └── Risk
 ├── IOC
 ├── Timeline Events
 └── Report
```

---

# 36. CASE NOTES

Notes must include:

```text
note_id
case_id
author
timestamp
content
classification
```

Existing notes must not be silently overwritten.

Edit history must be retained where audit policy requires it.

---

# 37. REMEDIATION ENTITY

Fields:

```text
remediation_id
finding_id
description
owner
priority
status
due_date
created_at
updated_at
```

Statuses:

```text
OPEN
IN_PROGRESS
COMPLETED
VERIFIED
REJECTED
```

---

# 38. REMEDIATION VERIFICATION

Verification should create a separate verification record.

```text
Original Finding
 ↓
Remediation
 ↓
Retest
 ↓
Evidence
 ↓
Verification
 ↓
Finding Status Update
```

KSEC must not mark a finding remediated merely because someone says it was fixed.

---

# 39. IOC ENTITY

Fields:

```text
ioc_id
type
value
normalized_value
confidence
source
first_seen
last_seen
status
created_at
```

Types:

```text
IP
DOMAIN
URL
HASH
EMAIL
USERNAME
FILE
PROCESS
CERTIFICATE
OTHER
```

---

# 40. THREAT ACTOR ENTITY

Threat actors are intelligence objects, not operator roles.

Fields:

```text
threat_actor_id
name
aliases
description
confidence
sources
created_at
updated_at
```

Threat actor profiles must remain separate from the Adversary Simulation operator workspace.

---

# 41. CAMPAIGN ENTITY

Fields:

```text
campaign_id
name
description
threat_actor_id
start_date
end_date
confidence
sources
```

---

# 42. TTP ENTITY

Fields:

```text
ttp_id
framework
technique_id
name
description
tactic
source
```

MITRE ATT&CK mappings must be stored as framework mappings rather than hardcoded assumptions.

---

# 43. TOOL RUN ENTITY

Every KSEC-controlled tool execution receives a persistent tool-run record.

Fields:

```text
tool_run_id
job_id
session_id
tool_id
adapter_id
tool_version
parser_id
parser_version
target_id
start_time
end_time
exit_code
status
raw_output_reference
```

---

# 44. JOB ENTITY

Fields:

```text
job_id
session_id
workspace_id
workflow_id
type
priority
status
created_at
started_at
completed_at
retry_count
resource_profile
```

Job state:

```text
QUEUED
VALIDATING
READY
RUNNING
PAUSED
CANCELLING
CANCELLED
COMPLETED
FAILED
RECOVERING
RETRYING
```

---

# 45. WORKFLOW ENTITY

Fields:

```text
workflow_id
name
version
owner
definition
status
created_at
updated_at
```

Workflow versions must be immutable once executed in an engagement.

---

# 46. REPORT ENTITY

Fields:

```text
report_id
engagement_id
case_id
report_type
version
status
created_by
created_at
generated_at
content_reference
integrity_hash
```

Reports must reference the exact findings/evidence used.

---

# 47. EVENT ENTITY

Events represent state changes or notable system/security events.

Fields:

```text
event_id
event_type
source
session_id
job_id
engagement_id
asset_id
case_id
timestamp
severity
payload
```

---

# 48. ALERT ENTITY

Alerts represent actionable security signals.

Fields:

```text
alert_id
source
type
severity
asset_id
finding_id
case_id
status
created_at
acknowledged_at
resolved_at
```

---

# 49. AUDIT LOG ENTITY

Audit records must be append-only.

Fields:

```text
audit_id
timestamp
actor
session_id
workspace_id
action
resource_type
resource_id
result
reason
source
metadata
```

Examples:

```text
USER_LOGIN
SCOPE_CREATED
AUTHORIZATION_APPROVED
TOOL_EXECUTED
TOOL_INSTALLED
EVIDENCE_CREATED
EVIDENCE_ACCESSED
FINDING_UPDATED
REPORT_GENERATED
POLICY_DENIED
```

---

# 50. SHARED STATE ENGINE

The Shared State Engine provides the authoritative state visible across sessions.

Example:

```text
Red Team discovers Asset A
        ↓
Shared State
        ↓
Blue Team sees Asset A
        ↓
Research adds intelligence
        ↓
Shared State
        ↓
Red Team sees enrichment
```

Access remains governed by RBAC and workspace policy.

---

# 51. EVENT-DRIVEN STATE UPDATE

State changes should generate events.

Example:

```text
Finding Created
 ↓
Event Published
 ↓
Shared State Updated
 ↓
Interested Sessions Notified
```

Sessions should not rely solely on polling.

---

# 52. CONCURRENCY CONTROL

Concurrent sessions may modify shared objects.

KSEC must use appropriate concurrency controls.

Examples:

* Transactions
* Row/version locking
* Optimistic concurrency
* Job leases
* Unique constraints
* Version numbers

---

# 53. OBJECT VERSIONING

Important mutable objects should contain a version field.

Example:

```text
finding_version = 7
```

An update based on an outdated version must be rejected or reconciled.

Example:

```text
Expected Version: 7
Actual Version: 8

RESULT:
CONFLICT
```

No silent overwrites.

---

# 54. JOB LEASES

Running jobs must have ownership/lease information.

Fields:

```text
job_id
worker_id
session_id
lease_started
lease_expires
heartbeat
```

If a session crashes, another worker may recover an expired job according to policy.

---

# 55. SESSION CRASH RECOVERY

If a terminal closes unexpectedly:

```text
Session:
DISCONNECTED

Jobs:
PRESERVED

State:
PRESERVED

Evidence:
PRESERVED
```

On reconnect:

```text
RECOVERING
 ↓
Restore Session State
 ↓
Reattach Jobs
 ↓
READY
```

---

# 56. SHARED DATA VISIBILITY

Data visibility must be policy-driven.

Possible visibility:

```text
PRIVATE
WORKSPACE
ENGAGEMENT
CASE
ORGANIZATION
GLOBAL
```

Default access should follow least privilege.

---

# 57. LEARN + WORK DATA

The Learn+Work workspace stores:

```text
Learning Profile
Lessons
Exercises
Progress
Assessments
Practical Work
Skill Records
```

Learning records must not accidentally expose restricted operational data.

---

# 58. LEARNING PROGRESS ENTITY

Fields:

```text
progress_id
learning_profile_id
lesson_id
exercise_id
status
score
attempts
completed_at
skill_level
```

Learning progress must be personal to the learning profile unless explicitly shared.

---

# 59. DATABASE INDEXING

Indexes must be created for high-frequency queries.

Minimum candidates:

```text
user_id
session_id
workspace_id
engagement_id
target_id
asset_id
finding_id
case_id
job_id
tool_run_id
timestamp
status
severity
ioc value
```

Indexes must be validated through performance testing.

---

# 60. DATA INTEGRITY CONSTRAINTS

The database must enforce:

* Unique IDs
* Required fields
* Valid foreign keys
* Valid status values
* Valid relationships
* Non-null required timestamps
* No orphaned evidence
* No orphaned findings
* No invalid case references
* No duplicate canonical assets where uniqueness is required

---

# 61. TRANSACTION RULES

Critical multi-step operations must use transactions.

Example:

```text
Create Finding
 + Create Evidence Reference
 + Create Audit Event
```

must either succeed consistently or roll back appropriately.

Partial state must not be silently accepted.

---

# 62. SOFT DELETE

Critical security records should normally use logical deletion.

Examples:

```text
Findings
Evidence
Cases
Audit Logs
Reports
Engagements
```

may use:

```text
deleted_at
deleted_by
deletion_reason
```

Audit records must not be physically deleted through ordinary application operations.

---

# 63. DATA RETENTION

Retention must be configurable.

Possible policies:

```text
30 days
90 days
180 days
1 year
Custom
Indefinite
```

Retention must respect:

* Engagement requirements
* Legal requirements
* Organizational policy
* Evidence preservation
* Privacy requirements

---

# 64. PRIVACY CLASSIFICATION

Data may be classified:

```text
PUBLIC
INTERNAL
CONFIDENTIAL
SENSITIVE
RESTRICTED
```

Access controls must follow classification.

---

# 65. SECRET SEPARATION

Credentials and secrets must not be stored directly inside ordinary findings/evidence records.

Use a dedicated secret-management mechanism.

References may be stored:

```text
secret_reference
credential_id
```

rather than plaintext secrets.

---

# 66. DATABASE ENCRYPTION

Where appropriate, KSEC should support encrypted storage or encrypted database volumes.

Sensitive evidence must receive stronger protection according to deployment policy.

---

# 67. BACKUP MODEL

Backups must include, according to configured policy:

```text
Database
Configuration
Cases
Findings
Evidence Metadata
Reports
Plugin Configuration
Learning Data
Audit Data
Environment Metadata
```

Large evidence files may be stored separately and referenced by the database.

---

# 68. BACKUP MANIFEST

Every backup must contain:

```text
backup_id
created_at
KSEC_version
schema_version
environment_version
database_hash
included_components
encryption_status
integrity_status
```

---

# 69. BACKUP INTEGRITY

After backup creation:

```text
Create Backup
 ↓
Generate Manifest
 ↓
Hash Backup
 ↓
Verify
 ↓
Mark Valid
```

A backup must not be considered reliable until verification succeeds.

---

# 70. RESTORE PROCESS

```text
Select Backup
 ↓
Verify Manifest
 ↓
Verify Integrity
 ↓
Check Compatibility
 ↓
Create Restore Point
 ↓
Restore Database
 ↓
Restore Evidence References
 ↓
Run Integrity Checks
 ↓
Run Migration if Required
 ↓
Verify
 ↓
Return to Service
```

---

# 71. DATABASE MIGRATIONS

Every schema change must use a versioned migration.

Example:

```text
001_initial_schema
002_add_learning
003_add_tool_runs
004_add_shared_state_versioning
```

Migrations must be:

* Ordered
* Repeat-safe where practical
* Tested
* Logged
* Reversible where technically possible

---

# 72. SCHEMA VERSION

The system must expose:

```bash
ksec db version
```

Example:

```text
Database Schema:
v1.8

KSEC:
v1.8.2

Compatibility:
PASS
```

---

# 73. MIGRATION SAFETY

Before migration:

```text
Backup
 ↓
Integrity Check
 ↓
Migration Plan
 ↓
Apply Migration
 ↓
Validate
```

Failed migrations must stop safely rather than leaving an unknown schema state.

---

# 74. DATABASE HEALTH

Command:

```bash
ksec db health
```

Checks:

```text
Connectivity
Schema
Indexes
Constraints
Migration State
Storage
Integrity
Locks
Transactions
Backup State
```

---

# 75. DATABASE REPAIR

Repair operations must be explicit.

Example:

```bash
ksec db repair
```

KSEC must first show:

* Detected issue
* Proposed repair
* Potential impact
* Backup requirement

High-impact repairs require confirmation.

---

# 76. AUDITABLE DATA EXPORT

KSEC must support structured exports.

Examples:

```bash
ksec export case CASE_ID
ksec export findings ENGAGEMENT_ID
ksec export evidence CASE_ID
ksec export assets ENGAGEMENT_ID
```

Exports must preserve provenance.

---

# 77. JSON EXPORT

Machine-readable exports must contain:

```text
schema_version
export_version
generated_at
source_system
records
provenance
integrity
```

---

# 78. CASE EXPORT

A case export should include:

```text
Case
 ├── Metadata
 ├── Assets
 ├── Findings
 ├── Evidence Metadata
 ├── IOCs
 ├── Timeline
 ├── Notes
 ├── Remediation
 ├── Verification
 ├── Reports
 └── Audit References
```

---

# 79. EVIDENCE EXPORT

Evidence export must preserve:

```text
Original Hash
Hash Algorithm
Original Timestamp
Source
Tool
Tool Version
Session
Job
Chain-of-Custody
```

---

# 80. SEARCH

KSEC must support global search across authorized data.

Search targets:

```text
Assets
Findings
Cases
Evidence
IOCs
Threat Actors
Campaigns
TTPs
Jobs
Reports
Tool Runs
```

Search results must respect permissions.

---

# 81. CORRELATION QUERIES

KSEC should support relationships such as:

```text
Find all findings for Asset X

Find all assets associated with Domain X

Find all evidence supporting Finding X

Find all cases containing IOC X

Find all tool runs that discovered Asset X
```

---

# 82. DATA LINEAGE

For every major result, KSEC should be able to trace:

```text
Finding
 ↓
Evidence
 ↓
Tool Run
 ↓
Job
 ↓
Workflow
 ↓
Session
 ↓
User
 ↓
Engagement
 ↓
Authorization
```

This is a core audit feature.

---

# 83. REPORT REPRODUCIBILITY

A report must identify:

* Data snapshot
* Finding versions
* Evidence references
* Risk engine version
* Report template version
* KSEC version
* Tool versions
* Environment snapshot

---

# 84. RISK VERSIONING

Risk calculations must store:

```text
risk_engine_version
risk_inputs
risk_score
severity
calculated_at
```

If the risk algorithm changes, historical risk values must remain reproducible.

---

# 85. FINDING DEDUPLICATION

KSEC should identify duplicate findings using:

* Asset
* Service
* Vulnerability identity
* Evidence
* Source
* Fingerprint

Deduplication must never destroy unique evidence.

---

# 86. EVIDENCE DEDUPLICATION

Identical evidence may be referenced by multiple findings where policy allows.

The original evidence object remains authoritative.

---

# 87. DATA CONFLICT HANDLING

If two sessions update the same record:

```text
Change A
Change B
 ↓
Conflict Detection
 ↓
Reconciliation
```

The system must never silently discard one user's update.

---

# 88. OFFLINE SHARED STATE

If the database temporarily becomes unavailable:

* Active jobs must follow recovery policy.
* Critical state must not be silently lost.
* Local queues may temporarily buffer approved non-critical events.
* Conflicts must be reconciled after reconnection.

Offline buffering must have explicit limits.

---

# 89. STORAGE MANAGEMENT

KSEC must monitor:

```text
Database Size
Evidence Size
Free Disk
Backup Size
Temporary Storage
Growth Rate
```

Warnings:

```text
WARNING
CRITICAL
```

must be generated before storage exhaustion.

---

# 90. EVIDENCE STORAGE TIERS

Optional storage tiers:

```text
HOT
WARM
ARCHIVE
```

Example:

```text
Recent Evidence → HOT
Older Evidence → WARM
Archived Case Evidence → ARCHIVE
```

The database stores references regardless of physical storage tier.

---

# 91. CASE CLOSURE

A case may only be closed when configured closure requirements are satisfied.

Example:

```text
Findings Reviewed
Evidence Preserved
Remediation Status Recorded
Verification Completed
Report Generated
Required Approvals Complete
```

---

# 92. CASE REOPEN

Closed cases may be reopened according to permission.

Reason must be recorded.

```text
Case:
CLOSED

Reason for Reopen:
New Evidence

Actor:
Authorized User

Audit:
RECORDED
```

---

# 93. AUDIT IMMUTABILITY

Audit records must be append-only.

Application users must not be able to modify historical audit records through ordinary UI/API operations.

---

# 94. DATABASE SECURITY

The database subsystem must implement:

* Least privilege
* Authentication
* Authorization
* Input validation
* Parameterized queries
* Secure migrations
* Secret separation
* Audit logging
* Backup protection
* Integrity checking
* Safe error messages

---

# 95. SQL / QUERY SAFETY

All application queries must use parameterized statements or a safe query abstraction.

Raw user input must never be concatenated directly into database queries.

---

# 96. PERFORMANCE REQUIREMENTS

The database must remain responsive under:

* Five simultaneous terminal sessions
* Multiple concurrent jobs
* Continuous event creation
* Large evidence metadata volumes
* Finding correlation
* Learning progress updates
* Audit logging

Performance testing must simulate realistic concurrent workloads.

---

# 97. DATABASE TEST SUITE

Required tests:

### Schema

* Tables
* Constraints
* Foreign keys
* Indexes

### Transactions

* Commit
* Rollback
* Failure recovery

### Concurrency

* Simultaneous updates
* Lock conflicts
* Version conflicts

### Evidence

* Hash validation
* Chain-of-custody
* Immutability

### Cases

* Create
* Update
* Close
* Reopen

### Backup

* Create
* Verify
* Restore

### Migration

* Upgrade
* Failure
* Rollback where supported

---

# 98. SHARED STATE ACCEPTANCE TEST

The system passes when:

1. Terminal 1 creates an authorized asset.
2. Shared state records it.
3. Terminal 2 can see it according to policy.
4. Terminal 3 can enrich it.
5. Terminal 4 can reference it inside an authorized simulation.
6. Terminal 5 can use it for permitted learning/practical work.
7. All actions remain attributable to sessions/users.
8. Unauthorized access is denied.
9. Concurrent updates do not silently overwrite data.
10. State survives terminal crashes.

---

# 99. EVIDENCE ACCEPTANCE TEST

KSEC passes when:

1. Tool output is captured.
2. Evidence receives a unique ID.
3. Hash is generated.
4. Provenance is recorded.
5. Chain-of-custody is created.
6. Evidence can be verified.
7. Evidence cannot be silently altered.
8. Evidence can be linked to findings.
9. Evidence can be linked to cases.
10. Evidence survives backup/restore.

---

# 100. CASE MANAGEMENT ACCEPTANCE TEST

KSEC passes when:

1. A case can be created.
2. Assets can be linked.
3. Findings can be linked.
4. Evidence can be linked.
5. IOCs can be linked.
6. Timeline events can be added.
7. Remediation can be tracked.
8. Verification can be recorded.
9. Reports can be generated.
10. Closure requirements can be enforced.
11. Cases can be reopened with audit history.

---

# 101. FINAL DATABASE DEFINITION OF DONE

The database subsystem is complete only when:

* Core schema exists
* IDs are immutable
* Relationships are enforced
* Sessions are persisted
* Multi-terminal state works
* Shared state works
* Concurrency works
* Jobs are persisted
* Tool runs are persisted
* Assets are normalized
* Findings are versioned
* Evidence is integrity-protected
* Chain-of-custody works
* Cases work
* Remediation works
* Verification works
* IOCs work
* Threat intelligence entities work
* Learning records work
* Reports are reproducible
* Audit logs are append-only
* Data lineage works
* Backup works
* Restore works
* Migration works
* Retention works
* Privacy classification works
* Secret separation works
* Export works
* Search works
* Performance requirements are tested
* Crash recovery works
* Offline recovery policy works
* RBAC is enforced
* No silent data loss occurs

---

# 102. MASTER DATA FLOW

```text
USER
 ↓
SESSION
 ↓
WORKSPACE
 ↓
ENGAGEMENT
 ↓
TARGET
 ↓
ASSET
 ↓
SERVICE
 ↓
TOOL RUN
 ↓
JOB
 ↓
RAW RESULT
 ↓
EVIDENCE
 ↓
NORMALIZED DATA
 ↓
FINDING
 ↓
RISK
 ↓
CASE
 ↓
REMEDIATION
 ↓
VERIFICATION
 ↓
REPORT
 ↓
AUDIT
```

---

# 103. MASTER SHARED-STATE RULE

> **KSEC must have one authoritative shared state while preserving session isolation, role isolation, data provenance, concurrency safety, and complete auditability.**

One person may operate all five terminals.

Five people may operate the five terminals.

The database architecture must support both without changing the underlying data model.

---

# 104. MASTER EVIDENCE RULE

> **If KSEC cannot prove where a result came from, when it was produced, what produced it, and whether the evidence remained intact, the result must not be treated as fully auditable evidence.**

---

# 105. MASTER CASE RULE

> **A finding is an observation; evidence supports it; a case organizes the investigation; remediation addresses it; verification proves whether it was resolved.**

These concepts must remain separate in the implementation.

---

# 106. FINAL IMPLEMENTATION INSTRUCTION

Build the persistence layer as a production-grade authoritative data system.

Do not use loosely structured files as the primary source of truth.

Do not silently overwrite concurrent changes.

Do not mutate finalized evidence.

Do not delete audit history through ordinary application operations.

Do not store plaintext secrets in findings, evidence, logs, or reports.

Do not claim evidence integrity without verification.

Do not mark remediation verified without evidence or an explicit verification record.

Do not allow one workspace to bypass another workspace's permissions.

Do not let a terminal crash destroy persistent job, evidence, case, or finding state.

The database and shared-state architecture must support the entire KSEC ecosystem:

**Operations → Research → Defense → Adversary Simulation → Learn+Work → Evidence → Risk → Cases → Reports → Audit → Recovery.**

**PDF 5 complete, boss.** Next **PDF 6** will lock the complete **Security + RBAC + Authorization + Safety Specification**, including command/module/action-level permissions, scope enforcement, authorization gates, destructive-action controls, adversary-simulation safeguards, secrets, audit and threat model.
