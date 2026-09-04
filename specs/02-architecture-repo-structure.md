Boss, **PDF 2** ka focus sirf architecture aur repository/code structure hai. PDF 1 ke requirements ko repeat karne ke bajaye yeh AI ko batayega ke **KSEC ko technically kaise build aur organize karna hai**.

# KSEC — SYSTEM ARCHITECTURE & REPOSITORY / CODE STRUCTURE

## Version 1.0 — Implementation Architecture Specification

**Project:** KSEC
**Purpose:** All-in-One Kali Linux Security Platform
**Primary OS:** Kali Linux
**Architecture:** Modular, local-first, AI-free, extensible, concurrent
**Primary Interface:** CLI + TUI
**Optional Interface:** Local Web Dashboard

---

# 1. ARCHITECTURAL MASTER DIRECTIVE

Build KSEC as a modular security platform rather than a collection of shell scripts.

The architecture must allow:

* Multiple security workspaces
* Multiple simultaneous sessions
* Multiple concurrent jobs
* Dynamic Kali tool discovery
* Dynamic capability registration
* Controlled tool installation
* Tool adapters
* Output parsers
* Workflow orchestration
* Shared state
* Evidence management
* Risk calculation
* Case management
* Reporting
* Learning
* Plugin extensions
* Offline operation
* Recovery after failures

The core must not depend on AI or cloud services.

---

# 2. HIGH-LEVEL ARCHITECTURE

```text
                         KALI LINUX
                              │
                              ▼
                    ┌──────────────────┐
                    │      KSEC        │
                    │   APPLICATION    │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
            CLI             TUI       Local Dashboard
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                    SESSION MANAGER
                             │
                             ▼
                    WORKSPACE MANAGER
                             │
        ┌────────────┬───────┼───────┬────────────┐
        ▼            ▼       ▼       ▼            ▼
      RED          BLUE   RESEARCH ADVERSARY  LEARN+WORK
                             │
                             ▼
                     POLICY ENGINE
                             │
                             ▼
                   AUTHORIZATION ENGINE
                             │
                             ▼
                    WORKFLOW ENGINE
                             │
                             ▼
                    JOB SCHEDULER
                             │
                             ▼
                  CAPABILITY REGISTRY
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
          Kali Tools     Plugins        Install Manager
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                    ADAPTER EXECUTION
                             │
                             ▼
                         PARSERS
                             │
                             ▼
                       NORMALIZER
                             │
                             ▼
                       CORRELATION
                             │
           ┌─────────────────┼─────────────────┐
           ▼                 ▼                 ▼
         ASSETS          FINDINGS           EVIDENCE
           │                 │                 │
           └─────────────────┼─────────────────┘
                             ▼
                        RISK ENGINE
                             │
                             ▼
                      CASE MANAGEMENT
                             │
                             ▼
                         REPORTING
```

---

# 3. ARCHITECTURAL PRINCIPLES

## 3.1 Modular

Every major subsystem must have a defined interface.

A module must be replaceable without rewriting unrelated modules.

## 3.2 Dependency Inversion

Core KSEC logic must not directly depend on a specific Kali tool.

Example:

```text
KSEC Capability
       ↓
Adapter Interface
       ↓
Tool Adapter
       ↓
Actual Kali Tool
```

## 3.3 Provider Model

A single capability may have multiple providers.

Example:

```text
Port Discovery
├── Provider A
├── Provider B
└── Provider C
```

KSEC chooses the best compatible provider.

## 3.4 Fail Gracefully

If one provider fails, KSEC should attempt a compatible fallback where policy permits.

## 3.5 Explicit State

Do not rely on temporary shell state as the source of truth.

Persist important:

* Jobs
* Sessions
* Findings
* Evidence
* Cases
* Tool runs
* Workflows
* Learning progress

---

# 4. CORE COMPONENTS

KSEC must contain the following architectural components.

## 4.1 Application Layer

Responsible for:

* Application startup
* Dependency initialization
* Configuration loading
* Service registration
* Shutdown
* Recovery

## 4.2 Interface Layer

Contains:

* CLI
* TUI
* Dashboard API
* Dashboard frontend
* Learning UI

Interfaces must communicate with the application through defined service contracts.

---

# 5. SESSION MANAGER

Responsible for:

* Creating sessions
* Closing sessions
* Resuming sessions
* Session persistence
* Session ownership
* Role assignment
* Workspace assignment
* Session permissions
* Session history

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

A disconnected terminal must not automatically terminate persistent jobs.

---

# 6. WORKSPACE MANAGER

Supported workspaces:

```text
RED_TEAM
BLUE_TEAM
RESEARCH_OSINT
ADVERSARY_SIMULATION
LEARN_WORK
```

Each workspace has:

* Permissions
* Default workflows
* Available modules
* UI configuration
* Learning settings
* Tool visibility
* Safety policy

---

# 7. MULTI-TERMINAL ARCHITECTURE

KSEC must support:

```text
Terminal 1 → Red Team
Terminal 2 → Blue Team
Terminal 3 → Research / OSINT
Terminal 4 → Adversary Simulation
Terminal 5 → Learn + Work
```

One operator may own all five.

Five operators may each own one.

The architecture must not assume:

```text
1 user = 1 terminal
```

Instead:

```text
User
 ├── Session A
 ├── Session B
 ├── Session C
 ├── Session D
 └── Session E
```

---

# 8. JOB MANAGER

The Job Manager represents individual execution tasks.

Each job must contain:

* Job ID
* Session ID
* Workspace
* User
* Workflow
* Capability
* Adapter
* Target
* Scope
* Status
* Priority
* Created time
* Started time
* Completion time
* Resource limits
* Output
* Error state

Job states:

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

# 9. JOB SCHEDULER

The scheduler controls:

* Queue
* Priority
* Concurrency
* CPU limits
* Memory limits
* Timeouts
* Retry policies
* Resource locks
* Cancellation
* Recovery

The scheduler must prevent one workflow from consuming all system resources.

---

# 10. SHARED STATE ENGINE

The Shared State Engine synchronizes relevant information between workspaces.

Examples:

```text
Research
   ↓
Asset Intelligence
   ↓
Red Team
```

```text
Red Team
   ↓
Finding
   ↓
Blue Team
```

```text
Adversary Simulation
   ↓
Detection Test
   ↓
Blue Team
```

Shared state must preserve:

* Source
* Timestamp
* Owner
* Permissions
* Provenance
* Confidence
* Modification history

---

# 11. POLICY ENGINE

The Policy Engine evaluates whether an action is permitted.

Inputs:

* User
* Role
* Workspace
* Command
* Tool
* Target
* Scope
* Authorization
* Risk
* Environment
* Action type

Output:

```text
ALLOW
DENY
REQUIRE_CONFIRMATION
REQUIRE_PRIVILEGE
REQUIRE_AUTHORIZATION
```

No security-sensitive execution should bypass the Policy Engine.

---

# 12. AUTHORIZATION ENGINE

Authorization must be independently represented from user identity.

An engagement may contain:

```text
Engagement
├── Authorization
├── Scope
├── Rules of Engagement
├── Targets
├── Time Window
├── Allowed Actions
└── Restrictions
```

Authorization must be checked before applicable workflows.

---

# 13. KALI ENVIRONMENT MANAGER

The Environment Manager detects:

* OS
* Kali version
* Kernel
* Architecture
* Runtime
* Virtualization
* Containers
* WSL
* NetHunter
* Hardware
* Privileges
* APT state
* Network state

It produces an environment fingerprint.

Example:

```text
Kali: detected
Architecture: x86_64
Kernel: detected
Runtime: VM
Privilege: normal user
APT: healthy
Wi-Fi monitor mode: available
GPU: available
```

---

# 14. KALI CAPABILITY REGISTRY

The registry maps:

```text
Tool
→ Package
→ Binary
→ Version
→ Capability
→ Category
→ Dependencies
→ Platform
→ Adapter
→ Parser
→ Health
```

The registry must be dynamically populated.

Do not hardcode the entire Kali tool list.

---

# 15. TOOL DISCOVERY ENGINE

The Tool Discovery Engine must inspect the actual system.

It should discover:

* Installed packages
* Installed binaries
* Version information
* Executable paths
* Tool metadata
* Capabilities
* Services
* Metapackages

The discovery process must be repeatable.

---

# 16. TOOL INSTALLATION MANAGER

When a required capability is missing:

```text
Capability Missing
↓
Find Supported Provider
↓
Source Validation
↓
Compatibility Check
↓
Dependency Check
↓
User Approval
↓
Installation
↓
Verification
↓
Registration
↓
Health Check
```

The installation manager must not blindly execute arbitrary downloaded scripts.

Supported providers must have defined trust metadata.

---

# 17. TOOL ADAPTER LAYER

The adapter abstracts a real security tool.

Example:

```text
KSEC Capability
      ↓
PortScannerAdapter
      ↓
SpecificToolProvider
      ↓
Binary Execution
```

Adapters must define:

* Metadata
* Capability
* Inputs
* Output types
* Command builder
* Environment requirements
* Privileges
* Safety classification
* Parser
* Error mapping
* Version compatibility

---

# 18. COMMAND BUILDER

The Command Builder converts structured execution requests into validated tool invocations.

Input:

```text
Capability
Target
Options
Policy
Environment
```

Output:

```text
Validated Execution Request
```

The command builder must:

* Validate arguments
* Prevent unintended argument injection
* Validate paths
* Validate targets
* Apply policy
* Apply scope
* Apply resource limits

Never concatenate untrusted strings into shell commands without safe handling.

---

# 19. EXECUTION ENGINE

The Execution Engine handles:

* Process creation
* Standard output
* Standard error
* Exit codes
* Signals
* Timeouts
* Resource limits
* Process groups
* Cancellation
* Cleanup

Tool processes must be isolated as reasonably practical.

---

# 20. PARSER ENGINE

Parsers convert raw tool output into structured results.

Example:

```text
Raw Tool Output
       ↓
Parser
       ↓
Structured Result
```

Parsers must support:

* Text
* JSON
* XML
* CSV
* Tool-specific formats
* Logs

Unknown output must never be silently discarded.

---

# 21. NORMALIZATION ENGINE

Different tools may describe the same object differently.

Normalize:

* IP addresses
* Domains
* URLs
* Ports
* Services
* Hosts
* Technologies
* Vulnerabilities
* IOCs
* Findings

Example:

```text
Tool A:
"80/tcp open http"

Tool B:
"HTTP service on TCP/80"

KSEC:
Asset → Port 80 → HTTP
```

---

# 22. CORRELATION ENGINE

The Correlation Engine connects related observations.

Example:

```text
Domain
↓
Subdomain
↓
IP
↓
Port
↓
Service
↓
Technology
↓
Finding
```

Correlation must preserve confidence and provenance.

Do not treat correlation as proof unless the evidence supports it.

---

# 23. ASSET ENGINE

Assets may include:

* IP
* CIDR
* Domain
* Subdomain
* URL
* Host
* Device
* Application
* Cloud resource
* Container
* Kubernetes resource
* Wireless asset

Assets must support:

* Ownership
* Criticality
* Tags
* Relationships
* Scope
* History

---

# 24. FINDING ENGINE

Findings must support:

* Title
* Description
* Severity
* Confidence
* Asset
* Service
* Evidence
* Risk
* Impact
* Recommendation
* Status
* Remediation
* Verification

---

# 25. EVIDENCE ENGINE

Evidence must support:

* Immutable identity
* Hash
* Source
* Tool
* Tool version
* Session
* Operator
* Timestamp
* Engagement
* Collection method
* Chain-of-custody

---

# 26. RISK ENGINE

Risk Engine receives:

```text
Severity
Asset Criticality
Exploitability
Exposure
Business Impact
Confidence
Evidence Quality
```

It produces:

```text
Critical
High
Medium
Low
Info
```

Risk logic must be deterministic and versioned.

---

# 27. CASE ENGINE

Case Engine connects:

```text
Case
├── Assets
├── Findings
├── Evidence
├── Events
├── IOCs
├── Tasks
├── Notes
├── Timeline
├── Remediation
└── Verification
```

---

# 28. REPORTING ENGINE

The Reporting Engine must consume structured KSEC data rather than raw terminal output.

Pipeline:

```text
Case
↓
Findings
↓
Evidence
↓
Risk
↓
Recommendations
↓
Report
```

Formats may include:

* HTML
* PDF
* Markdown
* JSON
* CSV

---

# 29. LEARNING ENGINE

The Learning Engine must be independent from AI.

Components:

```text
Curriculum
Lessons
Exercises
Labs
Knowledge Checks
Practical Assessments
Progress
Skills
Completion
```

It may connect learning content to operational workflows while maintaining authorization boundaries.

---

# 30. NOTIFICATION ENGINE

Support pluggable notification providers.

Examples:

* Email
* Telegram
* Slack
* Discord
* Webhooks

Notifications should be event-driven.

---

# 31. CONFIGURATION ENGINE

Configuration sources should follow a clear precedence model.

Example:

```text
Built-in Defaults
↓
System Configuration
↓
User Configuration
↓
Workspace Configuration
↓
Session Configuration
↓
Command-Line Override
```

Sensitive values must be handled separately from ordinary configuration.

---

# 32. DATABASE ARCHITECTURE

The database layer must support:

* Transactions
* Migrations
* Constraints
* Indexes
* Referential integrity
* Versioning
* Backup
* Restore

Database access must be centralized through repositories/services rather than scattered raw queries.

---

# 33. EVENT BUS

KSEC should use internal events for loosely coupled components.

Example:

```text
JOB_COMPLETED
        ↓
Event Bus
   ┌────┼────┐
   ↓    ↓    ↓
Parser Audit Notification
```

Events must have:

* Event ID
* Type
* Timestamp
* Actor
* Session
* Correlation ID
* Payload
* Version

---

# 34. AUDIT ARCHITECTURE

Security-relevant actions must produce audit events.

Examples:

* Login
* Permission change
* Scope change
* Tool installation
* Tool execution
* Evidence creation
* Case modification
* Report generation
* Configuration change
* Backup
* Restore

Audit records must be tamper-resistant as reasonably practical.

---

# 35. ERROR ARCHITECTURE

All components must use structured errors.

Suggested structure:

```text
Error Code
Component
Severity
Message
Cause
Context
Recovery Hint
Retryable
Correlation ID
```

---

# 36. LOGGING ARCHITECTURE

Logs should be structured.

Recommended levels:

```text
TRACE
DEBUG
INFO
WARNING
ERROR
CRITICAL
```

Never log secrets.

---

# 37. SECURITY BOUNDARY ARCHITECTURE

Security boundaries include:

```text
User
↓
Session
↓
Workspace
↓
Policy
↓
Authorization
↓
Workflow
↓
Job
↓
Adapter
↓
Tool
```

Each layer must enforce the controls applicable to it.

---

# 38. PLUGIN ARCHITECTURE

Plugins must be isolated from core functionality.

Example:

```text
Plugin
├── Manifest
├── Version
├── Capabilities
├── Permissions
├── Dependencies
├── Adapter
├── Parser
├── Tests
└── Documentation
```

Plugins must declare required permissions.

Untrusted plugins must not automatically receive unrestricted access.

---

# 39. REPOSITORY STRUCTURE

Use a professional repository structure.

```text
ksec/
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── CHANGELOG.md
├── pyproject.toml
├── Makefile
├── .gitignore
├── .env.example
│
├── src/
│   └── ksec/
│       ├── __init__.py
│       ├── main.py
│       │
│       ├── cli/
│       ├── tui/
│       ├── dashboard/
│       │
│       ├── core/
│       ├── config/
│       ├── sessions/
│       ├── workspaces/
│       ├── jobs/
│       ├── scheduler/
│       ├── workflows/
│       ├── policies/
│       ├── authorization/
│       ├── rbac/
│       │
│       ├── kali/
│       ├── capabilities/
│       ├── adapters/
│       ├── parsers/
│       ├── execution/
│       │
│       ├── assets/
│       ├── findings/
│       ├── evidence/
│       ├── cases/
│       ├── risk/
│       ├── correlation/
│       │
│       ├── threat_intel/
│       ├── osint/
│       ├── dfir/
│       ├── malware/
│       ├── reporting/
│       │
│       ├── learning/
│       ├── notifications/
│       ├── backups/
│       ├── updates/
│       ├── health/
│       ├── audit/
│       ├── events/
│       └── plugins/
│
├── plugins/
│   ├── discovery/
│   ├── network/
│   ├── web/
│   ├── api/
│   ├── wireless/
│   ├── vulnerability/
│   ├── cloud/
│   ├── containers/
│   ├── endpoint/
│   ├── dfir/
│   ├── malware/
│   ├── threat_intel/
│   ├── reporting/
│   ├── compliance/
│   └── integrations/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── adapters/
│   ├── parsers/
│   ├── workflows/
│   ├── scheduler/
│   ├── sessions/
│   ├── security/
│   ├── authorization/
│   ├── rbac/
│   ├── learning/
│   ├── recovery/
│   ├── performance/
│   └── fixtures/
│
├── docs/
│   ├── architecture/
│   ├── cli/
│   ├── tui/
│   ├── kali/
│   ├── security/
│   ├── workflows/
│   ├── plugins/
│   ├── learning/
│   ├── operations/
│   └── api/
│
├── scripts/
│   ├── install/
│   ├── uninstall/
│   ├── update/
│   ├── backup/
│   └── development/
│
├── migrations/
│
├── configs/
│
├── examples/
│   ├── workflows/
│   ├── configurations/
│   └── plugins/
│
├── packaging/
│
└── .github/
    ├── workflows/
    ├── ISSUE_TEMPLATE/
    └── PULL_REQUEST_TEMPLATE.md
```

---

# 40. CODE ORGANIZATION RULE

Use clear separation:

```text
Interface
   ↓
Application Service
   ↓
Domain Logic
   ↓
Repository / Infrastructure
```

The CLI must not directly manipulate the database.

The TUI must not directly execute shell commands.

The dashboard must not bypass authorization.

All interfaces should use the same core services.

---

# 41. DOMAIN MODULE RULE

Each major domain should own its logic.

Example:

```text
findings/
├── models
├── repository
├── service
├── validators
└── tests
```

Avoid giant files containing unrelated functionality.

---

# 42. TEST ORGANIZATION

Every major module should have:

* Unit tests
* Integration tests where applicable
* Failure tests
* Permission tests where applicable

Adapters must have fixture-based parser tests.

---

# 43. DEPENDENCY MANAGEMENT

Dependencies must be:

* Explicit
* Version-controlled
* Auditable
* Tested
* Minimal where practical

Separate:

```text
Core Dependencies
Optional Dependencies
Tool Dependencies
Development Dependencies
```

A missing optional dependency must not prevent unrelated KSEC functionality from starting.

---

# 44. STARTUP SEQUENCE

KSEC startup:

```text
Process Start
↓
Load Configuration
↓
Initialize Logging
↓
Check Database
↓
Run Migrations
↓
Detect Kali Environment
↓
Load Capability Registry
↓
Load Plugins
↓
Validate Plugin Health
↓
Initialize Scheduler
↓
Initialize Sessions
↓
Run Health Checks
↓
Ready
```

Failure in a non-critical plugin should not necessarily prevent KSEC core from starting.

---

# 45. SHUTDOWN SEQUENCE

On shutdown:

```text
Stop Accepting New Jobs
↓
Notify Active Sessions
↓
Persist State
↓
Gracefully Stop Jobs Where Appropriate
↓
Flush Logs
↓
Close Database
↓
Close Services
↓
Exit
```

Interrupted jobs must be recoverable where supported.

---

# 46. RECOVERY SEQUENCE

After crash/restart:

```text
Startup
↓
Detect Interrupted Jobs
↓
Validate State
↓
Recover Safe Jobs
↓
Mark Invalid Jobs Failed
↓
Restore Sessions Where Possible
↓
Reconcile Shared State
↓
Run Health Checks
↓
Ready
```

Never blindly resume an unsafe operation.

---

# 47. API ARCHITECTURE

All external/internal service APIs must have:

* Version
* Authentication
* Authorization
* Input validation
* Output schema
* Error schema
* Audit event
* Rate limiting where appropriate

Example:

```text
/api/v1/assets
/api/v1/findings
/api/v1/cases
/api/v1/jobs
/api/v1/sessions
/api/v1/workflows
/api/v1/tools
/api/v1/learning
```

---

# 48. DATA FLOW

Typical assessment:

```text
User
↓
CLI/TUI
↓
Application Service
↓
Policy Engine
↓
Authorization Engine
↓
Workflow Engine
↓
Scheduler
↓
Capability Registry
↓
Adapter
↓
Kali Tool
↓
Parser
↓
Normalizer
↓
Correlation
↓
Evidence
↓
Finding
↓
Risk
↓
Case
↓
Report
```

No interface should bypass this architecture for normal workflows.

---

# 49. ARCHITECTURAL NON-GOALS

Do not:

* Hardcode every Kali tool into core logic
* Make one tool mandatory for every capability
* Make AI mandatory
* Couple CLI directly to tools
* Couple dashboard directly to shell execution
* Store secrets in source code
* Hide failures
* Allow plugins unrestricted access by default
* Assume one user equals one session
* Assume one session equals one job
* Assume every Kali installation has identical capabilities

---

# 50. IMPLEMENTATION ORDER

Build in this order:

## Stage 1

Foundation:

* Repository
* Configuration
* Logging
* Database
* Core interfaces

## Stage 2

Security:

* Identity
* RBAC
* Sessions
* Authorization
* Policy engine
* Audit

## Stage 3

Execution:

* Kali detection
* Capability registry
* Tool discovery
* Adapter interface
* Execution engine
* Parser engine

## Stage 4

Orchestration:

* Workflow engine
* Scheduler
* Jobs
* Concurrency
* Recovery

## Stage 5

Security data:

* Assets
* Findings
* Evidence
* Risk
* Cases
* Correlation

## Stage 6

Interfaces:

* CLI
* TUI
* Dashboard API
* Dashboard

## Stage 7

Operational modules:

* Red Team
* Blue Team
* Research/OSINT
* Adversary Simulation
* DFIR
* Threat Intelligence

## Stage 8

Learning:

* Curriculum
* Lessons
* Labs
* Assessments
* Progress

## Stage 9

Operations:

* Backup
* Updates
* Health
* Notifications
* Deployment

## Stage 10

Testing:

* Full integration
* Security
* Concurrency
* Recovery
* Performance
* Kali compatibility

---

# 51. ARCHITECTURAL DEFINITION OF DONE

The architecture is complete only when:

* Every major subsystem has an owner/module.
* Every major subsystem has defined interfaces.
* CLI, TUI and dashboard use common application services.
* Sessions are persistent.
* Five workspaces can coexist.
* Jobs are independently managed.
* Scheduler supports concurrency.
* Shared state is consistent.
* Authorization cannot be bypassed through alternate interfaces.
* Kali tools are accessed through adapters.
* Missing capabilities can use the controlled installation path.
* Outputs are parsed and normalized.
* Evidence is preserved.
* Findings are correlated.
* Risk is deterministic.
* Cases are persistent.
* Reports are generated from structured data.
* Learning is integrated without AI.
* Plugins are permission-controlled.
* Failures are observable.
* Recovery is implemented.
* Tests cover critical architecture paths.
* Documentation matches implementation.

---

# 52. MASTER ARCHITECTURE RULE

The final implementation must preserve this separation:

```text
USER INTERFACE
       ↓
APPLICATION SERVICES
       ↓
DOMAIN LOGIC
       ↓
POLICY / AUTHORIZATION
       ↓
WORKFLOW / SCHEDULER
       ↓
CAPABILITY / ADAPTER LAYER
       ↓
KALI / EXTERNAL PROVIDERS
       ↓
PARSERS / NORMALIZATION
       ↓
SECURITY DATA
       ↓
REPORTING / LEARNING / OPERATIONS
```

If a proposed implementation breaks this separation, redesign it before proceeding.

---

# 53. FINAL AI IMPLEMENTATION INSTRUCTION

Treat this document as the authoritative **architecture contract** for KSEC.

Do not merely generate a folder tree.

Create a working implementation that follows this architecture.

For every component:

1. Define its interface.
2. Define its dependencies.
3. Implement it.
4. Add tests.
5. Integrate it.
6. Add error handling.
7. Add security controls.
8. Add documentation.
9. Verify integration.
10. Update the implementation checklist.

Never claim an architectural component is implemented when only a placeholder exists.

Use interfaces and dependency injection where practical.

Prefer simple, maintainable architecture over unnecessary complexity.

Do not introduce AI/LLM dependencies.

Do not silently change the architecture defined by this document.

If a technical decision must differ from this specification, document the reason, impact, migration path and compatibility implications.

---

# END OF PDF 02

**KSEC — System Architecture & Repository / Code Structure**
**Version 1.0**

Boss, **PDF 2 complete hai**. Iske baad PDF 3 mein hum **exact CLI grammar + TUI + 5-terminal UX + Beginner/Professional/Expert interface** ko implementation-level detail mein lock karenge.
