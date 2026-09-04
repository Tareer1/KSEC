# KSEC — MASTER BUILD PROMPT & COMPLETE PRODUCT SPECIFICATION

## Version 1.0 — Master Implementation Specification

**Project Name:** KSEC
**Project Type:** All-in-One Kali Linux Security Operations, Assessment, Research, Defense, Adversary Simulation & Learning Platform
**Primary Runtime:** Kali Linux
**Architecture:** Local-first, modular, extensible, offline-capable
**AI Dependency:** NONE
**Primary Interface:** KSEC Unified CLI + TUI
**Optional Interface:** Local Web Dashboard
**Operational Model:** One Kali OS → One KSEC Core → Multiple Concurrent Workspaces

---

# 1. MASTER DIRECTIVE

You are responsible for building **KSEC**, a production-grade, modular, Kali-aware cybersecurity platform.

KSEC must provide one unified interface through which authorized security professionals, researchers, defenders, learners, and security testers can perform their workflows without manually switching between individual Kali Linux security tools.

KSEC must orchestrate existing security tools behind the scenes.

The user should primarily interact with **KSEC**, not with dozens of separate tools.

The system must dynamically discover available Kali capabilities, determine which tools are installed, identify missing capabilities, and—when explicitly authorized—install supported missing tools through a controlled and verifiable installation system.

KSEC must not depend on artificial intelligence, LLMs, cloud AI APIs, or paid AI services.

The core platform must work locally and offline wherever the underlying functionality permits.

---

# 2. CORE PRINCIPLE

## "Don't reinvent Kali. Orchestrate Kali."

KSEC is not intended to replace every individual Kali security tool.

Instead, KSEC provides:

* Unified interface
* Tool discovery
* Capability discovery
* Tool orchestration
* Workflow automation
* Output parsing
* Result normalization
* Finding correlation
* Evidence management
* Risk analysis
* Case management
* Reporting
* Learning
* Governance
* Security controls
* Multi-terminal execution

Kali tools are treated as interchangeable capability providers.

---

# 3. PRIMARY OBJECTIVE

Build a platform where a user can perform an end-to-end authorized security workflow through KSEC.

Example:

```bash
ksec assess TARGET
```

KSEC should internally coordinate the appropriate workflow:

```text
Scope
↓
Authorization
↓
Environment Validation
↓
Capability Detection
↓
Discovery
↓
Enumeration
↓
Assessment
↓
Validation
↓
Output Parsing
↓
Normalization
↓
Correlation
↓
Risk Assessment
↓
Evidence Collection
↓
Finding Creation
↓
Case Management
↓
Reporting
↓
Remediation
↓
Verification
↓
Closure
```

The user should not need to manually launch different Kali tools for each stage during normal KSEC workflows.

---

# 4. FIVE KSEC WORKSPACES

KSEC must support five simultaneous workspaces.

## Workspace 1 — Red Team

Purpose:

**Authorized attack simulation and security testing.**

Primary responsibilities:

* Reconnaissance
* Asset discovery
* Enumeration
* Network security assessment
* Service identification
* Web security assessment
* API security assessment
* Wireless security assessment
* Vulnerability assessment
* Configuration testing
* Security-control validation
* Attack-surface analysis
* Attack-path analysis
* Evidence collection
* Finding creation
* Risk assessment
* Remediation verification
* Professional reporting

Workflow:

```text
Scope
→ Recon
→ Enumeration
→ Assessment
→ Validation
→ Evidence
→ Risk
→ Report
→ Remediation Verification
```

All offensive functionality must require appropriate authorization and scope.

---

# 5. BLUE TEAM

Purpose:

**Defense, monitoring, detection, investigation and remediation.**

Primary responsibilities:

* Host security auditing
* Network monitoring
* Log analysis
* Authentication monitoring
* Process analysis
* Service auditing
* File-integrity monitoring
* Suspicious activity detection
* Configuration auditing
* Vulnerability management
* Hardening
* Incident investigation
* DFIR integration
* IOC detection
* Threat-intelligence correlation
* Detection-gap analysis
* Remediation tracking
* Verification
* Security reporting

Workflow:

```text
Monitor
→ Detect
→ Investigate
→ Correlate
→ Contain
→ Remediate
→ Verify
→ Document
```

---

# 6. RESEARCH / OSINT

Purpose:

**Security detective and intelligence workspace.**

Support both:

* Passive intelligence collection
* Authorized active reconnaissance

Capabilities:

### Domain Intelligence

* Domain discovery
* Subdomain discovery
* DNS intelligence
* Certificate intelligence
* Domain registration intelligence
* Historical infrastructure information

### Infrastructure Intelligence

* IP intelligence
* CIDR intelligence
* Host relationships
* Service identification
* Technology fingerprinting
* Infrastructure mapping
* Cloud exposure research

### Public Information

* Public websites
* Public documents
* Public metadata
* Public repositories
* Public code
* Public usernames/accounts
* Public social/platform intelligence
* Search-engine intelligence
* Publicly available exposure information where legally appropriate

### Threat Intelligence

* IOC collection
* IOC enrichment
* Threat actors
* Campaigns
* TTPs
* ATT&CK mappings
* CVEs
* Security advisories
* Vulnerability research
* Technology research
* Exploitability research

### Intelligence Quality

Every research result should support:

* Source
* Timestamp
* Provenance
* Source reliability
* Confidence
* Collection method
* Passive/active classification
* Scope
* Evidence
* Deduplication
* Entity resolution

Research graph:

```text
Domain
↓
Subdomain
↓
IP
↓
Certificate
↓
Technology
↓
Service
↓
IOC
↓
Threat Actor / Campaign
↓
Finding
```

Research must support handoff to:

* Red Team
* Blue Team
* Adversary Simulation

---

# 7. ADVERSARY SIMULATION

The Adversary workspace represents sophisticated attacker behavior for:

* Authorized laboratories
* Purple-team exercises
* Defensive validation
* Detection testing
* Threat-emulation research

It must NOT be an unrestricted real-world Black Hat mode.

The platform may model attacker behavior, but execution must remain controlled by authorization, scope and safety policies.

Capabilities:

* Threat-actor profiles
* Campaign modeling
* Attack-chain modeling
* MITRE ATT&CK mapping
* TTP mapping
* Authorized adversary behavior simulation
* Detection validation
* Security-control validation
* Detection-gap analysis
* Defensive IOC generation
* Evidence correlation
* Attack-path modeling
* Coverage assessment
* Purple-team exercises
* Remediation validation
* Before/after security comparison
* Exercise reporting

Example:

```text
Adversary Profile
↓
Select TTPs
↓
Verify Authorization
↓
Verify Scope
↓
Controlled Simulation
↓
Blue Team Detection
↓
Evidence Correlation
↓
Detection Gap
↓
Remediation
↓
Retest
↓
Coverage Report
```

Threat actor profiles are data objects.

They must never be treated as unrestricted execution permissions.

---

# 8. LEARN + WORK

The fifth workspace combines:

**Learning + practical authorized work.**

It must not be study-only.

A learner should be able to:

```text
Learn
↓
Practice
↓
Understand
↓
Perform Authorized Task
↓
Analyze Result
↓
Create Finding
↓
Document
↓
Report
↓
Track Skill Progress
```

Learning must be integrated into actual KSEC workflows.

Learning mode must remain AI-free.

---

# 9. FIVE LEARNING LEVELS

KSEC must support five learning profiles.

## Level 1 — Explorer

Absolute beginner.

Teach:

* What computers are
* Operating systems
* Files
* Folders
* Applications
* Basic terminal usage
* Basic security concepts

## Level 2 — Beginner

Teach:

* Linux fundamentals
* Users
* Groups
* Permissions
* Processes
* Services
* Basic networking
* Basic security terminology

## Level 3 — Learner

Teach:

* Practical security workflows
* Tool usage
* Reconnaissance
* Enumeration
* Output interpretation
* Evidence
* Basic findings

## Level 4 — Advanced Learner

Teach:

* Deeper analysis
* Correlation
* Evidence quality
* Risk analysis
* Complex workflows
* DFIR
* Threat intelligence
* Professional methodology

## Level 5 — Security Practitioner

Teach:

* Professional security workflows
* Complex authorized assessments
* Defensive operations
* Research
* Reporting
* Remediation verification
* Practical assessment

---

# 10. END-TO-END LEARNING CURRICULUM

Learning must begin at initialization and continue through final practical assessment.

## Phase 0 — Orientation

Teach:

* KSEC
* Cybersecurity
* Authorized testing
* Ethics
* Scope
* Authorization
* Labs
* Safety
* Interface

## Phase 1 — Computer Basics

Teach:

* Hardware
* Operating systems
* Files
* Directories
* Processes
* Users
* Groups
* Applications
* Services
* Troubleshooting

## Phase 2 — Linux

Teach:

* Terminal
* Commands
* Paths
* Files
* Permissions
* Processes
* Packages
* Networking commands
* Kali fundamentals

## Phase 3 — Networking

Teach:

* IP
* IPv4
* IPv6
* MAC
* DNS
* DHCP
* TCP
* UDP
* Ports
* Protocols
* Routers
* Switches
* Firewalls
* HTTP
* HTTPS

## Phase 4 — Security Fundamentals

Teach:

* Vulnerability
* Threat
* Risk
* Attack surface
* Authentication
* Authorization
* Encryption
* Logging
* Indicators
* Security controls

## Phase 5 — Security Tools

Every tool must be taught using:

```text
What
↓
Why
↓
When
↓
How
↓
Input
↓
Output
↓
Interpretation
↓
Practice
```

## Phase 6 — Reconnaissance

Teach:

```text
Target
→ Scope
→ Discovery
→ Enumeration
→ Evidence
→ Findings
```

## Phase 7 — Web/API Security

Teach:

* Websites
* HTTP
* Requests
* Responses
* APIs
* Authentication concepts
* Common weaknesses
* Vulnerability identification
* Evidence
* Remediation

## Phase 8 — Defensive Security

Teach:

* Logs
* Monitoring
* Detection
* Host investigation
* Network investigation
* Suspicious activity
* Hardening
* Incident response

## Phase 9 — DFIR

Teach:

* Evidence
* Preservation
* Timelines
* Artifacts
* Investigation
* Correlation
* Reporting

## Phase 10 — OSINT / Threat Intelligence

Teach:

* Public information
* Indicators
* Domains
* IPs
* Relationships
* Source reliability
* Confidence
* Correlation

## Phase 11 — Professional Workflow

Teach:

```text
Initialize
→ Define Scope
→ Verify Authorization
→ Prepare Environment
→ Discover
→ Analyze
→ Validate
→ Collect Evidence
→ Assess Risk
→ Document
→ Report
→ Remediate
→ Verify
→ Close
```

## Phase 12 — Final Assessment

Final assessment must evaluate:

* Knowledge
* Tool selection
* Practical execution
* Output interpretation
* Evidence collection
* Finding classification
* Risk assessment
* Remediation
* Professional reporting

Completion requires:

```text
Knowledge Check
+
Practical Lab
+
Review
+
Progress Record
```

---

# 11. ALL-IN-ONE KALI TOOL SYSTEM

KSEC must be **Kali-aware**, not a hardcoded static wrapper.

It must dynamically inspect the local Kali environment.

Detect:

* Installed packages
* Installed binaries
* Tool versions
* Capabilities
* Categories
* Metapackages
* Dependencies
* Runtime environment
* Architecture
* Hardware
* Privileges
* Service state

Capability registry:

```text
Kali Tool
→ Package
→ Binary
→ Version
→ Category
→ Metapackage
→ KSEC Capability
→ Adapter
→ Parser
→ Evidence
→ Finding
```

---

# 12. MISSING TOOL INSTALLATION

If KSEC requires a capability that is not currently available, it must be able to identify a supported compatible tool.

Process:

```text
Capability Required
↓
Check Installed Tools
↓
Capability Missing
↓
Find Supported Tool
↓
Verify Source
↓
Check Compatibility
↓
Check Dependencies
↓
Request User Approval
↓
Install
↓
Verify Installation
↓
Register Capability
↓
Load Adapter
↓
Health Check
↓
Make Available
```

KSEC must NOT blindly execute arbitrary internet scripts.

Supported sources may include:

* Kali APT repositories
* Official vendor/project packages
* Official project repositories
* Python packages
* Go packages
* Rust packages
* Verified standalone binaries
* Local packages
* Offline packages
* Containers where appropriate

External software must undergo source and compatibility validation.

---

# 13. KALI ENVIRONMENT FINGERPRINTING

Before a workflow starts, KSEC should identify:

* Kali release
* Kernel
* Architecture
* Runtime
* Privilege state
* APT health
* Installed tools
* Tool versions
* Required dependencies
* Optional dependencies
* Hardware capabilities
* Network state
* Virtualization/container environment

Supported environments may include:

* Bare metal
* Virtual machines
* WSL
* Containers
* ARM
* NetHunter
* Other supported Kali environments

---

# 14. KALI METAPACKAGE AWARENESS

KSEC must understand Kali metapackages.

It should detect:

* Installed metapackages
* Missing metapackages
* Partial capability coverage
* Capability readiness
* Relevant category groups

KSEC must never assume that because Kali is installed, every security tool is installed.

---

# 15. KALI VERSION AND COMPATIBILITY

KSEC must track:

* Kali version
* Kernel version
* Tool versions
* Adapter compatibility
* Dependency compatibility
* Known incompatibilities
* Environment snapshots

Engagements must optionally support environment freezing to reduce accidental changes during an assessment.

---

# 16. KALI SERVICE MANAGEMENT

KSEC should understand supported service helpers and service states.

Before starting a service:

```text
Check status
↓
Already running?
→ Reuse
```

If stopped:

```text
Start
↓
Verify
↓
Register state
```

KSEC must avoid blindly restarting services that are already running.

---

# 17. USER INTERFACE

KSEC must provide:

## CLI

Examples:

```bash
ksec
ksec assess TARGET
ksec recon TARGET
ksec network TARGET
ksec web TARGET
ksec vuln TARGET
ksec research TARGET
ksec dfir CASE
ksec osint TARGET
ksec tools
ksec learn
ksec jobs
ksec reports
ksec session list
```

## TUI

Provide:

* Menus
* Live progress
* Current stage
* Current tool
* Findings
* Evidence
* Jobs
* Pause
* Resume
* Cancel
* Details
* Learn

## Optional Local Dashboard

Pages:

* Overview
* Assets
* Findings
* Cases
* Evidence
* Workflows
* Jobs
* Threat Intelligence
* Reports
* Learning
* Tools
* Users
* Audit Logs
* System Health

---

# 18. THREE OPERATION MODES

## Beginner

```text
Target
→ Start
→ Understand
→ Result
```

## Professional

```text
Target
→ Profile
→ Modules
→ Options
→ Execute
→ Analyze
→ Report
```

## Expert

Expose:

* Tool selection
* Arguments
* Adapters
* Workflows
* Parsers
* Execution
* Raw output
* Logs
* Environment
* Advanced configuration

Principle:

**Hide complexity, never hide useful information.**

---

# 19. TOOL EXPLANATION SYSTEM

Every tool being used must expose understandable information.

Display:

* Tool name
* Simple description
* Technical description
* Category
* Why selected
* What it does
* What KSEC will do
* Data collected
* Risk
* Privilege requirements
* Inputs
* Outputs
* Status
* Progress
* Learn More

Example:

### Beginner

"This tool looks for doors that are open on a computer or network."

### Technical

"This capability performs authorized port and service enumeration."

The same tool must be understandable to someone with very little technical knowledge while still providing professional technical details.

---

# 20. RESULT EXPLANATION

Every important result should answer:

### What happened?

### Why does it matter?

### What evidence supports it?

### What should happen next?

For risk:

### Why did KSEC mark this High?

KSEC must provide deterministic explanations based on actual risk factors.

---

# 21. MULTI-TERMINAL MODEL

KSEC must support five simultaneous workspaces:

```text
Terminal 1 → Red Team
Terminal 2 → Blue Team
Terminal 3 → Research / OSINT
Terminal 4 → Adversary Simulation
Terminal 5 → Learn + Work
```

One person must be able to operate all five simultaneously.

Five different people must also be able to use their assigned workspace simultaneously.

Each session must maintain independent:

* Role
* Workspace
* Permissions
* History
* Jobs
* State
* Environment
* Context

---

# 22. SHARED STATE

Relevant information may be shared between workspaces according to permissions.

Examples:

```text
Research
→ Asset Intelligence
→ Red Team
```

```text
Red Team Finding
→ Blue Team
```

```text
Adversary Simulation
→ Blue Team Detection
```

```text
Blue Team IOC
→ Research / Threat Intelligence
```

Shared information must preserve provenance and access control.

---

# 23. CENTRAL JOB SCHEDULER

KSEC must provide:

* Job queue
* Priority
* Concurrency
* Resource limits
* Timeouts
* Retry
* Pause
* Resume
* Cancel
* Recovery
* Job persistence
* Job isolation
* Resource monitoring

Jobs must survive terminal disconnects when possible.

---

# 24. AUTHORIZATION AND SCOPE

KSEC must provide:

* Authorization records
* Target allowlists
* Target blocklists
* Scope definitions
* Rules of Engagement
* Lab/CTF mode
* Safe mode
* Read-only mode
* Rate limits
* Concurrency limits
* Destructive-action confirmation
* Emergency stop
* Full audit trail

Out-of-scope targets must be blocked.

---

# 25. ROLE-BASED ACCESS CONTROL

KSEC must implement RBAC.

Permissions must be defined at:

* Workspace
* Module
* Command
* Action
* Resource
* Tool
* Workflow
* Evidence
* Case

Roles and threat-actor profiles must remain separate concepts.

---

# 26. RISK ENGINE

Risk must be deterministic and explainable.

Factors:

* Severity
* Asset criticality
* Exploitability
* Exposure
* Business impact
* Confidence
* Evidence quality

Output:

```text
Critical
High
Medium
Low
Info
```

Every risk result must include its reasoning.

Risk calculations must be versioned.

---

# 27. DATA MODEL

Core entities:

```text
Users
Roles
Workspaces
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
Threat Actors
Campaigns
TTPs
Workflows
Jobs
Tool Runs
Reports
Controls
Policies
Audit Logs
Notifications
Plugins
Integrations
Backups
Configs
Sessions
Session Roles
Job Locks
Learning Profiles
Lessons
Exercises
Learning Progress
Assessments
```

Relationship:

```text
Asset
→ Service
→ Finding
→ Evidence
→ Risk
→ Case
→ Remediation
→ Verification
```

---

# 28. EVIDENCE MANAGEMENT

Evidence must support:

* Source
* Timestamp
* Hash
* Provenance
* Collection method
* Tool
* Tool version
* Operator
* Session
* Engagement
* Integrity
* Chain-of-custody
* Retention
* Export

Evidence must never silently change.

---

# 29. CASE MANAGEMENT

Cases must support:

* Case creation
* Assets
* Findings
* Evidence
* Events
* IOCs
* Notes
* Tasks
* Timeline
* Severity
* Status
* Ownership
* Remediation
* Verification
* Closure

---

# 30. REPORTING

KSEC must produce professional reports.

Reports should support:

* Executive summary
* Scope
* Authorization
* Methodology
* Assets
* Findings
* Severity
* Risk
* Evidence
* Technical details
* Impact
* Recommendations
* Remediation
* Retesting
* Conclusion
* Appendix

Reports must preserve evidence provenance.

---

# 31. PLUGIN AND ADAPTER ARCHITECTURE

KSEC must use modular adapters.

Structure:

```text
plugins/
├── discovery/
├── network/
├── web/
├── api/
├── wireless/
├── vulnerability/
├── cloud/
├── containers/
├── endpoint/
├── dfir/
├── malware/
├── threat_intel/
├── reporting/
├── compliance/
└── integrations/
```

Each adapter should define:

* Tool name
* Version
* Capabilities
* Dependencies
* Privilege requirements
* Inputs
* Outputs
* Parser
* Error handling
* Supported platforms
* Safety classification

---

# 32. CORE ORCHESTRATION PIPELINE

```text
Detect Tools
↓
Identify Capabilities
↓
Check Versions
↓
Check Dependencies
↓
Select Suitable Tool
↓
Build Validated Command
↓
Execute
↓
Capture Output
↓
Parse
↓
Normalize
↓
Correlate
↓
Store Evidence
↓
Create Findings
↓
Calculate Risk
↓
Update Case
↓
Generate Report
```

---

# 33. AUTOMATION

Users should be able to create reusable workflows.

Examples:

```bash
ksec workflow create
ksec workflow list
ksec workflow validate
ksec workflow run NAME TARGET
```

Custom workflow:

```bash
ksec run my-standard-assessment TARGET
```

Workflows must respect:

* Authorization
* Scope
* RBAC
* Tool availability
* Resource limits
* Safety policies

---

# 34. OBSERVABILITY

KSEC must expose:

* Structured logs
* Job history
* Tool execution history
* Performance metrics
* Resource usage
* Error logs
* Audit events
* Plugin health
* Tool health
* System health
* Diagnostic bundle

Health states:

```text
HEALTHY
WARNING
ERROR
```

---

# 35. BACKUP AND RECOVERY

Back up:

* Configuration
* Cases
* Evidence
* Reports
* Plugin configuration
* Learning progress
* Database
* Audit records

Support:

* Encrypted local backups
* Optional remote backups
* Restore verification
* Disaster recovery
* Backup integrity checks

---

# 36. UPDATE SYSTEM

Support updates for:

* KSEC
* Plugins
* Adapters
* Dependencies

Requirements:

* Version compatibility
* Update verification
* Rollback
* Offline update
* Failed-update recovery
* Migration handling

---

# 37. OFFLINE / AIR-GAPPED OPERATION

Core KSEC functionality must operate without internet where possible.

Support:

* Offline tool metadata
* Local documentation
* Offline packages
* Local intelligence sources
* Local backups
* Offline reports
* Offline learning
* Air-gapped environments

Internet-dependent features must clearly show that dependency.

---

# 38. SECURITY MODEL

KSEC itself must be security-critical software.

Implement:

* Secure defaults
* Least privilege
* Input validation
* Command validation
* Path validation
* Secrets protection
* Authentication
* Authorization
* RBAC
* Audit logging
* Secure storage
* Secure update verification
* Plugin trust controls
* Dependency verification
* Tamper detection where appropriate

Never trust tool output blindly.

---

# 39. SECRET MANAGEMENT

Support secure handling of:

* API keys
* Passwords
* Tokens
* SSH credentials
* Certificates
* Private keys

Do not expose secrets in:

* Logs
* Reports
* Screens
* Error messages
* Shell history

unless explicitly required and authorized.

---

# 40. ERROR HANDLING

Every subsystem must have structured errors.

Errors must explain:

* What failed
* Why it failed
* Which component failed
* Suggested remediation
* Whether retry is safe
* Whether user action is required

Never silently ignore failures.

---

# 41. TESTING

Implement:

### Unit Tests

* Core
* Database
* Parsers
* Risk engine
* Policy engine
* Learning engine

### Integration Tests

* Tool adapters
* Workflow engine
* Database
* Evidence
* Reporting
* Scheduler

### Security Tests

* RBAC
* Authorization
* Scope enforcement
* Secret handling
* Plugin validation
* Update verification

### Concurrency Tests

* Five simultaneous terminals
* Multiple simultaneous jobs
* Shared state consistency
* Job isolation
* Session isolation

### Recovery Tests

* Crash
* Tool failure
* Network failure
* Dependency failure
* Interrupted job
* Database recovery

### Learning Tests

* Curriculum progression
* Lab completion
* Knowledge checks
* Practical assessments
* Progress tracking

---

# 42. PERFORMANCE

KSEC must be designed for laptop-first operation.

Avoid unnecessary CPU, RAM and storage consumption.

Resource-aware scheduling must prevent one workflow from starving the entire system.

The system should detect:

* CPU
* RAM
* Disk
* GPU
* Network
* Hardware capabilities

and adapt workloads accordingly.

---

# 43. ACCESSIBILITY

Support:

* Keyboard navigation
* High contrast
* Color-blind-safe presentation
* Colors never being the sole signal
* Screen-reader-friendly text
* Plain-text mode
* Large-text mode
* Headless operation

---

# 44. DOCUMENTATION

The project must include:

```text
docs/
├── Installation
├── Quick Start
├── User Guide
├── Red Team Guide
├── Blue Team Guide
├── Research / OSINT Guide
├── Adversary Simulation Guide
├── Learning Guide
├── Learning Curriculum
├── DFIR Guide
├── Threat Intelligence Guide
├── Admin Guide
├── Security Model
├── Architecture
├── CLI Reference
├── Workflow Reference
├── Plugin Development
├── Adapter Development
├── API Reference
├── Database Schema
├── Troubleshooting
├── Backup & Recovery
└── FAQ
```

---

# 45. GITHUB-READY PROJECT

The generated repository must be professionally organized.

Include:

* README
* LICENSE
* CONTRIBUTING
* SECURITY
* CHANGELOG
* CODE_OF_CONDUCT
* Issue templates
* Pull request templates
* Documentation
* Tests
* CI configuration
* Release configuration
* Installation scripts
* Development environment
* Example configurations
* Example workflows

Do not place secrets in the repository.

---

# 46. VERSION CONTROL

Use semantic versioning:

```text
MAJOR.MINOR.PATCH
```

Example:

```text
0.1.0
0.2.0
1.0.0
```

All database, API and configuration changes must be migration-aware.

---

# 47. DEVELOPMENT RULES

While implementing KSEC:

1. Do not remove requirements silently.
2. Do not invent undocumented behavior.
3. Do not hardcode the Kali tool ecosystem.
4. Do not make AI/LLM services a dependency.
5. Do not bypass authorization controls.
6. Do not bypass scope controls.
7. Do not blindly install software from untrusted sources.
8. Do not hide important technical information.
9. Do not silently ignore errors.
10. Do not mark unfinished functionality as complete.
11. Do not create fake tool integrations.
12. Do not claim compatibility without testing.
13. Maintain backward compatibility where practical.
14. Write tests for implemented functionality.
15. Update documentation when behavior changes.

---

# 48. DEFINITION OF DONE

KSEC is not considered complete merely because the application starts.

A feature is complete only when:

```text
Implemented
+
Integrated
+
Tested
+
Error Handled
+
Documented
+
Security Reviewed
+
Accessible
+
Recoverable
```

The final system must:

* Install on Kali
* Detect its environment
* Detect available tools
* Detect missing capabilities
* Install supported missing tools with approval
* Verify installations
* Register tools
* Execute workflows
* Parse outputs
* Normalize results
* Correlate findings
* Manage evidence
* Calculate risk
* Manage cases
* Generate reports
* Support five concurrent workspaces
* Support multiple users/sessions
* Support learning
* Enforce authorization
* Enforce scope
* Maintain audit trails
* Recover from failures
* Backup and restore data
* Operate offline where possible
* Pass the defined test suite
* Be GitHub-ready

---

# 49. FINAL PRODUCT VISION

The finished product should feel like:

**One security operating environment running on Kali Linux.**

The user should think:

> "I am using KSEC."

Not:

> "Which Kali tool do I need next?"

KSEC should intelligently orchestrate the appropriate verified capabilities behind the unified interface.

The platform should make complex cybersecurity workflows easier to execute, understand, document and repeat without hiding important technical information.

---

# 50. FINAL IMPLEMENTATION COMMAND

Build KSEC according to this specification.

Do not treat this document as a conceptual proposal.

Treat it as the **master implementation contract**.

Before implementing any subsystem:

1. Identify its requirements.
2. Identify dependencies.
3. Define interfaces.
4. Implement it.
5. Test it.
6. Integrate it.
7. Document it.
8. Verify it against this specification.

Maintain a machine-readable implementation checklist.

Every requirement must have a status:

```text
PLANNED
IN_PROGRESS
IMPLEMENTED
TESTED
VERIFIED
BLOCKED
```

Never mark a requirement `VERIFIED` without evidence.

If a requirement conflicts with another requirement, stop and resolve the conflict explicitly rather than silently choosing one.

If a required capability cannot be implemented because the underlying Kali environment or external dependency does not support it, report the limitation clearly and provide the safest compatible fallback.

---

# 51. MASTER SUCCESS CRITERIA

The final KSEC system must satisfy these principles:

### Unified

One primary interface.

### Modular

Tools and capabilities can be added or removed without rewriting the core.

### Kali-aware

The platform adapts to the actual Kali environment.

### AI-free

No AI/LLM/API dependency.

### Explainable

Users understand what KSEC is doing and why.

### Safe

Authorization and scope are enforced.

### Professional

Evidence, risk, cases and reports are first-class objects.

### Educational

Beginners can learn while doing authorized work.

### Concurrent

Five workspaces can operate simultaneously.

### Recoverable

Jobs and state survive failures where possible.

### Extensible

New tools and capabilities can be added through adapters/plugins.

### Offline-capable

Core functions work without cloud services.

### GitHub-ready

The repository is structured for professional development and collaboration.

---

# 52. FINAL ARCHITECTURE

```text
                         ONE KALI LINUX OS
                                │
                                ▼
                         ┌──────────────┐
                         │     KSEC     │
                         │   CORE       │
                         └──────┬───────┘
                                │
        ┌───────────┬───────────┼───────────┬───────────┐
        ▼           ▼           ▼           ▼           ▼
      RED         BLUE       RESEARCH    ADVERSARY   LEARN+WORK
      TEAM        TEAM       / OSINT     SIMULATION
        │           │           │           │           │
        └───────────┴───────────┴───────────┴───────────┘
                                │
                                ▼
                     SESSION / STATE ENGINE
                                │
                                ▼
                     CENTRAL JOB SCHEDULER
                                │
                                ▼
                       WORKFLOW ENGINE
                                │
                                ▼
                     POLICY / SCOPE ENGINE
                                │
                                ▼
                      KALI CAPABILITY LAYER
                                │
                 ┌──────────────┼──────────────┐
                 ▼              ▼              ▼
            Installed       Missing        External
              Tools        Capability       Sources
                 │              │              │
                 │              ▼              │
                 │      Installation Manager   │
                 │              │              │
                 └──────────────┴──────────────┘
                                │
                                ▼
                     TOOL ADAPTERS / PLUGINS
                                │
                                ▼
                         TOOL EXECUTION
                                │
                                ▼
                            PARSERS
                                │
                                ▼
                         NORMALIZATION
                                │
                                ▼
                          CORRELATION
                                │
                 ┌──────────────┼──────────────┐
                 ▼              ▼              ▼
              FINDINGS        EVIDENCE         ASSETS
                 │              │              │
                 └──────────────┼──────────────┘
                                ▼
                           RISK ENGINE
                                │
                                ▼
                         CASE MANAGEMENT
                                │
                                ▼
                            REPORTING
                                │
                                ▼
                     REMEDIATION / VERIFY
                                │
                                ▼
                          FINAL RESULTS
```

# END OF PDF 01

**KSEC Master Build Prompt & Complete Product Specification — Version 1.0**
