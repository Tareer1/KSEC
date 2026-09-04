Boss, **PDF 3** ka focus exact **CLI + TUI + 5-Terminal UX + Beginner/Professional/Expert experience + Tool Explainability + Learn+Work interface + Accessibility** hoga.

# KSEC — CLI, TUI & FIVE-TERMINAL USER EXPERIENCE SPECIFICATION

**Version:** 1.0
**Status:** Build-Ready / Final Specification
**Platform:** Kali Linux
**Architecture:** Single KSEC Core + Multiple Concurrent Sessions
**AI Dependency:** None

---

# 1. PURPOSE

This document defines the complete user-experience and interface specification for KSEC.

KSEC must provide one unified security interface instead of forcing operators to manually switch between Kali Linux security tools.

The primary interaction model is:

**User → KSEC → Workflow → Tool Selection → Tool Execution → Parsing → Correlation → Evidence → Finding → Risk → Report**

Kali tools operate behind KSEC as capability providers.

The user should normally interact with KSEC rather than individual underlying tools.

---

# 2. MASTER UX PRINCIPLE

> **Hide complexity, never hide useful information.**

KSEC must be simple enough for a beginner to understand while remaining powerful enough for an experienced security professional.

The interface must never sacrifice technical visibility merely to make the system look simple.

Every operation must support progressive detail.

---

# 3. SUPPORTED INTERFACES

KSEC provides four primary interfaces:

1. CLI
2. TUI
3. Optional Local Web Dashboard
4. Learning Interface

All interfaces must use the same underlying KSEC core.

They must not implement separate business logic.

```text
                 KSEC CORE
                     │
       ┌─────────────┼─────────────┐
       ↓             ↓             ↓
      CLI           TUI       Web Dashboard
       │             │             │
       └─────────────┼─────────────┘
                     ↓
              Shared Services
                     │
              Shared Database
```

Learning functionality is also connected to the same core but maintains separate educational state.

---

# 4. FIVE TERMINAL WORKSPACE MODEL

KSEC supports five primary concurrent workspaces.

```text
Terminal 1 → RED TEAM
Terminal 2 → BLUE TEAM
Terminal 3 → RESEARCH / OSINT
Terminal 4 → ADVERSARY SIMULATION
Terminal 5 → LEARN + WORK
```

These are logical KSEC sessions.

They may be displayed as:

```text
┌──────────────┬──────────────┬──────────────┬──────────────┬──────────────┐
│ RED TEAM     │ BLUE TEAM    │ RESEARCH     │ ADVERSARY    │ LEARN + WORK │
│ Terminal 1   │ Terminal 2   │ Terminal 3   │ Terminal 4   │ Terminal 5   │
└──────────────┴──────────────┴──────────────┴──────────────┴──────────────┘
```

One person may operate all five simultaneously.

Five different people may also operate one workspace each.

The architecture must support both cases.

---

# 5. SESSION ISOLATION

Every session must maintain independent:

* Workspace
* Role
* Session ID
* Command history
* Active engagement
* Job list
* UI state
* Learning state where applicable
* Permissions
* Environment state
* Current target/scope
* Temporary files
* Logs
* Notifications

Sessions may access shared information only according to authorization and RBAC policy.

---

# 6. CLI DESIGN

The CLI is the primary automation and scripting interface.

Base command:

```bash
ksec
```

Examples:

```bash
ksec assess TARGET
ksec recon TARGET
ksec network TARGET
ksec web TARGET
ksec vuln TARGET
ksec research TARGET
ksec dfir CASE
ksec tools
ksec reports
ksec learn
ksec jobs
ksec session list
```

---

# 7. GLOBAL CLI OPTIONS

KSEC must support:

```text
-h, --help
-v, --version
-q, --quiet
--verbose
--debug
--no-color
--json
--non-interactive
--dry-run
--profile NAME
--workspace NAME
--config PATH
```

Example:

```bash
ksec assess example.local --dry-run
```

JSON:

```bash
ksec assess example.local --json
```

Non-interactive:

```bash
ksec assess example.local --non-interactive
```

---

# 8. CLI COMMAND GROUPS

The CLI must expose the following command groups.

## Core

```text
ksec init
ksec status
ksec doctor
ksec config
ksec version
ksec update
```

## Assessment

```text
ksec assess
ksec recon
ksec network
ksec web
ksec api
ksec vuln
ksec wireless
```

## Red Team

```text
ksec redteam
ksec redteam recon
ksec redteam assess
ksec redteam validate
ksec redteam findings
```

## Blue Team

```text
ksec blue
ksec blue monitor
ksec blue audit
ksec blue investigate
ksec blue harden
ksec blue incident
```

## Research / OSINT

```text
ksec osint
ksec research
ksec intel
ksec watchlist
ksec graph
```

## Adversary Simulation

```text
ksec adversary
ksec adversary profile
ksec adversary campaign
ksec adversary simulate
ksec adversary coverage
ksec adversary report
```

All adversary simulation operations must remain authorization- and scope-controlled.

## DFIR

```text
ksec dfir
ksec case
ksec evidence
ksec timeline
```

## Tools

```text
ksec tools
ksec tools list
ksec tools search
ksec tools info
ksec tools health
ksec tools install
ksec tools update
ksec tools remove
```

## Workflow

```text
ksec workflow
ksec workflow list
ksec workflow create
ksec workflow edit
ksec workflow validate
ksec workflow run
ksec workflow history
```

## Jobs

```text
ksec jobs
ksec jobs list
ksec jobs status
ksec jobs pause
ksec jobs resume
ksec jobs cancel
ksec jobs logs
```

## Sessions

```text
ksec session
ksec session list
ksec session open
ksec session close
ksec session switch
ksec session status
```

## Findings

```text
ksec findings
ksec finding show
ksec finding update
ksec finding verify
```

## Reports

```text
ksec reports
ksec report create
ksec report preview
ksec report export
```

## Learning

```text
ksec learn
ksec learn start
ksec learn continue
ksec learn lesson
ksec learn practice
ksec learn assess
ksec learn progress
```

---

# 9. CLI HELP SYSTEM

Every command must provide contextual help.

```bash
ksec --help
ksec assess --help
ksec recon --help
ksec redteam --help
ksec blue --help
ksec research --help
ksec adversary --help
ksec dfir --help
ksec tools --help
ksec workflow --help
ksec learn --help
```

Help must contain:

* Description
* Usage
* Arguments
* Options
* Examples
* Required permissions
* Safety restrictions
* Expected output
* Related commands
* Learning information where applicable

---

# 10. CLI OUTPUT LEVELS

KSEC supports multiple information levels.

## Minimal

Shows:

```text
Status
Success/failure
Critical result
```

## Normal

Shows:

```text
Operation
Progress
Findings
Warnings
Summary
```

## Verbose

Shows:

```text
Workflow stages
Selected tools
Tool status
Parser status
Evidence collection
Correlation
Risk calculation
```

## Debug

Shows:

```text
Internal execution information
Detailed logs
Adapter operations
Command construction metadata
Environment diagnostics
Parser diagnostics
State transitions
```

Sensitive secrets must never appear in normal/debug output unless explicitly authorized through secure administrative diagnostics.

---

# 11. DRY-RUN MODE

Before execution:

```bash
ksec assess TARGET --dry-run
```

KSEC displays:

```text
Scope Check       PASS
Authorization     PASS
Environment       READY

Planned Workflow:
1. Discovery
2. Enumeration
3. Service analysis
4. Vulnerability assessment
5. Evidence collection
6. Risk analysis
7. Report generation

Planned Tools:
Tool A
Tool B
Tool C

No commands executed.
```

Dry-run must not perform target interaction.

---

# 12. TUI

The TUI is an application-like terminal environment.

Example layout:

```text
┌───────────────────────────────────────────────────────────────┐
│ KSEC | RED TEAM | Engagement: ENG-001 | Status: ACTIVE       │
├───────────────┬───────────────────────────────────────────────┤
│ Navigation    │ Current Operation                            │
│               │                                               │
│ Dashboard     │ Discovery                                    │
│ Assets        │ ███████████████████░░ 82%                    │
│ Jobs          │                                               │
│ Findings      │ Tool: <adapter>                              │
│ Evidence      │ Stage: Service Enumeration                   │
│ Cases         │                                               │
│ Workflows     │ Findings: 7                                  │
│ Reports       │ Evidence: 14                                 │
│ Tools         │                                               │
│ Learning      │                                               │
│ Settings      │                                               │
├───────────────┴───────────────────────────────────────────────┤
│ [P] Pause [R] Resume [C] Cancel [D] Details [L] Learn        │
└───────────────────────────────────────────────────────────────┘
```

---

# 13. TUI NAVIGATION

Minimum navigation:

```text
Dashboard
Sessions
Assets
Jobs
Findings
Evidence
Cases
Workflows
Threat Intelligence
Tools
Reports
Learning
Users
Audit
System Health
Settings
```

Navigation must be keyboard accessible.

---

# 14. LIVE OPERATION VIEW

While a tool/workflow is running, KSEC must show:

* Current workflow
* Current stage
* Current tool
* Tool category
* Tool purpose
* Why it was selected
* What it is doing
* Progress
* Findings discovered
* Evidence collected
* Warnings
* Resource usage
* Permission status
* Scope status
* Cancel/pause controls
* Learning controls

Example:

```text
CURRENT OPERATION

Tool:
Service Enumeration Adapter

Simple explanation:
"This checks which network services are available."

Technical explanation:
"Enumerates reachable services and attempts to identify
service characteristics on the authorized target."

Why selected:
The discovery stage identified reachable network services.

Status:
RUNNING

Progress:
████████████████░░░░ 78%

Findings:
3

Evidence:
11 items

Risk:
Pending analysis
```

---

# 15. TOOL EXPLANATION SYSTEM

Every tool integrated into KSEC must have a Tool Card.

Minimum fields:

```text
Tool Name
Icon
Simple Description
Technical Description
Category
Purpose
When Used
Why Selected
Inputs
Outputs
Permissions
Dependencies
Supported Platforms
Runtime Expectations
Limitations
Safety Classification
Installed Version
Health
Documentation
Adapter Status
Parser Status
Related Tools
```

---

# 16. THREE EXPLANATION LEVELS

## Level 1 — Beginner

Example:

> “This tool looks for doors that are open on a computer or network.”

## Level 2 — Intermediate

> “This tool checks network ports and services to identify what is reachable.”

## Level 3 — Technical

> “The adapter performs service and port enumeration, normalizes discovered endpoints, and forwards structured results to the KSEC asset and finding engines.”

The user can switch explanation level at any time.

---

# 17. WHY DID KSEC SELECT THIS TOOL?

KSEC must explain tool selection.

Example:

```text
WHY THIS TOOL?

KSEC selected this tool because:

✓ Target is within authorized scope
✓ Network discovery is required
✓ Capability is available
✓ Tool is compatible with this Kali environment
✓ Required dependencies are installed
✓ Adapter is healthy

Alternative compatible tools:
Tool B
Tool C
```

---

# 18. WHAT IS KSEC DOING?

Every workflow must provide a human-readable explanation.

Example:

```text
WHAT IS HAPPENING?

KSEC is currently identifying services exposed by the
authorized target.

Why:
Knowing available services helps determine the target's
attack surface.

Next:
KSEC will analyze the discovered services for relevant
security issues.
```

---

# 19. WHAT HAPPENED?

After an operation:

```text
WHAT HAPPENED?

KSEC identified:

3 reachable services
1 potentially outdated service
2 informational observations

Why it matters:
An outdated service may increase security risk.

Evidence:
12 evidence items collected.

Next:
Review findings and recommended remediation.
```

---

# 20. RESULT PRESENTATION

Findings must be human-readable.

Example:

```text
FINDING #0042

Severity: HIGH
Asset: server01
Service: HTTPS
Confidence: HIGH

What happened:
The service configuration contains a security weakness.

Why it matters:
An attacker may be able to abuse the weakness under
certain conditions.

Evidence:
- Evidence-001
- Evidence-002
- Evidence-003

Recommended action:
Apply the recommended configuration change and verify
the service afterward.

[View Technical Details]
[View Evidence]
[Create Case]
[Add to Report]
[Learn Why]
```

---

# 21. RISK EXPLANATION

KSEC must explain why a finding receives its severity.

Example:

```text
WHY IS THIS HIGH?

Severity factors:

Asset Criticality: High
Exposure: High
Exploitability: Medium
Business Impact: High
Confidence: High
Evidence Quality: High

Overall Risk: HIGH
Risk Engine Version: 1.0
```

Risk calculation remains deterministic.

---

# 22. JOB MANAGEMENT UX

Every execution is a Job.

Supported states:

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

Jobs interface:

```text
JOB ID     WORKSPACE     TASK             STATUS
JOB-001    RED TEAM      Recon            RUNNING
JOB-002    BLUE TEAM     Log Analysis     RUNNING
JOB-003    RESEARCH      OSINT            PAUSED
JOB-004    ADVERSARY     Coverage Test    QUEUED
JOB-005    LEARN+WORK    Lab Exercise     RUNNING
```

Actions:

```text
View
Pause
Resume
Cancel
Logs
Details
Retry
```

---

# 23. FIVE-TERMINAL DASHBOARD

KSEC may provide a consolidated view:

```text
┌──────────────────────────────────────────────────────────────┐
│                    KSEC MULTI-TERMINAL                       │
├────────────┬────────────┬────────────┬────────────┬──────────┤
│ RED TEAM   │ BLUE TEAM  │ RESEARCH   │ ADVERSARY  │ LEARN    │
│ ACTIVE     │ ACTIVE     │ ACTIVE     │ PAUSED     │ ACTIVE   │
│ Job: 12    │ Job: 19    │ Job: 22    │ Job: 31    │ Job: 40  │
│ 67%        │ 43%        │ 81%        │ 31%        │ 55%      │
└────────────┴────────────┴────────────┴────────────┴──────────┘
```

The operator can switch between sessions without stopping jobs.

---

# 24. SESSION SWITCHING

Example:

```bash
ksec session list
```

Output:

```text
ID       WORKSPACE             STATUS
S001     RED_TEAM              ACTIVE
S002     BLUE_TEAM             ACTIVE
S003     RESEARCH_OSINT        ACTIVE
S004     ADVERSARY_SIMULATION  PAUSED
S005     LEARN_WORK            ACTIVE
```

Switch:

```bash
ksec session switch S003
```

Session switching must not terminate running jobs.

---

# 25. RED TEAM UX

Red Team workflow:

```text
Scope
 ↓
Authorization
 ↓
Recon
 ↓
Enumeration
 ↓
Assessment
 ↓
Validation
 ↓
Evidence
 ↓
Risk
 ↓
Report
 ↓
Remediation Verification
```

The UI must clearly indicate authorized scope.

Out-of-scope targets must be blocked.

---

# 26. BLUE TEAM UX

Blue Team workflow:

```text
Monitor
 ↓
Detect
 ↓
Investigate
 ↓
Correlate
 ↓
Contain
 ↓
Remediate
 ↓
Verify
 ↓
Document
```

Blue Team views prioritize:

* Alerts
* Events
* Hosts
* Processes
* Logs
* Authentication
* Findings
* Cases
* Evidence
* Remediation

---

# 27. RESEARCH / OSINT UX

Research workflow:

```text
Research Target
 ↓
Source Selection
 ↓
Collection
 ↓
Normalization
 ↓
Entity Resolution
 ↓
Correlation
 ↓
Confidence Assessment
 ↓
Intelligence Graph
 ↓
Finding / Intelligence Report
```

Every intelligence item must show:

* Source
* Timestamp
* Collection method
* Passive/active classification
* Confidence
* Reliability
* Scope
* Provenance

---

# 28. ADVERSARY SIMULATION UX

The adversary workspace must clearly identify itself as:

**AUTHORIZED ADVERSARY SIMULATION**

It must display:

```text
Exercise
Authorization
Scope
Threat Actor Profile
Selected TTPs
Simulation Stage
Detection Status
Evidence
Coverage
Gaps
Remediation
Retest
```

The interface must never present unrestricted real-world attack mode.

---

# 29. LEARN + WORK TERMINAL

The fifth terminal combines education and authorized practical work.

Example:

```text
LEARN + WORK

Current Lesson:
Understanding TCP Ports

Learning:
██████████████░░░░ 72%

Practice:
Lab Target

Operational Task:
Authorized Network Assessment

Concept:
Ports identify network services that may accept connections.

Practice Result:
22 → SSH
80 → HTTP
443 → HTTPS

[Explain]
[Practice Again]
[Continue Work]
```

The user may move between learning and work without leaving KSEC.

---

# 30. LEARNING MODE

Learning Mode must never simply provide answers.

It teaches through:

```text
Explain
 ↓
Demonstrate
 ↓
Practice
 ↓
Observe
 ↓
Interpret
 ↓
Correct
 ↓
Repeat
 ↓
Assess
```

Assistance progression:

```text
Hint
 ↓
Concept Explanation
 ↓
Guided Correction
 ↓
Detailed Guidance
```

The system should not immediately reveal the complete answer when learning is active.

---

# 31. LEARNING PROFILES

Five levels:

```text
1. Explorer
2. Beginner
3. Learner
4. Advanced Learner
5. Security Practitioner
```

Each profile changes:

* Explanation depth
* Task complexity
* Guidance amount
* Practice difficulty
* Required independence
* Assessment difficulty

---

# 32. LEARNING PROGRESS

Progress must be tracked per user/session.

Categories include:

```text
Computer Basics
Linux
Networking
Security Fundamentals
Recon
Web Security
API Security
Defensive Security
DFIR
OSINT
Threat Intelligence
Security Methodology
Professional Reporting
```

Example:

```text
NETWORKING

IP Addressing       ███████████░ 85%
TCP/UDP             ████████░░░ 68%
DNS                 █████████░░ 74%
Ports               ███████████ 91%
Routing              ██████░░░░ 54%
```

---

# 33. LEARNING + OPERATIONAL LINK

Learning and operational work may be connected.

Example:

```text
Lesson:
Understanding Services

        ↓

Practice:
Identify services in a lab

        ↓

Real Authorized Work:
Analyze discovered services

        ↓

Interpret:
Understand output

        ↓

Finding:
Create security observation

        ↓

Report:
Document professionally

        ↓

Skill Progress:
Service Enumeration +1
```

Operational permissions must remain separate from learning permissions.

---

# 34. BEGINNER MODE

Beginner workflow:

```text
Select Target
      ↓
Verify Authorization
      ↓
Start
      ↓
KSEC Explains
      ↓
Observe
      ↓
Understand Result
      ↓
Learn
```

The interface should minimize unnecessary configuration.

Example:

```text
TARGET
[ authorized-lab.local ]

WHAT WOULD YOU LIKE TO DO?

[ Understand This System ]
[ Check Security ]
[ Learn Networking ]
[ Explore Services ]
```

---

# 35. PROFESSIONAL MODE

Professional workflow:

```text
Target
Profile
Modules
Options
Execute
Analyze
Evidence
Findings
Risk
Report
```

Professionals can control:

* Workflow profile
* Modules
* Tool capabilities
* Scope
* Rate limits
* Concurrency
* Evidence requirements
* Reporting
* Validation

---

# 36. EXPERT MODE

Expert mode exposes advanced technical information.

Available information:

* Adapter
* Tool
* Tool version
* Command metadata
* Arguments
* Environment
* Raw output
* Parsed output
* Parser
* Workflow stage
* Execution timing
* Logs
* Resource usage
* Evidence
* Correlation
* State transitions

Expert mode must still respect authorization and safety controls.

---

# 37. PROGRESSIVE DISCLOSURE

KSEC must not overwhelm beginners.

Information is revealed progressively:

```text
Beginner
Simple explanation
       ↓
Professional
More technical details
       ↓
Expert
Complete technical execution details
```

No information is permanently hidden.

---

# 38. TOOL SEARCH

Users can search tools:

```bash
ksec tools search network discovery
```

Results:

```text
Matching capabilities:

1. Tool A
   Purpose: Network discovery
   Status: Available
   Health: Healthy

2. Tool B
   Purpose: Host discovery
   Status: Available
   Health: Healthy

3. Tool C
   Purpose: Service discovery
   Status: Missing
```

---

# 39. MISSING TOOL UX

If KSEC requires a capability that is unavailable:

```text
CAPABILITY REQUIRED

Capability:
Service Enumeration

Status:
NOT AVAILABLE

KSEC found:
2 compatible installation sources.

Source:
Verified package repository

Compatibility:
PASS

Dependencies:
PASS

Installation required.

[Install]
[Cancel]
```

Installation must require user approval where policy requires it.

After installation:

```text
Installation
 ↓
Verification
 ↓
Capability Registration
 ↓
Adapter Loading
 ↓
Health Check
 ↓
AVAILABLE
```

---

# 40. ERROR UX

Errors must be understandable.

Bad:

```text
Exit code 127
```

Better:

```text
OPERATION FAILED

KSEC could not start the required tool.

Likely reason:
The required executable is not installed.

Suggested action:
Open Tool Manager and install the missing capability.

Error Code:
KSEC-TOOL-001
```

Technical details remain available.

---

# 41. SAFETY UX

Before sensitive operations:

```text
AUTHORIZATION CHECK

Target:
10.10.10.20

Scope:
ENG-001

Authorization:
VALID

Action:
AUTHORIZED

Risk:
MODERATE

Continue?

[Yes] [No]
```

Out-of-scope:

```text
BLOCKED

The selected target is outside the authorized scope.

Target:
10.10.20.50

Reason:
Not included in ENG-001.

No operation was executed.
```

---

# 42. PRIVILEGE UX

If root is required:

```text
PRIVILEGE REQUIRED

This operation requires elevated privileges.

Reason:
Access to the requested system resource.

Elevate privileges?

[Yes] [No]
```

If already root:

```text
Privilege:
ROOT

No elevation required.
```

KSEC should avoid unnecessary repeated prompts.

---

# 43. ACCESSIBILITY

KSEC must support:

* Full keyboard navigation
* High contrast
* Color-blind-safe indicators
* Colors never being the only status signal
* Screen-reader-compatible text
* Plain-text output
* Large text where supported
* Clear labels
* Consistent navigation
* Descriptive error messages

Example:

Instead of only:

```text
🔴
```

Use:

```text
CRITICAL
```

---

# 44. COLOR AND STATUS SYSTEM

Status must use text plus visual indicators.

Example:

```text
[OK] HEALTHY
[!] WARNING
[X] ERROR
[>] RUNNING
[-] PAUSED
[✓] COMPLETED
```

Color may supplement the text but must never be required to understand the status.

---

# 45. NOTIFICATION SYSTEM

KSEC may notify users about:

* Job completion
* Critical findings
* Failed jobs
* Tool failures
* Installation requirements
* Scope violations
* Authorization problems
* System health problems
* Backup failures
* Security alerts

Notifications may be delivered through configured integrations.

---

# 46. COMMAND HISTORY

KSEC must maintain history per session.

Example:

```bash
ksec history
```

History must support:

* Search
* Re-run
* Filter by session
* Filter by workspace
* Timestamp
* Job ID
* User
* Engagement

Sensitive values must be redacted.

---

# 47. AUDIT VISIBILITY

Users with appropriate permission can inspect:

```text
Who
What
When
Where
Why
Authorization
Target
Action
Result
Evidence
```

Example:

```text
AUDIT EVENT

User: operator-01
Workspace: RED_TEAM
Action: Assessment Started
Target: authorized-lab.local
Authorization: ENG-001
Timestamp: 2026-09-04
Result: Completed
```

---

# 48. WEB DASHBOARD

The optional local dashboard should provide:

```text
Overview
Assets
Sessions
Jobs
Findings
Cases
Evidence
Workflows
Threat Intelligence
Tools
Reports
Learning
Users
Audit Logs
System Health
Settings
```

The web dashboard must use the same KSEC API and authorization model as CLI/TUI.

---

# 49. DASHBOARD OVERVIEW

Example:

```text
KSEC OVERVIEW

Active Sessions: 5
Running Jobs: 8
Critical Findings: 2
High Findings: 7
Open Cases: 4
Tool Health: 97%
System Health: HEALTHY

Recent Activity
-------------------------
Assessment completed
New finding discovered
Research watchlist updated
Learning assessment completed
```

---

# 50. UI CONSISTENCY RULE

The same object must appear consistently across interfaces.

For example:

```text
CLI Finding
TUI Finding
Web Finding
Report Finding
```

must refer to the same underlying Finding object.

The same applies to:

* Assets
* Jobs
* Cases
* Evidence
* Sessions
* Workflows
* Learning progress
* Tool records

---

# 51. OFFLINE UX

Core KSEC interfaces must continue operating without Internet access where functionality permits.

Offline mode must clearly show:

```text
NETWORK:
OFFLINE

Local capabilities:
AVAILABLE

Online intelligence:
UNAVAILABLE

Cached data:
AVAILABLE
```

KSEC must never pretend that an online source was queried when it was not.

---

# 52. PERFORMANCE UX

The interface must remain responsive while jobs execute.

Long-running tasks must run asynchronously.

The UI must never freeze because a security tool is executing.

Required controls:

```text
Pause
Resume
Cancel
View Logs
View Details
Switch Session
```

---

# 53. CRASH / RECONNECT UX

If the terminal closes while a job is running:

```text
SESSION DISCONNECTED

Running jobs:
JOB-001 — RUNNING
JOB-002 — PAUSED

Jobs remain active according to policy.

Reconnect with:

ksec session reconnect SESSION_ID
```

After reconnect:

```text
RECOVERY COMPLETE

Previous session state restored.
Running jobs detected.
```

---

# 54. EMPTY STATES

Empty states must teach the user.

Bad:

```text
No data.
```

Better:

```text
NO FINDINGS YET

Run an authorized assessment to begin collecting
security findings.

[Start Assessment]
[Learn About Findings]
```

---

# 55. CONFIRMATION DESIGN

Confirmation should be used when meaningful risk exists.

Example:

```text
CONFIRM ACTION

This operation may modify the authorized environment.

Target:
LAB-01

Action:
Configuration change

[Confirm]
[Cancel]
```

Routine read-only actions should not be burdened by unnecessary confirmation dialogs.

---

# 56. EXPERT RAW OUTPUT

Expert mode must allow viewing original tool output.

Display:

```text
NORMALIZED RESULT
↓
PARSER RESULT
↓
RAW TOOL OUTPUT
```

Evidence provenance must identify the source.

---

# 57. LEARNING TOOL CARD

Every tool lesson must follow:

```text
WHAT
WHY
WHEN
HOW
OUTPUT
INTERPRETATION
PRACTICE
COMMON MISTAKES
SAFETY
ASSESSMENT
```

Example:

```text
WHAT:
A network discovery tool finds systems that respond.

WHY:
You need to know which systems exist before analyzing them.

WHEN:
During authorized discovery.

HOW:
KSEC runs the appropriate capability through its adapter.

OUTPUT:
Discovered hosts.

INTERPRETATION:
A discovered host does not automatically mean it is vulnerable.

PRACTICE:
Try the lab exercise.
```

---

# 58. BEGINNER-FRIENDLY TERMINOLOGY

Technical terms must be explained the first time they appear.

Example:

```text
Port

Simple:
A numbered doorway used by network services.

Technical:
A transport-layer endpoint identified by a port number.
```

Terms may link to the local KSEC Security Encyclopedia.

---

# 59. NO-ASSUMPTION RULE

KSEC must not assume the operator understands:

* Linux
* Networking
* Security terminology
* Kali tools
* Ports
* Protocols
* Vulnerabilities
* Evidence
* Risk
* Reports

Beginner mode teaches the required concept before expecting the user to interpret it.

---

# 60. PROFESSIONAL INFORMATION PRESERVATION

Beginner simplification must never modify underlying data.

The same result must remain available as:

```text
Simple Explanation
Technical Explanation
Structured Data
Raw Evidence
Raw Tool Output
```

---

# 61. JSON OUTPUT

CLI automation must support structured output.

Example:

```bash
ksec findings list --json
```

JSON must be machine-readable and versioned.

No human-only formatting should be mixed into JSON mode.

---

# 62. NON-INTERACTIVE MODE

Automation must support:

```bash
ksec workflow run assessment-profile \
  --target TARGET \
  --non-interactive
```

Any action that normally requires confirmation must either:

* use an explicit policy-approved configuration, or
* fail safely.

KSEC must never silently bypass authorization requirements.

---

# 63. TAB COMPLETION

CLI autocomplete should support:

* Commands
* Subcommands
* Options
* Profiles
* Workspaces
* Sessions
* Jobs
* Workflow names
* Case IDs
* Finding IDs
* Tool names
* Capability names

---

# 64. SEARCH

KSEC must provide global search.

Searchable objects:

```text
Assets
Findings
Evidence
Cases
Jobs
Sessions
Tools
Reports
Threat Actors
Campaigns
IOCs
Learning Content
```

Example:

```bash
ksec search "web server"
```

---

# 65. CONTEXT-AWARE ACTIONS

The interface should present actions relevant to the current object.

For a Finding:

```text
View
Explain
Evidence
Risk
Create Case
Add to Report
Mark False Positive
Verify
Remediation
Learn
```

For a Tool:

```text
Info
Health
Capabilities
Run
Documentation
Dependencies
Update
Remove
```

---

# 66. MASTER UX FLOW

A standard KSEC operation should feel like:

```text
USER
 ↓
SELECT WORKSPACE
 ↓
SELECT TASK
 ↓
DEFINE/CONFIRM SCOPE
 ↓
VERIFY AUTHORIZATION
 ↓
CHECK ENVIRONMENT
 ↓
EXPLAIN PLAN
 ↓
EXECUTE
 ↓
SHOW LIVE PROGRESS
 ↓
EXPLAIN TOOL
 ↓
PARSE RESULTS
 ↓
SHOW FINDINGS
 ↓
EXPLAIN RISK
 ↓
STORE EVIDENCE
 ↓
CREATE CASE IF NEEDED
 ↓
RECOMMEND ACTION
 ↓
REPORT
 ↓
VERIFY REMEDIATION
 ↓
LEARN / UPDATE SKILL
```

---

# 67. FINAL UX REQUIREMENTS

KSEC UX is considered complete only when:

* CLI is fully documented
* CLI autocomplete works
* CLI help is complete
* JSON output works
* Non-interactive mode works
* TUI is operational
* Five concurrent workspaces work
* One user can operate all five
* Five users can operate separate sessions
* Sessions are isolated
* Jobs survive session disconnect
* Jobs can pause/resume/cancel
* Beginner mode works
* Professional mode works
* Expert mode works
* Tool Cards exist
* Tool explanations appear during execution
* “What happened?” explanations work
* “Why?” explanations work
* Risk explanations work
* Tool search works
* Tool health is visible
* Missing tool installation flow works
* Safety/authorization UI works
* Root/privilege UI works
* Learn+Work works
* Five learning levels work
* Learning progress is stored
* End-to-end curriculum is accessible
* Accessibility requirements are implemented
* Offline mode is understandable
* Errors are human-readable
* Raw technical information remains available
* Audit information is visible to authorized users
* Web dashboard, if enabled, uses the same API/core
* No AI is required for any UX function

---

# 68. FINAL MASTER UX RULE

> **KSEC must make professional cybersecurity workflows understandable to a complete beginner without reducing the technical power available to an expert.**

A 13-year-old beginner should be able to understand what KSEC is doing.

A learner should be able to understand why it is doing it.

A professional should be able to control the workflow.

An expert should be able to inspect the technical execution.

All four experiences must operate on the same KSEC core.

---

# 69. IMPLEMENTATION INSTRUCTION

The implementation agent must build this specification as a functional system, not as a mock interface.

Do not create placeholder buttons for core functionality.

Every visible action must map to a real backend capability, API endpoint, command, workflow, or documented unavailable state.

CLI, TUI, Web Dashboard, and Learning UI must share the same domain services.

Do not duplicate business logic between interfaces.

Maintain strict authorization, scope enforcement, RBAC, auditability, and safety controls across every interface.

The final implementation must satisfy the complete KSEC Definition of Done.

**PDF 3 is now locked as the implementation-grade UX/interface specification.** PDF 4 will be the big **Kali Integration + Complete Tool/Capability System** document, including dynamic Kali discovery, metapackages, tool installation, adapters, parsers, capability registry, compatibility and health system.
