"""Learning curriculum (spec: END-TO-END LEARNING CURRICULUM).

Twelve phases from orientation to final assessment, plus the five learner
level profiles. Content is local, AI-free and built into the platform.
"""
from __future__ import annotations

from dataclasses import dataclass

# Spec section 9: five learning levels.
LEARNING_LEVELS: dict[int, str] = {
    1: "Explorer",
    2: "Beginner",
    3: "Learner",
    4: "Advanced Learner",
    5: "Security Practitioner",
}


@dataclass(frozen=True)
class LearningLesson:
    id: str
    title: str
    summary: str
    content: str


@dataclass(frozen=True)
class LearningPhase:
    number: int
    title: str
    description: str
    lessons: tuple[LearningLesson, ...]


CURRICULUM: tuple[LearningPhase, ...] = (
    LearningPhase(
        0, "Orientation",
        "KSEC, cybersecurity, authorized testing, ethics, scope and safety.",
        (
            LearningLesson(
                "orientation.what-is-ksec",
                "What is KSEC?",
                "KSEC is one unified interface that orchestrates Kali security tools.",
                "KSEC runs on Kali Linux and coordinates many security tools behind one "
                "interface. You interact with KSEC instead of switching between dozens of "
                "separate tools. Everything runs locally and works offline; no AI or cloud "
                "service is required.",
            ),
            LearningLesson(
                "orientation.authorization",
                "Authorization and ethics",
                "Only ever test systems you are authorized to test.",
                "Cybersecurity work is legal and professional only when it has clear "
                "authorization and scope. KSEC enforces scope rules: targets outside your "
                "engagement are blocked. Never test a system you do not own or have written "
                "permission to test.",
            ),
        ),
    ),
    LearningPhase(
        1, "Computer Basics",
        "Hardware, operating systems, files, processes and users.",
        (
            LearningLesson(
                "basics.files",
                "Files and directories",
                "Everything on a computer is stored as files organized in directories.",
                "Files hold data; directories (folders) organize them. A path describes "
                "where a file lives, for example /etc/passwd. Permissions control who can "
                "read, write or execute each file.",
            ),
            LearningLesson(
                "basics.processes",
                "Processes and services",
                "Programs running on your computer are processes.",
                "A process is a running program with its own memory and state. Services are "
                "processes that run in the background, such as a web server listening on a "
                "port. Understanding processes is essential for security investigation.",
            ),
        ),
    ),
    LearningPhase(
        2, "Linux",
        "Terminal, commands, paths, permissions, packages and Kali fundamentals.",
        (
            LearningLesson(
                "linux.terminal",
                "The terminal",
                "The terminal is the primary way to interact with Linux.",
                "Commands are typed into a shell. Common commands: ls (list files), cd "
                "(change directory), cat (print a file), man (read documentation). Kali "
                "pre-installs hundreds of security tools you can launch from the terminal.",
            ),
            LearningLesson(
                "linux.permissions",
                "Permissions and users",
                "Linux separates users and controls access with permissions.",
                "Every file has an owner and read/write/execute permissions for the owner, "
                "the group and everyone else. The root user can do anything. Security tools "
                "often need specific privileges; KSEC checks and reports privilege state.",
            ),
        ),
    ),
    LearningPhase(
        3, "Networking",
        "IP, DNS, TCP/UDP, ports, protocols and HTTP.",
        (
            LearningLesson(
                "network.ip",
                "IP addresses and ports",
                "Computers are addressed by IP; services live on ports.",
                "An IP address identifies a computer on a network (IPv4 like 192.168.1.1, "
                "IPv6 like 2001:db8::1). A port numbers a service on that computer: 22 is "
                "SSH, 80 is HTTP, 443 is HTTPS. Port scanning asks which ports are open.",
            ),
            LearningLesson(
                "network.dns",
                "DNS",
                "DNS turns domain names into IP addresses.",
                "The Domain Name System maps names like example.com to IP addresses. "
                "Reconnaissance often starts with DNS lookups to discover the infrastructure "
                "behind a domain.",
            ),
        ),
    ),
    LearningPhase(
        4, "Security Fundamentals",
        "Vulnerability, threat, risk, authentication, encryption and logging.",
        (
            LearningLesson(
                "security.risk",
                "Vulnerability and risk",
                "A vulnerability is a weakness; risk combines likelihood and impact.",
                "KSEC calculates risk deterministically from severity, asset criticality, "
                "exploitability, exposure, impact, confidence and evidence quality. Every "
                "risk score includes its reasoning so you can understand why it was marked "
                "High or Critical.",
            ),
            LearningLesson(
                "security.controls",
                "Security controls",
                "Controls protect confidentiality, integrity and availability.",
                "Authentication verifies identity, authorization decides what an identity "
                "may do, and encryption protects data. Logging records what happened. KSEC "
                "applies these same ideas to its own operation with RBAC, scope enforcement "
                "and an audit log.",
            ),
        ),
    ),
    LearningPhase(
        5, "Security Tools",
        "How to learn any tool: what, why, when, how, input, output, interpretation.",
        (
            LearningLesson(
                "tools.framework",
                "The tool learning framework",
                "Learn every tool the same structured way.",
                "For each tool ask: What is it? Why use it? When is it appropriate? How does "
                "it work? What input does it need? What output does it produce? How do you "
                "interpret that output? KSEC's adapters package tools so the same workflow "
                "pattern applies everywhere.",
            ),
        ),
    ),
    LearningPhase(
        6, "Reconnaissance",
        "Target, scope, discovery, enumeration, evidence and findings.",
        (
            LearningLesson(
                "recon.workflow",
                "The reconnaissance workflow",
                "Recon finds and maps a target's exposed surface.",
                "Define the target, confirm it is in scope, discover assets (domains, IPs), "
                "enumerate services, collect evidence, and turn observations into findings. "
                "Run it with: ksec assess TARGET --workflow recon.",
            ),
        ),
    ),
    LearningPhase(
        7, "Web / API Security",
        "HTTP, requests, responses, authentication and common weaknesses.",
        (
            LearningLesson(
                "web.http",
                "HTTP fundamentals",
                "Web applications communicate over HTTP requests and responses.",
                "A request has a method (GET, POST), a URL, headers and optionally a body; "
                "a response has a status code (200 OK, 403 Forbidden) and content. Common "
                "weaknesses include injection, broken authentication and misconfiguration.",
            ),
        ),
    ),
    LearningPhase(
        8, "Defensive Security",
        "Logs, monitoring, detection, investigation and hardening.",
        (
            LearningLesson(
                "defense.detection",
                "Monitoring and detection",
                "Defenders monitor systems to detect suspicious activity.",
                "Collect logs, watch for indicators, investigate anomalies, contain "
                "incidents and harden systems so attacks fail. The Blue Team workspace "
                "covers monitoring, auditing and incident investigation.",
            ),
        ),
    ),
    LearningPhase(
        9, "DFIR",
        "Evidence, preservation, timelines, artifacts and investigation.",
        (
            LearningLesson(
                "dfir.evidence",
                "Evidence handling",
                "Forensic evidence must stay intact and provable.",
                "Preserve evidence, record when and how it was collected, and keep a chain "
                "of custody. KSEC hashes evidence (SHA-256) so any change is detected — "
                "evidence must never silently change.",
            ),
        ),
    ),
    LearningPhase(
        10, "OSINT / Threat Intelligence",
        "Public information, indicators, domains, IPs and source reliability.",
        (
            LearningLesson(
                "osint.intel",
                "OSINT basics",
                "Open-source intelligence uses public information legally.",
                "Collect public data: domains, IPs, certificates, documents and accounts. "
                "Rate sources by reliability and confidence. The Research / OSINT workspace "
                "supports this with provenance tracking.",
            ),
        ),
    ),
    LearningPhase(
        11, "Professional Workflow",
        "Scope, authorization, discovery, analysis, evidence, reporting, remediation.",
        (
            LearningLesson(
                "professional.engagement",
                "Running an engagement",
                "Professional assessments follow a documented lifecycle.",
                "Initialize, define scope, verify authorization, discover, analyze, "
                "validate, collect evidence, assess risk, document, report, remediate, "
                "verify and close. KSEC models this lifecycle with engagements, "
                "authorizations, findings, evidence and cases.",
            ),
        ),
    ),
    LearningPhase(
        12, "Final Assessment",
        "Knowledge check, practical lab, review and progress record.",
        (
            LearningLesson(
                "assessment.final",
                "Final assessment",
                "Complete the curriculum with a knowledge check and practical lab.",
                "The final assessment evaluates tool selection, execution, output "
                "interpretation, evidence collection, finding classification, risk "
                "assessment, remediation and reporting. Completion requires a knowledge "
                "check, a practical lab, a review and a progress record.",
            ),
        ),
    ),
)


def phases() -> list[LearningPhase]:
    return list(CURRICULUM)


def lesson_count() -> int:
    return sum(len(phase.lessons) for phase in CURRICULUM)


def find_lesson(lesson_id: str) -> tuple[LearningPhase, LearningLesson] | None:
    for phase in CURRICULUM:
        for lesson in phase.lessons:
            if lesson.id == lesson_id:
                return phase, lesson
    return None