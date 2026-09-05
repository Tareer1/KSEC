"""Curated knowledge base content.

Every entry is written for a human who may know *nothing* yet: concepts
start from zero, tool cards explain what the tool does in plain language
and how to run it through KSEC, and role playbooks give the exact ordered
commands for that job. Keywords include common Roman-Urdu spellings so
questions like "nmap kya hai" route correctly.
"""
from __future__ import annotations

from dataclasses import dataclass

# Section block types: "p" paragraph, "cmd" shell command, "tip" note.
_Section = tuple[str, str]


@dataclass(frozen=True)
class Topic:
    id: str
    title: str
    kind: str  # concept | tool | role | workflow | module
    audience: tuple[str, ...]  # all | red | blue | purple | learner
    summary: str  # the direct plain-language answer
    keywords: tuple[str, ...]  # search aliases (english + roman urdu)
    sections: tuple[_Section, ...]


# ---------------------------------------------------------------------------
# Core concepts (start from absolute zero)
# ---------------------------------------------------------------------------

TOPICS: tuple[Topic, ...] = (
    Topic(
        id="ksec",
        title="What is KSEC?",
        kind="concept",
        audience=("all",),
        summary=(
            "KSEC is a command-line platform that wraps Kali Linux security tools in one "
            "safe system: every action must match an authorized engagement, and results are "
            "parsed into a shared knowledge base (assets, findings, IOCs, cases, reports)."
        ),
        keywords=("ksec", "kya hai", "what is ksec", "tool", "platform", "software"),
        sections=(
            ("p", "Think of five people sharing one workspace: a Red Team operator (attacker role), a Blue Team analyst (defender), a Purple Team researcher (OSINT/threat intel), a Learner, and an Admin. Each works in their own workspace (RED_TEAM, BLUE_TEAM, RESEARCH_OSINT, ADVERSARY_SIMULATION, LEARN_WORK) but they all share one database, so one team's results feed the other teams."),
            ("p", "Two design rules matter most. 1) SAFETY FIRST: nothing runs against a target unless that target is inside an engagement's scope you created — out-of-scope targets are blocked automatically. 2) TOOLS THAT TALK: when dig, nmap or any tool runs, its output is parsed into structured records instead of being left as raw text."),
            ("p", "One OS (Kali), one KSEC install, one database, and as many terminals as you want — each terminal can act as a different team member."),
            ("cmd", "ksec status"),
            ("cmd", "ksec doctor"),
            ("cmd", "ksec tools list"),
            ("tip", "Everything you ask here with 'ksec ask' is answered inside the tool — you never need to leave."),
        ),
    ),
    Topic(
        id="ip-address",
        title="IP addresses — what they are and how KSEC uses them",
        kind="concept",
        audience=("all",),
        summary=(
            "An IP address is the unique 'postal address' of a device on a network (IPv4 like "
            "192.168.1.10, or IPv6 like 2001:db8::1). KSEC tracks IPs as assets, matches them "
            "against scope rules (including CIDR ranges) and registers them as IOCs when found."
        ),
        keywords=("ip", "ip address", "address", "internet protocol", "cidr", "ipv4", "ipv6", "range", "subnet", "ip address kya hai"),
        sections=(
            ("p", "Every device that talks on a network needs a number so other devices can find it — that number is its IP address. IPv4 looks like 192.168.1.10; IPv6 looks like 2001:db8::1."),
            ("p", "Some ranges are private (only used inside a network): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16. 127.0.0.1 is 'this machine itself' (localhost)."),
            ("p", "A CIDR range like 10.0.0.0/8 means 'any address starting with 10.' — KSEC scope rules accept ranges like this, so you can allow or deny a whole network at once."),
            ("p", "In KSEC, discovered addresses become ip assets automatically, and an ip linked to known-bad activity becomes an IOC in the intel module."),
            ("cmd", "ksec asset list"),
            ("cmd", "ksec engagement scope add --engagement 1 --target 10.0.0.0/8 --effect deny"),
            ("tip", "Run 'ksec run port_scan <ip>' to see which doors (ports) that address has open."),
        ),
    ),
    Topic(
        id="port",
        title="Ports — the doors on a machine",
        kind="concept",
        audience=("all",),
        summary=(
            "A port is a numbered 'door' on a machine that a service listens on. Port 22 is SSH, "
            "80 is HTTP, 443 is HTTPS, 445 is Windows file sharing (SMB). Scanning ports finds "
            "which doors are open and what runs behind them."
        ),
        keywords=("port", "ports", "port scan", "open port", "service", "door", "port kya hai"),
        sections=(
            ("p", "A machine has one IP address but many services, so each service gets its own door number (1-65535). Knowing which doors are open tells you what software is exposed."),
            ("p", "Common doors: 21 FTP, 22 SSH, 25 SMTP (email), 53 DNS, 80 HTTP, 443 HTTPS, 445 SMB file sharing, 3306 MySQL, 3389 RDP."),
            ("p", "In KSEC, nmap performs the port scan. Every open port becomes structured data, and the IPs behind services register as assets automatically."),
            ("cmd", "ksec run port_scan example.com --engagement 1 --user admin"),
            ("cmd", "ksec run port_scan 10.0.0.5 --engagement 1 --user admin --dry-run   # policy check only"),
        ),
    ),
    Topic(
        id="dns",
        title="DNS and domains — the internet's phone book",
        kind="concept",
        audience=("all",),
        summary=(
            "DNS translates human names (example.com) into IP addresses. A domain's records (A, "
            "AAAA, MX, NS, TXT...) describe what it points to and how its mail, nameservers and "
            "security policies are configured."
        ),
        keywords=("dns", "domain", "domain name", "record", "a record", "mx", "ns", "txt", "nameserver", "phone book", "dns kya hai"),
        sections=(
            ("p", "You remember names, computers remember numbers — DNS is the lookup service in between. 'example.com' resolves to IPs like 93.184.216.34."),
            ("p", "Record types you will see: A (name -> IPv4), AAAA (name -> IPv6), CNAME (alias), MX (mail servers), NS (nameservers), TXT (text, often SPF/DMARC security), SOA (zone authority)."),
            ("p", "KSEC's dig and dnsrecon tools query these records; found names become domain assets and their IPs register as ip assets + IOCs automatically."),
            ("cmd", "ksec run dns_lookup example.com --engagement 1 --user admin"),
            ("cmd", "ksec run dns_enum example.com --engagement 1 --user admin"),
        ),
    ),
    Topic(
        id="http-https",
        title="HTTP/HTTPS and websites",
        kind="concept",
        audience=("all",),
        summary=(
            "HTTP is the language browsers use to fetch web pages; HTTPS is the same language "
            "encrypted with TLS so nobody in the middle can read it. Web security testing starts "
            "by probing these services."
        ),
        keywords=("http", "https", "website", "web", "url", "browser", "request", "http kya hai"),
        sections=(
            ("p", "When you visit a site your browser sends an HTTP request and the server answers with a status code: 200 OK, 301/302 redirect, 401/403 denied, 404 not found, 500 error."),
            ("p", "HTTPS wraps that conversation in TLS encryption. A site serving plain HTTP, or with weak TLS settings, is exposing data — KSEC checks this with curl (http_probe) and sslscan (tls_scan)."),
            ("p", "The URL you test can be a full link (https://example.com/path) — KSEC automatically reduces it to its host for scope matching."),
            ("cmd", "ksec run http_probe example.com --engagement 1 --user admin"),
            ("cmd", "ksec run tls_scan example.com --engagement 1 --user admin"),
            ("cmd", "ksec vuln check --engagement 1 --user admin --port 443 example.com"),
        ),
    ),
    Topic(
        id="tls-ssl",
        title="TLS/SSL — encryption on the wire",
        kind="concept",
        audience=("all",),
        summary=(
            "TLS is the encryption technology behind HTTPS. Weak TLS (old protocol versions like "
            "TLS 1.0/1.1, weak ciphers, missing HSTS) lets attackers downgrade or read traffic — "
            "KSEC detects these as findings."
        ),
        keywords=("tls", "ssl", "certificate", "cipher", "hsts", "https", "encryption", "sslscan", "tls kya hai"),
        sections=(
            ("p", "TLS 1.2 and 1.3 are modern and safe. TLS 1.0/1.1 and SSL are deprecated — seeing them is a finding. Weak ciphers (old algorithms) are likewise flagged."),
            ("p", "HSTS is a header that tells browsers 'only ever connect over HTTPS'. Missing HSTS means a user could be redirected to plain HTTP."),
            ("p", "KSEC runs sslscan (tls_scan capability) to enumerate protocol/cipher support and turns TLS problems into findings with risk scores."),
            ("cmd", "ksec run tls_scan example.com --engagement 1 --user admin"),
            ("cmd", "ksec vuln check --engagement 1 --user admin example.com"),
            ("tip", "After a vuln check, 'ksec finding list' shows what was found and 'ksec finding explain 1' explains a finding in plain language."),
        ),
    ),
    Topic(
        id="vulnerability",
        title="Vulnerabilities, CVEs and severity",
        kind="concept",
        audience=("all",),
        summary=(
            "A vulnerability is a weakness in software that can be abused. Known ones get CVE "
            "identifiers (CVE-2024-1234). KSEC rates each finding's severity and computes a "
            "0-10 risk score from many factors."
        ),
        keywords=("vulnerability", "vuln", "cve", "weakness", "bug", "exploit", "severity", "vulnerability kya hai"),
        sections=(
            ("p", "Severity words used everywhere: info, low, medium, high, critical. 'Critical' means the weakness is easy to abuse and causes serious damage."),
            ("p", "A CVE (Common Vulnerabilities and Exposures) is a public ID for a known vulnerability. Scanners like wpscan/nuclei match what they find against such IDs."),
            ("p", "KSEC's risk score (0-10) is not just severity — it combines severity, asset importance, exploitability, exposure, impact, confidence and evidence quality, deterministically."),
            ("cmd", "ksec vuln check --engagement 1 --user admin example.com"),
            ("cmd", "ksec finding list"),
            ("cmd", "ksec finding explain 1"),
        ),
    ),
    Topic(
        id="engagement-scope",
        title="Engagements and scope — KSEC's safety core",
        kind="concept",
        audience=("all",),
        summary=(
            "An engagement is a written authorization (a contract) listing which targets are "
            "allowed. Scope rules say allow/deny per target; anything outside an allow rule is "
            "automatically BLOCKED before any tool runs. This is how KSEC guarantees authorized "
            "testing only."
        ),
        keywords=("engagement", "scope", "authorization", "authorized", "allowed", "blocked", "out of scope", "permission", "rules", "engagement kya hai"),
        sections=(
            ("p", "Before testing anything you create an engagement, then add scope rules: 'allow example.com', 'deny 10.0.0.0/8'. KSEC then checks EVERY action against these rules."),
            ("p", "If a target is not allowed, or matches a deny rule, the tool refuses to run — even a dry-run shows BLOCKED. There is no silent bypass."),
            ("p", "This is what makes red-team work here professional and legal: real pentesting always happens inside such written authorizations."),
            ("cmd", "ksec engagement create --name RT-2026"),
            ("cmd", "ksec engagement scope add --engagement 1 --target example.com --effect allow"),
            ("cmd", "ksec engagement scope add --engagement 1 --target 10.0.0.0/8 --effect deny"),
            ("cmd", "ksec assess recon example.com --engagement 1 --user admin --dry-run"),
            ("tip", "Unauthorized (black-hat) testing is never supported: the scope gate is the heart of the design and is never disabled."),
        ),
    ),
    Topic(
        id="ioc",
        title="IOCs — indicators of compromise",
        kind="concept",
        audience=("all", "blue", "purple"),
        summary=(
            "An IOC is a fingerprint of malicious activity: a bad IP, domain, URL, email, file "
            "hash or process name. Threat intel stores IOCs; SOC rules match incoming events "
            "against them to raise alerts."
        ),
        keywords=("ioc", "indicator", "compromise", "threat", "intel", "malicious", "bad ip", "hash", "indicator of compromise"),
        sections=(
            ("p", "When a scan finds an address or hostname, KSEC auto-registers it as an IOC candidate; researchers can also add IOCs from feeds with confidence low/medium/high."),
            ("p", "In the SOC, an event touching a registered IOC gets enriched (ioc=yes) and its risk score jumps — often producing a critical alert."),
            ("cmd", "ksec intel ioc add --value 203.0.113.66 --type IP --confidence high --source apache-access.log"),
            ("cmd", "ksec intel ioc list"),
            ("cmd", "ksec intel ioc extract --text 'beacon to evil-c2.top from 203.0.113.66'"),
        ),
    ),
    Topic(
        id="finding-evidence-case",
        title="Findings, evidence and cases — building the report",
        kind="concept",
        audience=("all",),
        summary=(
            "A finding is one discovered problem with a risk score; evidence is the proof "
            "(captured output with a SHA-256 hash); a case groups related findings/evidence "
            "into one trackable incident that ends in a client report."
        ),
        keywords=("finding", "evidence", "case", "report", "proof", "sha256", "finding kya hai"),
        sections=(
            ("p", "Workflow: tools discover problems -> findings carry the problem + risk score -> evidence proves it (integrity-verifiable) -> a case bundles them -> report turns it all into a deliverable."),
            ("cmd", "ksec finding create --title 'Weak TLS 1.0 enabled' --risk --severity high"),
            ("cmd", "ksec evidence add --content 'openssl output ...' --tool sslscan"),
            ("cmd", "ksec case create --title 'RT-2026 findings' --severity medium"),
            ("cmd", "ksec case add-finding --case 1 --finding 1"),
            ("cmd", "ksec report create --engagement 1 --format markdown"),
            ("cmd", "ksec report show 1"),
        ),
    ),
    Topic(
        id="risk-score",
        title="The 0-10 risk score",
        kind="concept",
        audience=("all",),
        summary=(
            "KSEC rates every finding with a deterministic risk score from 0 to 10. Above ~7 "
            "usually means 'fix this fast'. The score combines severity, asset value, "
            "exploitability, exposure, impact, confidence and evidence quality."
        ),
        keywords=("risk", "score", "risk score", "rating", "priority", "10", "critical score"),
        sections=(
            ("p", "Low (0-3): observations. Medium (4-6): real weakness worth fixing. High (7-8.9) and Critical (9-10): active danger — prioritize these."),
            ("p", "Unlike subjective guessing, the same input always yields the same score — that keeps reports defensible."),
            ("cmd", "ksec finding list"),
            ("cmd", "ksec finding explain 1   # shows why_this_risk in plain words"),
        ),
    ),
    Topic(
        id="red-vs-blue",
        title="Red team vs Blue team — attacker mindset vs defender mindset",
        kind="concept",
        audience=("all",),
        summary=(
            "Red Team simulates attacks against AUTHORIZED targets to find weaknesses before "
            "real attackers do. Blue Team defends: it detects, triages and contains those same "
            "kinds of activity. Purple is the collaboration between them."
        ),
        keywords=("red team", "blue team", "purple", "attacker", "defender", "red vs blue", "difference"),
        sections=(
            ("p", "Red works in RED_TEAM/ADVERSARY_SIMULATION workspaces: recon -> scanning -> finding weaknesses -> proving them -> reporting."),
            ("p", "Blue works in BLUE_TEAM: watch events, run detection rules, triage alerts, investigate with DFIR, close cases."),
            ("p", "Purple (RESEARCH_OSINT) feeds both: threat intel, actors, IOCs and gap analysis. Red's atomic tests validate whether Blue's rules actually fire — that loop is the Purple function."),
            ("tip", "Type 'ksec ask role red', 'ksec ask role blue' or 'ksec ask role purple' for that team's full step-by-step."),
        ),
    ),
    Topic(
        id="workspace-session",
        title="Workspaces, users, roles and sessions",
        kind="concept",
        audience=("all",),
        summary=(
            "Users hold roles (admin/operator/auditor/learner), sessions place a user into one "
            "of five workspaces (RED_TEAM, BLUE_TEAM, RESEARCH_OSINT, ADVERSARY_SIMULATION, "
            "LEARN_WORK), and roles decide which permissions that session has."
        ),
        keywords=("workspace", "session", "role", "user", "permission", "rbac", "admin", "operator", "auditor", "learner", "user kya hai"),
        sections=(
            ("p", "One person can hold many sessions — for example terminal 1 = red in RED_TEAM, terminal 2 = blue in BLUE_TEAM. A team uses separate accounts."),
            ("p", "Permissions are fine-grained (recon.run, assess.run, audit.read, ...). 'ksec ask scope' and the RBAC module enforce them."),
            ("cmd", "ksec admin user create --username red --password secret123"),
            ("cmd", "ksec session open --user red --password secret123 --workspace RED_TEAM"),
            ("cmd", "ksec session list"),
        ),
    ),
    Topic(
        id="osint",
        title="OSINT — open-source intelligence",
        kind="concept",
        audience=("all", "purple"),
        summary=(
            "OSINT is collecting information from public/open sources: DNS records, WHOIS, "
            "search results, certificates. It is passive (no intrusion), fully legal, and is the "
            "research foundation red and blue teams both use."
        ),
        keywords=("osint", "open source", "intelligence", "recon", "passive", "research", "public", "whois", "google", "osint kya hai"),
        sections=(
            ("p", "Researchers (RESEARCH_OSINT workspace) turn OSINT into structured knowledge: domains/IPs from DNS, actors + campaigns in intel, IOCs with confidence scores."),
            ("p", "KSEC keeps OSINT safe by default — dns_lookup/dns_enum are passive queries, and active tools stay behind scope rules."),
            ("cmd", "ksec run dns_enum example.com --user purple --workspace RESEARCH_OSINT"),
            ("cmd", "ksec intel actor add --name APT-Echo --description 'suspected phishing group'"),
            ("cmd", "ksec intel campaign link --actor 1 --ttp T1566"),
        ),
    ),
    Topic(
        id="ethics",
        title="The rules of engagement — legal and ethical basics",
        kind="concept",
        audience=("all",),
        summary=(
            "Security testing is only legal with written authorization for every target. "
            "Black-hat activity (testing systems you do not own or lack permission for) is "
            "illegal and is not supported anywhere in KSEC — by design."
        ),
        keywords=("legal", "ethical", "law", "authorized", "permission", "black hat", "illegal", "hacking legal", "rules"),
        sections=(
            ("p", "The professional path: written scope -> engagement -> authorized testing -> findings/report to the owner. Bug bounty programs are the same idea at scale."),
            ("p", "Every offensive module in KSEC (recon, vuln checks, atomics, adversary exercises, hydra, wpscan...) only executes inside an engagement's allow-rules. That gate is never removed."),
            ("p", "If you want to practice attacks legally, use intentionally vulnerable lab targets (DVWA, Metasploitable, TryHackMe/HackTheBox machines) — the exact same skills, zero legal risk."),
            ("tip", "When in doubt: if you don't have written permission for the target, don't scan it. That one habit protects your whole career."),
        ),
    ),
    Topic(
        id="soc-pipeline",
        title="The SOC pipeline — event to alert to case",
        kind="workflow",
        audience=("all", "blue"),
        summary=(
            "A raw security event flows: normalize (clean fields) -> enrich (match assets, IOCs, "
            "findings) -> correlate (related events) -> rules -> risk score -> alert -> "
            "auto-opened case. Blue then triages to closure."
        ),
        keywords=("soc", "alert", "pipeline", "event", "ingest", "rule", "normalize", "enrich", "correlate", "siem", "soc pipeline"),
        sections=(
            ("p", "Every stage is visible per event: ksec soc ingest prints normalized fields, enrichment hits, correlation count, matched rules, risk, and whether an alert fired."),
            ("p", "Rules match fields (ip/domain/username/...) with operators (eq/contains/regex/min_severity). Events touching IOCs get auto-enriched."),
            ("cmd", "ksec soc rule add --name ssh-bruteforce --event-type auth_failure --field username --operator eq --value root --severity high"),
            ("cmd", "ksec soc ingest --event-id e1 --source firewall --event-type auth_failure --severity low --ip 203.0.113.9 --username root"),
            ("cmd", "ksec soc alert list"),
            ("cmd", "ksec soc alert action ack 1"),
            ("cmd", "ksec soc alert action resolve 1 --case 1"),
        ),
    ),
    Topic(
        id="dfir",
        title="DFIR — forensics and incident timeline",
        kind="module",
        audience=("all", "blue"),
        summary=(
            "DFIR means Digital Forensics & Incident Response: collecting artifacts (logs, "
            "files, processes) and reconstructing the timeline of an incident inside a case."
        ),
        keywords=("dfir", "forensic", "incident", "artifact", "timeline", "response", "forensics"),
        sections=(
            ("p", "Artifacts attach evidence to a case (type: file/log/process/network/auth/...). Timeline events reconstruct what happened when, in order."),
            ("p", "Combine with SOC alerts: alert opens case -> DFIR adds the story -> case closes with evidence."),
            ("cmd", "ksec dfir artifact add --case 1 --type log --name auth.log --tool collector"),
            ("cmd", "ksec dfir artifact hash 1 --path /evidence/auth.log   # record SHA-256 of the collected file"),
            ("cmd", "ksec dfir event add --case 1 --time 2026-09-04T10:00:00Z --type auth_failure --details 'brute force burst'"),
            ("cmd", "ksec dfir timeline --case 1"),
            ("cmd", "ksec dfir export --case 1 --format jsonl --out case-1.jsonl   # shareable chronology"),
        ),
    ),
    Topic(
        id="vuln-module",
        title="The vuln module — authorized vulnerability checks",
        kind="module",
        audience=("all", "red"),
        summary=(
            "'ksec vuln check' runs deterministic, read-only probes (TLS settings, HTTP "
            "security headers, banner disclosure, dev-server detection) and turns each finding "
            "into a risk-scored record — no exploit, no guessing."
        ),
        keywords=("vuln check", "vuln module", "headers", "banner", "tls check", "findings auto"),
        sections=(
            ("p", "Checks are safe: they connect, inspect, and report — they never attack. Out-of-scope targets are blocked before the probe starts."),
            ("cmd", "ksec vuln check --engagement 1 --user admin example.com"),
            ("cmd", "ksec vuln checks"),
            ("cmd", "ksec finding list"),
        ),
    ),
    Topic(
        id="atomic",
        title="The atomic module — validating your detections",
        kind="module",
        audience=("all", "red", "blue"),
        summary=(
            "'ksec atomic' runs one ATT&CK technique at a time (like real attacker activity) "
            "against an in-scope target so Blue can see whether their rules actually fire — "
            "that is the purple-team loop."
        ),
        keywords=("atomic", "red team", "detection", "test", "att&ck", "technique", "validation", "atomic test"),
        sections=(
            ("p", "Example techniques: T1595 (active scanning), T1046 (network service discovery), T1071.001 (web C2), T1082 (system info), T1190 (exploit public-facing app)."),
            ("cmd", "ksec atomic list"),
            ("cmd", "ksec atomic info 1"),
            ("cmd", "ksec atomic run 1 example.com --engagement 1 --user admin --dry-run"),
            ("cmd", "ksec atomic run 1 example.com --engagement 1 --user admin"),
        ),
    ),
    Topic(
        id="adversary",
        title="The adversary module — full attack simulation",
        kind="module",
        audience=("all", "red"),
        summary=(
            "Profiles model a threat actor as ordered ATT&CK steps (TTPs). An exercise runs that "
            "profile step-by-step against an authorized target — policy-gated per step. "
            "Kill-chain mode executes steps in real ATT&CK tactic order."
        ),
        keywords=("adversary", "simulation", "profile", "exercise", "kill chain", "ttp", "att&ck", "attack simulation"),
        sections=(
            ("p", "Create profile (actor -> techniques) -> create exercise from it -> plan (dry-run) -> run live (executes allowed steps as jobs) -> chain (kill-chain order) -> report coverage."),
            ("cmd", "ksec adversary profile add --name APT-X --technique T1190 --technique T1059"),
            ("cmd", "ksec adversary exercise new --name ex1 --profile 1 --engagement 1 --user admin"),
            ("cmd", "ksec adversary exercise run 1 --target example.com --engagement 1 --user admin --dry-run"),
            ("cmd", "ksec adversary exercise chain 1 --target example.com --user admin"),
            ("cmd", "ksec adversary exercise report 1"),
        ),
    ),
    Topic(
        id="plugins",
        title="Plugins — extending KSEC",
        kind="module",
        audience=("all",),
        summary=(
            "Plugins add new capabilities (adapters/parsers/tools) from a manifest with "
            "declared permissions. Loading is permission-controlled: a plugin only gets the "
            "capabilities its manifest requests and that you approve."
        ),
        keywords=("plugin", "plugins", "extension", "addon", "capability", "manifest"),
        sections=(
            ("p", "Bundled example: plugins/web/http_headers adds an http_headers capability that runs as a workflow: ksec run http_headers example.com."),
            ("cmd", "ksec plugin list"),
            ("cmd", "ksec plugin new http-headers --tool curl --category web   # scaffold a plugin"),
            ("cmd", "ksec plugin install plugins/web/http_headers --trust LOCAL --user admin --password ... --yes"),
            ("cmd", "ksec plugin check"),
            ("tip", "ksec plugin new generates a valid manifest + adapter + parser skeleton — fill in the logic, then install."),
        ),
    ),
    Topic(
        id="siem",
        title="SIEM ingestion — logs flow into SOC by themselves",
        kind="module",
        audience=("all", "blue"),
        summary=(
            "ksec siem connects real log streams to the SOC pipeline: a UDP listener treats "
            "each datagram as one record (syslog format), and a file watcher ingests appended "
            "log lines. Every record goes through normalize -> rules -> alerts like a manual "
            "ingest, with deduplication built in."
        ),
        keywords=("siem", "syslog", "log collector", "udp", "log stream", "file watch", "auto ingest", "rsyslog", "siem kya hai"),
        sections=(
            ("p", "Supported record formats (auto-detected): JSONL (one JSON event per line), RFC3164 syslog (host tag[pid]: message) and auditd-style key=value records. IPs/domains inside the message are extracted automatically."),
            ("p", "Each record gets a deterministic id from its content — restarting the listener or re-sending a burst never duplicates events."),
            ("p", "Point rsyslog at it: '*.* @127.0.0.1:5514' or pipe tools: 'tail -F auth.log | ksec siem watch /dev/stdin'."),
            ("cmd", "ksec siem listen --port 5514 --source syslog          # run forever, Ctrl+C to stop"),
            ("cmd", "ksec siem watch /var/log/auth.log --source filewatch"),
            ("cmd", "ksec siem watch /var/log --once                      # bulk backfill existing files"),
            ("cmd", "ksec siem demo --ingest                            # show all formats end-to-end"),
            ("tip", "Combine with a windowed rule (ksec ask windowed-rules) to alert on brute force automatically."),
        ),
    ),
    Topic(
        id="windowed-rules",
        title="Windowed rules — '5 failures in 5 minutes' detection",
        kind="concept",
        audience=("all", "blue"),
        summary=(
            "A windowed detection rule counts matching events inside a time window and fires "
            "once when the count crosses its threshold — the classic brute-force detector: "
            "5 auth_failures from one IP within 5 minutes."
        ),
        keywords=("window", "windowed", "threshold", "count", "within", "brute force", "bruteforce", "failed logins", "time window", "repeat"),
        sections=(
            ("p", "Add --within <minutes> --count <N> to any rule whose operator is eq/contains/min_severity. The rule's value stays the match text (e.g. the IP), --count is how many matches inside the window trigger it."),
            ("p", "It fires exactly once per burst (when the incoming event crosses N), so you get one alert per attack — not a flood. Different IPs are counted separately because the filter is per-value."),
            ("cmd", "ksec soc rule add --name ssh-brute --event-type auth_failure --field ip --operator eq --value 203.0.113.66 --within 5 --count 5 --severity high"),
            ("cmd", "ksec soc rule list"),
            ("cmd", "ksec siem demo --ingest   # feed it and watch it fire"),
            ("tip", "Windowed rules use the same alert/risk/case pipeline — a crossing event opens the case automatically when severity is high."),
        ),
    ),
    Topic(
        id="api",
        title="The REST API — scripts and SIEMs drive KSEC",
        kind="module",
        audience=("all",),
        summary=(
            "ksec api exposes KSEC over HTTP/JSON with revocable bearer tokens: read status, "
            "jobs, findings, alerts, cases; write events, alert actions, and run scope-checked "
            "capabilities. Every request passes the same policy + audit as the CLI."
        ),
        keywords=("api", "rest", "token", "http", "json api", "curl", "automation", "integration", "script", "webhook"),
        sections=(
            ("p", "Tokens are stored hashed (never plaintext) and shown once at creation — revoke a token and it dies instantly."),
            ("p", "The API cannot bypass scope: running a tool against an out-of-scope target returns a refusal, exactly like the CLI."),
            ("cmd", "ksec api token create --user admin --password ... --name ci"),
            ("cmd", "ksec api serve --host 127.0.0.1 --port 9090"),
            ("cmd", "curl -H 'Authorization: Bearer <token>' http://127.0.0.1:9090/api/status"),
            ("cmd", "curl -H 'Authorization: Bearer <token>' -X POST http://127.0.0.1:9090/api/alerts/1/ack"),
            ("tip", "Bind to 127.0.0.1 (default) unless you need remote access — then use a firewall + short-lived tokens."),
        ),
    ),
    Topic(
        id="schedules",
        title="Recurring jobs — automation without a human",
        kind="module",
        audience=("all", "red", "blue", "purple"),
        summary=(
            "ksec job schedule runs a capability on a cron timer (e.g. daily DNS recon at "
            "06:00) through the normal scheduler + audit trail. Creation checks scope, and "
            "every run re-checks it — automation can never target an unauthorized host."
        ),
        keywords=("schedule", "recurring", "cron", "timer", "daily", "automation", "repeat", "job schedule", "scheduled"),
        sections=(
            ("p", "Cron format: 5 fields (minute hour day month weekday), with *, */step, ranges and lists. Example: '0 6 * * *' = every day 06:00."),
            ("p", "Use case: daily passive recon + IOC diff, weekly TLS re-check of your own estate, hourly auth-failure watch."),
            ("cmd", "ksec job schedule add dns_enum example.com --cron '0 6 * * *' --engagement 1 --user admin"),
            ("cmd", "ksec job schedule list"),
            ("cmd", "ksec job schedule run 1        # run now (re-checks scope)"),
            ("cmd", "ksec job schedule remove 1"),
            ("tip", "Scheduled job runs appear in ksec audit list with actor=schedule — automation is audited like everything else."),
        ),
    ),
    Topic(
        id="dashboard",
        title="The web dashboard — SOC triage in a browser",
        kind="module",
        audience=("all", "blue"),
        summary=(
            "ksec dashboard start opens a local web page with an overview and live SOC views: "
            "ack/resolve/close alerts and close cases from the browser. Every click is "
            "recorded in the audit log (actor=dashboard)."
        ),
        keywords=("dashboard", "web", "browser", "gui", "ui", "triage", "html"),
        sections=(
            ("p", "The page is read-mostly with triage buttons — keep it bound to 127.0.0.1; use ksec api with tokens for anything reachable by others."),
            ("cmd", "ksec dashboard start --port 8080"),
            ("cmd", "open http://127.0.0.1:8080/soc"),
            ("tip", "#overview / #soc / #cases hash links switch the view; the page auto-refreshes data on each action."),
        ),
    ),
    # -----------------------------------------------------------------------
    # Tool cards — every integrated tool, plain-language + how to run
    # -----------------------------------------------------------------------
    Topic(
        id="tool-nmap",
        title="nmap — the port scanner",
        kind="tool",
        audience=("all", "red"),
        summary=(
            "nmap discovers which ports (doors) are open on a target and which service/version "
            "runs behind each. In KSEC it runs under the port_scan capability and its results "
            "become assets automatically."
        ),
        keywords=("nmap", "port scan", "scan", "service scan", "nmap kya hai", "port scanner"),
        sections=(
            ("p", "Output entities: host + open ports with service names. IPs and hostnames auto-register as assets/IOCs when the job completes."),
            ("cmd", "ksec run port_scan example.com --engagement 1 --user admin"),
            ("cmd", "ksec run port_scan 10.0.0.5 --engagement 1 --user admin --dry-run"),
            ("tip", "Add a deny rule for ranges you must never touch: ksec engagement scope add --engagement 1 --target 10.0.0.0/8 --effect deny"),
        ),
    ),
    Topic(
        id="tool-dig",
        title="dig — DNS lookup",
        kind="tool",
        audience=("all",),
        summary=(
            "dig asks the DNS 'phone book' where a name points (A/AAAA/MX/NS/TXT records). In "
            "KSEC it is the dns_lookup capability; record IPs become assets and IOCs."
        ),
        keywords=("dig", "dns lookup", "dns", "resolve", "records", "dig kya hai", "nslookup"),
        sections=(
            ("cmd", "ksec run dns_lookup example.com --engagement 1 --user admin"),
            ("p", "Record types: A (IPv4), AAAA (IPv6), MX (mail), NS (nameservers), TXT (SPF/DMARC)."),
        ),
    ),
    Topic(
        id="tool-dnsrecon",
        title="dnsrecon — deep DNS enumeration",
        kind="tool",
        audience=("all", "red", "purple"),
        summary=(
            "dnsrecon maps a domain's records more thoroughly than dig, including SOA/NS "
            "details and (optionally) zone-transfer and brute subdomain attempts. Passive by "
            "default in KSEC; brute/zone options stay scope-gated."
        ),
        keywords=("dnsrecon", "dns enum", "dns enumeration", "subdomain", "zone transfer", "dnsrecon kya hai"),
        sections=(
            ("cmd", "ksec run dns_enum example.com --engagement 1 --user admin"),
            ("p", "Every found record becomes a dns_record entity; names and IPs auto-register as assets."),
        ),
    ),
    Topic(
        id="tool-curl",
        title="curl — HTTP probing",
        kind="tool",
        audience=("all", "red"),
        summary=(
            "curl fetches a web server's response (status code, headers, content type) to see "
            "if/how it answers. In KSEC it is the http_probe capability — the first step of "
            "any web test."
        ),
        keywords=("curl", "http probe", "http", "status code", "headers", "curl kya hai", "web request"),
        sections=(
            ("cmd", "ksec run http_probe example.com --engagement 1 --user admin"),
            ("p", "Answers like 200/301/403/500 tell you what the site exposes before deeper scans."),
        ),
    ),
    Topic(
        id="tool-sslscan",
        title="sslscan — TLS/SSL inspection",
        kind="tool",
        audience=("all", "red"),
        summary=(
            "sslscan tests which TLS protocol versions and ciphers a server supports and "
            "reports weak ones (TLS 1.0/1.1, weak ciphers). In KSEC it is the tls_scan "
            "capability."
        ),
        keywords=("sslscan", "tls", "ssl", "cipher", "protocol", "sslscan kya hai", "tls scan"),
        sections=(
            ("cmd", "ksec run tls_scan example.com --engagement 1 --user admin"),
            ("p", "Weak protocol/cipher findings feed the same finding store used by vuln check."),
        ),
    ),
    Topic(
        id="tool-nikto",
        title="nikto — web server scanner",
        kind="tool",
        audience=("all", "red"),
        summary=(
            "nikto checks a web server against thousands of known dangerous files, outdated "
            "software and misconfigurations. In KSEC it is the web_vuln_scan capability."
        ),
        keywords=("nikto", "web scan", "web server", "vulnerability scan", "nikto kya hai", "web vuln"),
        sections=(
            ("cmd", "ksec run web_vuln_scan example.com --engagement 1 --user admin"),
            ("p", "Matches become nikto_finding entities (OSVDB references) you can review and promote to risk-scored findings."),
        ),
    ),
    Topic(
        id="tool-gobuster",
        title="gobuster — hidden directories and files",
        kind="tool",
        audience=("all", "red"),
        summary=(
            "gobuster tries many path names against a web server to find hidden directories "
            "and files that aren't linked anywhere. In KSEC it is the directory_brute "
            "capability."
        ),
        keywords=("gobuster", "directory", "brute", "hidden", "path", "gobuster kya hai", "dir search"),
        sections=(
            ("cmd", "ksec run directory_brute example.com --engagement 1 --user admin"),
            ("p", "Found paths come back with HTTP status codes so you can separate real content from redirects."),
        ),
    ),
    Topic(
        id="tool-wpscan",
        title="wpscan — WordPress scanner",
        kind="tool",
        audience=("all", "red"),
        summary=(
            "wpscan inspects a WordPress site — core version, plugins, themes — and matches "
            "them against known vulnerabilities (CVEs). In KSEC it is the wpscan capability "
            "and emits structured CVE findings."
        ),
        keywords=("wpscan", "wordpress", "wp", "cms", "plugin vuln", "wpscan kya hai", "wordpress scan"),
        sections=(
            ("cmd", "ksec run wpscan example.com --engagement 1 --user admin"),
            ("p", "Plugin/theme vulnerabilities become wpscan_vuln entities with CVE + fixed_in version, ready to turn into findings."),
        ),
    ),
    Topic(
        id="tool-hydra",
        title="hydra — online login testing (authorized only)",
        kind="tool",
        audience=("all", "red"),
        summary=(
            "hydra tests login credentials against a service (ssh, http-form, rdp, smb...) to "
            "find weak passwords. It makes REAL login attempts, so it only runs against "
            "targets inside an engagement you authorized — same as every active KSEC tool."
        ),
        keywords=("hydra", "brute force", "password", "login", "auth", "crack", "hydra kya hai", "weak password"),
        sections=(
            ("p", "Supply a username and a wordlist (or single password) plus the service. Confirmed logins are recorded as auth_finding entities."),
            ("cmd", "ksec run auth_test 10.0.0.5 --engagement 1 --user admin"),
            ("tip", "Only ever point this at systems you own or have written permission to test — that is the law and KSEC's scope gate enforces it."),
        ),
    ),
    Topic(
        id="tool-enum4linux",
        title="enum4linux — SMB/Windows enumeration",
        kind="tool",
        audience=("all", "red"),
        summary=(
            "enum4linux inspects a Windows-style file-sharing host (SMB/NetBIOS) — shares, "
            "users, OS info — including whether guest/null sessions are allowed. In KSEC it "
            "is the smb_enum capability."
        ),
        keywords=("enum4linux", "smb", "windows", "netbios", "share", "null session", "enum4linux kya hai", "smb enum"),
        sections=(
            ("cmd", "ksec run smb_enum 10.0.0.5 --engagement 1 --user admin"),
            ("p", "Output: smb_share entities + smb_finding when a null (guest) session is permitted — a classic misconfiguration."),
        ),
    ),
    Topic(
        id="tool-smbmap",
        title="smbmap — SMB share access map",
        kind="tool",
        audience=("all", "red"),
        summary=(
            "smbmap lists SMB shares on a host and shows the effective permission on each "
            "(read-only / read-write / no access) for the account used. In KSEC it is the "
            "smb_map capability."
        ),
        keywords=("smbmap", "smb", "share", "permission", "read write", "smbmap kya hai", "smb shares"),
        sections=(
            ("cmd", "ksec run smb_map 10.0.0.5 --engagement 1 --user admin"),
            ("p", "Output: smb_host + smb_share entities with permission, e.g. a world-readable 'shared' folder = finding."),
        ),
    ),
    Topic(
        id="tool-subfinder",
        title="subfinder — passive subdomain discovery",
        kind="tool",
        audience=("all", "purple"),
        summary=(
            "subfinder finds subdomains of a domain from public sources without touching the "
            "target (passive OSINT). In KSEC it maps to the subdomain_enum capability."
        ),
        keywords=("subfinder", "subdomain", "subdomain enum", "passive", "subfinder kya hai"),
        sections=(
            ("cmd", "ksec run subdomain_enum example.com --user purple --workspace RESEARCH_OSINT"),
            ("p", "If subfinder is not installed, KSEC shows it as missing — 'ksec tools install subdomain_enum' (Kali package: subfinder)."),
        ),
    ),
    Topic(
        id="tool-nuclei",
        title="nuclei — fast template-based vulnerability scanner",
        kind="tool",
        audience=("all", "red"),
        summary=(
            "nuclei checks targets against hundreds of small detection templates — known "
            "CVEs, misconfigurations, exposed files — and reports matches with severity. "
            "In KSEC it is an alternative provider for the web_vuln_scan capability."
        ),
        keywords=("nuclei", "template", "cve scan", "web vuln", "nuclei kya hai", "vulnerability scanner"),
        sections=(
            ("cmd", "ksec run web_vuln_scan example.com --engagement 1 --user admin"),
            ("p", "nuclei or nikto can back the same web_vuln_scan capability; matches carry the template name + severity so you can promote them to risk-scored findings."),
            ("tip", "Keep templates updated on your Kali box (nuclei -update) — detection quality depends on them."),
        ),
    ),
    Topic(
        id="tool-whois",
        title="whois — domain ownership lookup",
        kind="tool",
        audience=("all", "purple"),
        summary=(
            "whois reveals who registered a domain, when, and via which registrar — pure "
            "public-record research. In KSEC it is the whois_lookup capability under the "
            "recon workspace."
        ),
        keywords=("whois", "registrar", "domain owner", "registration", "whois kya hai"),
        sections=(
            ("cmd", "ksec run whois_lookup example.com --user purple --workspace RESEARCH_OSINT"),
            ("p", "Researcher use: registration dates, registrar and nameservers help tie infrastructure to an actor or campaign during OSINT."),
        ),
    ),
    Topic(
        id="tool-whatweb",
        title="whatweb — web technology fingerprinting",
        kind="tool",
        audience=("all", "red"),
        summary=(
            "whatweb inspects a website and reports which technologies it runs: server "
            "software, frameworks (WordPress, jQuery, ...), titles and the IP behind it. "
            "In KSEC it is the web_fingerprint capability."
        ),
        keywords=("whatweb", "fingerprint", "web tech", "technology", "framework", "whatweb kya hai", "website technology"),
        sections=(
            ("cmd", "ksec run web_fingerprint example.com --engagement 1 --user admin"),
            ("p", "Output: host entities (IP/domain auto-register as assets) plus web_tech entities with server, title and detected frameworks + versions — perfect input before picking wpscan/nikto."),
            ("tip", "Run it before deep scans: knowing the stack (WordPress? custom PHP? nginx?) tells you which scanner to run next."),
        ),
    ),
    Topic(
        id="tool-theharvester",
        title="theHarvester — passive OSINT harvesting",
        kind="tool",
        audience=("all", "purple"),
        summary=(
            "theHarvester collects emails, hostnames/subdomains and IPs about a domain from "
            "public sources — pure research that never contacts the target. In KSEC it is "
            "the osint_harvest capability."
        ),
        keywords=("theharvester", "harvester", "osint", "email harvest", "emails", "passive recon", "harvest", "theharvester kya hai"),
        sections=(
            ("cmd", "ksec run osint_harvest example.com --user purple --workspace RESEARCH_OSINT"),
            ("p", "Default source crtsh (certificate transparency) needs no API key; emails feed the intel module, non-wildcard hostnames register as domain assets + IOC candidates."),
            ("tip", "Purple flow: theHarvester -> DNS recon -> IOCs -> share with Blue so the SOC knows what an attacker could learn about your estate."),
        ),
    ),
    # -----------------------------------------------------------------------
    # Role playbooks — the step-by-step "tareeqa" per job
    # -----------------------------------------------------------------------
    Topic(
        id="role-red",
        title="RED TEAM playbook — how an authorized attacker works in KSEC",
        kind="role",
        audience=("red",),
        summary=(
            "The red teamer's method: (1) create the engagement + scope, (2) recon, (3) probe "
            "and scan, (4) vulnerability checks, (5) emulate real attack paths, (6) document "
            "findings with evidence, (7) deliver a report. Every step is inside the authorized "
            "scope."
        ),
        keywords=("red team", "red", "attacker", "pentest", "penetration", "offensive", "red team playbook", "red team kaise", "attack"),
        sections=(
            ("p", "STEP 1 — AUTHORIZE. Create the engagement and write the scope contract."),
            ("cmd", "ksec engagement create --name RT-2026"),
            ("cmd", "ksec engagement scope add --engagement 1 --target example.com --effect allow"),
            ("cmd", "ksec engagement scope add --engagement 1 --target 10.0.0.0/8 --effect deny"),
            ("p", "STEP 2 — RECON. Map the surface: DNS + ports."),
            ("cmd", "ksec run recon example.com --engagement 1 --user red"),
            ("cmd", "ksec run dns_enum example.com --engagement 1 --user red"),
            ("p", "STEP 3 — PROBE services found (http? smb? ssh? wordpress?)."),
            ("cmd", "ksec run http_probe example.com --engagement 1 --user red"),
            ("cmd", "ksec run tls_scan example.com --engagement 1 --user red"),
            ("cmd", "ksec run wpscan example.com --engagement 1 --user red"),
            ("cmd", "ksec run smb_enum 10.0.0.5 --engagement 1 --user red"),
            ("p", "STEP 4 — AUTOMATED CHECKS. Deterministic vuln findings with risk scores."),
            ("cmd", "ksec vuln check --engagement 1 --user red example.com"),
            ("p", "STEP 5 — EMULATE ATTACK PATHS (optional, authorized): atomics + adversary exercises validate what an attacker could chain."),
            ("cmd", "ksec atomic list"),
            ("cmd", "ksec adversary exercise chain 1 --target example.com --engagement 1 --user red --dry-run"),
            ("p", "STEP 6 — DOCUMENT. Findings + proof + case."),
            ("cmd", "ksec finding list"),
            ("cmd", "ksec evidence add --content 'probe output...' --tool sslscan --method capture"),
            ("cmd", "ksec case create --title 'RT-2026 findings' --severity medium"),
            ("cmd", "ksec case add-finding --case 1 --finding 1"),
            ("p", "STEP 7 — DELIVER the report."),
            ("cmd", "ksec report create --engagement 1 --format markdown"),
            ("cmd", "ksec report show 1"),
            ("tip", "Start with --dry-run anywhere until you are sure the scope is right. Out-of-scope = auto BLOCK."),
        ),
    ),
    Topic(
        id="role-blue",
        title="BLUE TEAM playbook — how a SOC defender works in KSEC",
        kind="role",
        audience=("blue",),
        summary=(
            "The blue teamer's method: (1) know your detections (rules + IOCs), (2) ingest "
            "events, (3) triage alerts, (4) investigate (enrich, correlate, DFIR), (5) "
            "contain/resolve, (6) close cases, (7) learn and improve rules."
        ),
        keywords=("blue team", "blue", "defender", "soc", "defense", "analyst", "blue team playbook", "blue team kaise", "incident response"),
        sections=(
            ("p", "STEP 1 — DETECTION BASELINE. Load threat intel + rules so events mean something."),
            ("cmd", "ksec intel ioc add --value 203.0.113.66 --type IP --confidence high --source feed"),
            ("cmd", "ksec intel actor add --name APT-Phantom"),
            ("cmd", "ksec soc rule add --name ssh-bruteforce --event-type auth_failure --field username --operator eq --value root --severity high"),
            ("p", "STEP 2 — INGEST events (from SIEM/logs or manually for drills)."),
            ("cmd", "ksec soc ingest --event-id e1 --source firewall --event-type auth_failure --severity low --ip 203.0.113.66 --username root"),
            ("p", "STEP 3 — TRIAGE the alert queue."),
            ("cmd", "ksec soc alert list"),
            ("cmd", "ksec soc alert show 1"),
            ("cmd", "ksec soc alert action ack 1"),
            ("p", "STEP 4 — INVESTIGATE: what actor, what chain, what evidence."),
            ("cmd", "ksec intel ioc correlate --value 203.0.113.66"),
            ("cmd", "ksec dfir artifact add --case 1 --type log --name auth.log"),
            ("cmd", "ksec dfir timeline --case 1"),
            ("p", "STEP 5-6 — CONTAIN + CLOSE."),
            ("cmd", "ksec soc alert action resolve 1 --case 1"),
            ("cmd", "ksec case close 1"),
            ("p", "STEP 7 — LEARN: findings + notifications + rule tuning close the loop."),
            ("cmd", "ksec finding create --title 'Block 203.0.113.66' --risk --severity critical"),
            ("cmd", "ksec notify test --title 'SOC report' --body '...'"),
            ("tip", "Run 'ksec atomic list' with your red teammate to test whether your rules actually fire."),
        ),
    ),
    Topic(
        id="role-blackhat",
        title="BLACK HAT emulation playbook — the attacker mindset, authorized",
        kind="role",
        audience=("red",),
        summary=(
            "The black-hat playbook emulates how a real malicious attacker thinks and "
            "operates — full kill chain, no mercy, worst-case assumptions — so defenders "
            "see what an actual intrusion looks like. It is CONTROLLED ADVERSARY "
            "SIMULATION (spec 06#28): every step still runs inside an engagement you "
            "authorized, never against systems you lack permission to test."
        ),
        keywords=("black hat", "blackhat", "hacker", "criminal", "malicious", "kill chain", "initial access", "privilege escalation", "lateral movement", "persistence", "exfiltration", "emulation", "attacker mindset", "black hat kya hai", "blackhat kaise"),
        sections=(
            ("p", "STEP 1 — AUTHORIZE (non-negotiable). A real black hat has no permission; a professional emulating one MUST have written scope. Create the engagement first — this playbook refuses to work outside it."),
            ("cmd", "ksec engagement create --name blackhat-emulation"),
            ("cmd", "ksec engagement scope add --engagement 1 --target lab-target.example --effect allow"),
            ("cmd", "ksec engagement scope add --engagement 1 --target 10.0.0.0/8 --effect deny"),
            ("p", "STEP 2 — RECON like an intruder: enumerate aggressively, assume nothing is private."),
            ("cmd", "ksec run dns_enum lab-target.example --engagement 1 --user red"),
            ("cmd", "ksec run port_scan lab-target.example --engagement 1 --user red"),
            ("cmd", "ksec run web_fingerprint lab-target.example --engagement 1 --user red"),
            ("cmd", "ksec run osint_harvest lab-target.example --workspace RESEARCH_OSINT"),
            ("p", "STEP 3 — HUNT WEAKNESSES like an attacker would: version checks, headers, banners, web paths."),
            ("cmd", "ksec vuln check --engagement 1 --user red lab-target.example"),
            ("cmd", "ksec run directory_brute lab-target.example --engagement 1 --user red"),
            ("cmd", "ksec run web_vuln_scan lab-target.example --engagement 1 --user red"),
            ("cmd", "ksec run wpscan lab-target.example --engagement 1 --user red"),
            ("p", "STEP 4 — VALIDATE access like a real intrusion (only against in-scope targets): credential/authentication testing, SMB access, TLS gaps."),
            ("cmd", "ksec run auth_test lab-target.example --engagement 1 --user red"),
            ("cmd", "ksec run smb_enum lab-target.example --engagement 1 --user red"),
            ("cmd", "ksec run smb_map lab-target.example --engagement 1 --user red"),
            ("p", "STEP 5 — EMULATE the full intrusion chain: atomics + adversary exercises model initial access -> persistence -> lateral movement -> exfiltration, and prove whether Blue's detections fire."),
            ("cmd", "ksec atomic list"),
            ("cmd", "ksec adversary profile add --name blackhat-ops --threat-actor 'Real-World Intruder' --technique T1190 --technique T1059 --technique T1547 --technique T1021 --technique T1041"),
            ("cmd", "ksec adversary exercise new --name bh-ex --profile 1 --engagement 1 --user red"),
            ("cmd", "ksec adversary exercise chain 1 --target lab-target.example --engagement 1 --user red --dry-run"),
            ("p", "STEP 6 — DOCUMENT the intrusion story: what a real black hat would steal/change, evidence, findings, risk, remediation."),
            ("cmd", "ksec finding create --title 'Persistence achievable (emulated)' --risk --severity high"),
            ("cmd", "ksec evidence add --content 'emulated kill chain output' --tool adversary --operator red"),
            ("cmd", "ksec case create --title 'Black-hat emulation findings' --severity high"),
            ("cmd", "ksec report create --engagement 1 --format markdown"),
            ("tip", "This playbook is legal only inside authorized engagements or intentionally vulnerable labs (HTB, TryHackMe, Metasploitable, DVWA). The scope gate is never disabled — 'black hat' here means the MINDSET, not the crime."),
        ),
    ),
    Topic(
        id="role-purple",
        title="PURPLE TEAM / RESEARCHER playbook — OSINT and threat intel",
        kind="role",
        audience=("purple",),
        summary=(
            "The researcher's method: (1) passive OSINT collection, (2) turn findings into "
            "structured intel (IOCs, actors, campaigns, TTPs), (3) share context that makes "
            "red smarter and blue faster, (4) run gap analysis by validating blue's "
            "detections against red's techniques."
        ),
        keywords=("purple", "researcher", "osint", "research", "threat intel", "analyst", "ioc", "actor", "campaign", "purple team playbook", "researcher kaise"),
        sections=(
            ("p", "STEP 1 — COLLECT passive OSINT."),
            ("cmd", "ksec session open --user purple --workspace RESEARCH_OSINT"),
            ("cmd", "ksec run dns_enum example.com --user purple"),
            ("p", "STEP 2 — STRUCTURE intel: IOCs with confidence, actors, campaigns, ATT&CK links."),
            ("cmd", "ksec intel ioc add --value evil-c2.top --type DOMAIN --confidence high --actor APT-Phantom"),
            ("cmd", "ksec intel actor add --name APT-Phantom --alias phantom-group"),
            ("cmd", "ksec intel campaign add --name summer-phish"),
            ("cmd", "ksec intel ttp add --id T1566"),
            ("cmd", "ksec intel campaign link --campaign 1 --ttp T1566 --actor 1"),
            ("p", "STEP 3 — SHARE: IOCs auto-enrich blue's SOC events; DNS findings give red new targets."),
            ("cmd", "ksec intel ioc list"),
            ("cmd", "ksec intel ioc extract --evidence 1"),
            ("p", "STEP 4 — VALIDATE (the purple loop): does blue detect what red does?"),
            ("cmd", "ksec atomic run 1 example.com --user red --workspace ADVERSARY_SIMULATION --dry-run"),
            ("cmd", "ksec adversary exercise report 1"),
            ("tip", "Purple is not a separate attacker — it is the collaboration layer feeding both sides."),
        ),
    ),
    Topic(
        id="role-learner",
        title="LEARNER playbook — how to learn security inside KSEC",
        kind="role",
        audience=("learner",),
        summary=(
            "The learner path: follow the built-in curriculum (12 phases, 18 lessons, 5 "
            "levels), ask questions here with 'ksec ask', practice each role in its own "
            "workspace, and level up by completing lessons."
        ),
        keywords=("learner", "learn", "student", "beginner", "curriculum", "lesson", "level", "course", "seekhna", "learning"),
        sections=(
            ("p", "STEP 1 — Open a learner session and see the curriculum."),
            ("cmd", "ksec session open --user learner --workspace LEARN_WORK"),
            ("cmd", "ksec learn list"),
            ("p", "STEP 2 — Explore lessons and mark progress."),
            ("cmd", "ksec learn lesson --id 1"),
            ("cmd", "ksec learn complete --id 1 --user learner"),
            ("p", "STEP 3 — Level up: progress records your journey through Explorer -> ... -> Expert."),
            ("cmd", "ksec learn progress --user learner"),
            ("p", "STEP 4 — Use this mentor for anything unclear — tools, roles, concepts, commands."),
            ("cmd", "ksec ask what is a port"),
            ("cmd", "ksec ask role red"),
            ("cmd", "ksec ask nmap kya hai"),
            ("tip", "Every demo/simulation-style exercise belongs here in learning; production modules run for real under each role."),
        ),
    ),
    Topic(
        id="grc",
        title="GRC — compliance frameworks mapped to real checks",
        kind="module",
        audience=("all", "blue"),
        summary=(
            "ksec grc maps KSEC's deterministic checks (TLS, security headers, audit, "
            "evidence integrity, backups, scope) to controls of NIST 800-53, CIS, OWASP, "
            "ISO 27001, SOC 2 and PCI DSS. It never claims certification — only that a "
            "technical check passed or failed."
        ),
        keywords=("grc", "compliance", "framework", "nist", "cis", "owasp", "iso", "soc2", "pci", "audit", "control", "certification", "grc kya hai"),
        sections=(
            ("p", "Flow (spec 08#37): Framework -> Control -> Requirement -> Technical Test -> Evidence -> Status -> Gap -> Remediation. Every check run is stored as evidence so the mapping is provable."),
            ("p", "Targeted checks (TLS, headers, banners) need an in-scope target; platform checks (audit active, evidence integrity, backups, scope) run locally."),
            ("cmd", "ksec grc frameworks"),
            ("cmd", "ksec grc controls --framework 'ISO 27001'"),
            ("cmd", "ksec grc status"),
            ("cmd", "ksec grc check --target example.com   # stores snapshot as evidence + audit"),
            ("tip", "A failing control means the check failed, not that you are non-compliant — review the detail line and remediate the underlying issue."),
        ),
    ),
    Topic(
        id="malware",
        title="Malware analysis — static triage without execution",
        kind="module",
        audience=("all", "blue"),
        summary=(
            "ksec malware analyze hashes a sample (SHA-256/1/MD5), detects its format "
            "(PE/ELF/Mach-O/ZIP/PDF/script), extracts strings, computes entropy, registers "
            "the hashes as IOCs and stores the analysis as evidence. It NEVER executes the "
            "sample."
        ),
        keywords=("malware", "sample", "hash", "strings", "entropy", "pe", "elf", "analysis", "triage", "virus", "malware analysis", "malware kya hai"),
        sections=(
            ("p", "Pipeline (spec 08#22): Sample -> Hash -> Metadata -> Static Analysis -> IOC extraction -> Evidence -> optional Finding. Dynamic/behavioral analysis needs an isolated sandbox and is intentionally not in the core."),
            ("p", "Entropy above ~7.0 often means packed/encrypted content; unusual strings (URLs, commands) and embedded zip entries are worth investigating."),
            ("cmd", "ksec malware analyze /evidence/sample.bin"),
            ("cmd", "ksec malware analyze /evidence/sample.bin --finding   # also create a finding"),
            ("cmd", "ksec intel ioc list --type HASH   # hashes auto-registered as IOCs"),
            ("tip", "Pair with DFIR: collect the file as a dfir artifact first, then analyze it and link the analysis evidence."),
        ),
    ),
    Topic(
        id="endpoint",
        title="Endpoint security — know the machine you are defending",
        kind="module",
        audience=("all", "blue"),
        summary=(
            "ksec endpoint inventories the local host read-only: OS/kernel/arch, processes, "
            "user accounts and listening sockets. It modifies nothing — pure passive "
            "collection from /proc and /etc, with optional findings for notable "
            "observations."
        ),
        keywords=("endpoint", "host", "process", "user", "port", "socket", "inventory", "os", "kernel", "uptime", "endpoint security"),
        sections=(
            ("p", "Useful for blue-team baselining: which accounts exist, what is listening where, and which processes are running — the starting picture for any investigation."),
            ("p", "'ksec endpoint check' flags root-equivalent login accounts, listening sockets without an owning process, and non-loopback listeners — create findings with --create-findings."),
            ("cmd", "ksec endpoint inventory"),
            ("cmd", "ksec endpoint process --limit 50"),
            ("cmd", "ksec endpoint user"),
            ("cmd", "ksec endpoint port"),
            ("cmd", "ksec endpoint check --create-findings"),
        ),
    ),
    Topic(
        id="stop-emergency",
        title="Emergency stop — kill every job instantly",
        kind="workflow",
        audience=("all",),
        summary=(
            "ksec stop --all is the global emergency stop: it cancels every running/queued "
            "job, blocks new submissions, preserves all evidence and job state, and records "
            "an audit event. Use it when a run is going wrong and you want everything to "
            "halt now."
        ),
        keywords=("stop", "emergency", "kill", "halt", "abort", "cancel all", "stop --all", "emergency stop"),
        sections=(
            ("p", "Jobs are cancelled (never deleted), evidence stays intact, and the audit log records emergency_stop with the cancelled job ids. New submissions are refused until you clear it."),
            ("cmd", "ksec stop --all"),
            ("cmd", "ksec stop --status"),
            ("cmd", "ksec stop --reset"),
            ("tip", "Rate limiting is configurable in [safety]: rate_limit_per_minute (global) and rate_limit_per_user keep runaway automation in check before you ever need the stop."),
        ),
    ),
    Topic(
        id="time-bound-auth",
        title="Time-bound authorization — engagements with an expiry",
        kind="workflow",
        audience=("all",),
        summary=(
            "An engagement can carry a validity window (--valid-from / --valid-until). "
            "Before it starts or after it expires, every target action is refused at the "
            "policy gate — even when a scope rule matches (spec 06#54)."
        ),
        keywords=("time-bound", "validity", "valid-from", "valid-until", "expiry", "expired", "window", "engagement window", "authorization window"),
        sections=(
            ("p", "Flow: create the engagement with a window, add your scope rules, and KSEC automatically blocks runs once the window closes — no manual revocation needed."),
            ("cmd", "ksec engagement create --name q1 --valid-from 2026-01-01 --valid-until 2026-12-31"),
            ("cmd", "ksec engagement list      # flags [not-yet-valid] / [expired]"),
            ("tip", "Timestamps accept ISO-8601: full datetimes or plain dates (YYYY-MM-DD, treated as UTC midnight)."),
        ),
    ),
    Topic(
        id="lab-mode",
        title="Lab/CTF mode — practice only, public targets blocked",
        kind="workflow",
        audience=("all", "learner"),
        summary=(
            "Lab/CTF mode restricts KSEC to lab ranges: private/loopback networks, .test / "
            ".local / .lab / .ctf hostnames and lab-labelled names. Real public targets are "
            "denied with a clear reason, making it safe for classrooms and practice ranges "
            "(spec 06#56)."
        ),
        keywords=("lab", "ctf", "mode", "practice", "training", "sandbox", "classroom", "lab mode", "ctf mode"),
        sections=(
            ("p", "Allowed: 127.0.0.0/8, 10/8, 172.16/12, 192.168/16, ::1, fc00::/7 plus hostnames ending .test/.local/.lab/.ctf/.lan/.internal/.example or containing lab/ctf/target/sandbox."),
            ("cmd", "ksec mode status"),
            ("cmd", "ksec mode set lab on"),
            ("cmd", "ksec mode set lab off"),
            ("cmd", "ksec mode set safe on"),
            ("cmd", "ksec mode set read-only on"),
            ("tip", "Modes persist in the config file's [safety] table and apply from the next invocation."),
        ),
    ),
    Topic(
        id="workflow-dag",
        title="Workflow DAG + retries — steps that depend on steps",
        kind="workflow",
        audience=("all", "red"),
        summary=(
            "Workflow steps can declare name + depends_on, so a step only runs after its "
            "dependencies finish, and retry/retry_delay for automatic backoff on failure. "
            "Edits bump the version and every run snapshots exactly what executed (spec 07)."
        ),
        keywords=("workflow", "dag", "depends", "dependency", "parallel", "retry", "backoff", "version", "snapshot", "steps", "automation"),
        sections=(
            ("p", "Use --steps-json for named steps with dependencies: each step object may carry \"name\", \"depends_on\": [...], \"retry\": N and \"retry_delay\": seconds. Cycles and unknown dependencies are rejected at creation."),
            ("cmd", "ksec workflow create --name staged --steps-json '[{\"capability\":\"dns_lookup\",\"name\":\"resolve\"},{\"capability\":\"port_scan\",\"name\":\"scan\",\"depends_on\":[\"resolve\"],\"retry\":2}]'"),
            ("cmd", "ksec workflow validate --name staged"),
            ("cmd", "ksec workflow run staged example.com --engagement 1 --user admin --password ..."),
            ("cmd", "ksec workflow history --json    # version + immutable snapshot per run"),
            ("tip", "Running a workflow never uses a half-edited definition: the version + steps are frozen into the run record at start."),
        ),
    ),
    Topic(
        id="session-switch",
        title="Session switch/reconnect — move between workspaces",
        kind="workflow",
        audience=("all",),
        summary=(
            "ksec session switch pauses your other active sessions and activates the one "
            "you choose; ksec session reconnect brings a paused session back (spec 07#31-32). "
            "Think of it as moving your terminal focus between workspaces."
        ),
        keywords=("session", "switch", "reconnect", "workspace", "focus", "terminal", "context", "session switch"),
        sections=(
            ("p", "Sessions belong to their user: switching/reconnecting to another user's session is refused. The other active sessions of the same user are paused, keeping one clear focus."),
            ("cmd", "ksec session list"),
            ("cmd", "ksec session switch <session-id> --user admin --password ..."),
            ("cmd", "ksec session reconnect <session-id> --user admin --password ..."),
            ("tip", "Global flags also help here: ksec --profile soc status merges a [profiles.soc] config section on top of the base config."),
        ),
    ),
    Topic(
        id="ask-how",
        title="Using ksec ask — the in-tool mentor",
        kind="workflow",
        audience=("all",),
        summary=(
            "ksec ask answers questions in plain language inside the tool: concepts from zero, "
            "tool cards, role playbooks and module guides — and always suggests the exact "
            "command to run next."
        ),
        keywords=("ask", "help", "mentor", "guide", "question", "how", "kaise", "kya hai", "explain"),
        sections=(
            ("cmd", "ksec ask what is an ip address"),
            ("cmd", "ksec ask nmap kya hai"),
            ("cmd", "ksec ask red team kaise shuru karun"),
            ("cmd", "ksec ask role blue"),
            ("cmd", "ksec ask --list"),
            ("cmd", "ksec role red"),
            ("tip", "ksec ask works offline — no internet, no AI dependency. Try ksec ask 'scan kese karein'."),
        ),
    ),
)

# Concept/tool/module ids that act as routing aliases (e.g. "role red" ->
# role-red) so answers never dead-end.
ALIASES: dict[str, str] = {
    "help": "ask-how",
    "guide": "ask-how",
    "mentor": "ask-how",
    "red": "role-red",
    "blue": "role-blue",
    "purple": "role-purple",
    "blackhat": "role-blackhat",
    "black hat": "role-blackhat",
    "osint researcher": "role-purple",
    "learner": "role-learner",
}


def all_topics() -> tuple[Topic, ...]:
    return TOPICS


def topic_by_id(topic_id: str) -> Topic | None:
    for topic in TOPICS:
        if topic.id == topic_id:
            return topic
    return None
