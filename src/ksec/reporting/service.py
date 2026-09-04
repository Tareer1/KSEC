"""Reporting engine (spec: REPORTING ENGINE).

Reports are generated from structured KSEC data (engagement, scope, assets,
findings, risk, evidence, cases), never from raw terminal output.
"""
from __future__ import annotations

import html as html_lib
import sqlite3
from dataclasses import dataclass

from ksec.assets.service import AssetService
from ksec.authorization.service import AuthorizationService
from ksec.cases.service import CaseService
from ksec.db.connection import Database
from ksec.evidence.service import EvidenceService
from ksec.findings.service import FindingService
from ksec.identity.users import now_utc

VALID_FORMATS = ("markdown", "html")


@dataclass(frozen=True)
class Report:
    id: int
    engagement_id: int | None
    title: str
    format: str
    content: str
    created_at: str
    created_by: str


def _escape_md(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


class ReportService:
    def __init__(
        self,
        db: Database,
        authz: AuthorizationService,
        assets: AssetService,
        findings: FindingService,
        evidence: EvidenceService,
        cases: CaseService,
    ):
        self.db = db
        self.authz = authz
        self.assets = assets
        self.findings = findings
        self.evidence = evidence
        self.cases = cases

    def generate(
        self,
        engagement_id: int | None,
        title: str = "",
        fmt: str = "markdown",
        created_by: str = "",
    ) -> Report:
        if fmt not in VALID_FORMATS:
            raise ValueError(f"Invalid report format: {fmt}")
        engagement = self.authz.get_engagement(engagement_id) if engagement_id else None
        report_title = title or (f"Assessment Report — {engagement.name}" if engagement else "KSEC Report")

        findings = self.findings.list(engagement_id=engagement_id)
        assets = self.assets.list(engagement_id=engagement_id)
        evidence = self.evidence.list(engagement_id=engagement_id)
        cases = self.cases.list()
        rules = self.authz.list_authorizations(engagement_id) if engagement_id else []

        content = (
            self._render_markdown(
                report_title, engagement, rules, assets, findings, evidence, cases
            )
            if fmt == "markdown"
            else self._render_html(
                report_title, engagement, rules, assets, findings, evidence, cases
            )
        )
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO reports (engagement_id, title, format, content, created_at,"
                " created_by) VALUES (?, ?, ?, ?, ?, ?)",
                (engagement_id, report_title, fmt, content, now_utc(), created_by),
            )
        return self.get(cursor.lastrowid)

    def get(self, report_id: int) -> Report | None:
        row = self.db.query_one("SELECT * FROM reports WHERE id = ?", (report_id,))
        return self._from_row(row) if row else None

    def list(self) -> list[Report]:
        rows = self.db.query_all("SELECT * FROM reports ORDER BY id DESC")
        return [self._from_row(row) for row in rows]

    # -- renderers ---------------------------------------------------------

    def _render_markdown(
        self, title, engagement, rules, assets, findings, evidence, cases
    ) -> str:
        lines = [f"# {title}", ""]
        lines.append(f"- Generated: {now_utc()}")
        if engagement:
            lines.append(f"- Engagement: {engagement.name} ({engagement.status})")
        lines.append("")
        lines.append("## Scope")
        if rules:
            for rule in rules:
                lines.append(f"- **{rule['effect']}** `{rule['action']}` → `{rule['target']}`")
        else:
            lines.append("- _No scope rules defined._")
        lines.append("")
        lines.append(f"## Assets ({len(assets)})")
        for asset in assets:
            lines.append(f"- {asset.target} ({asset.asset_type}, criticality={asset.criticality})")
        lines.append("")
        lines.append(f"## Findings ({len(findings)})")
        for finding in findings:
            lines.append(
                f"- **[{finding.severity.upper()}]** {finding.title} "
                f"(status={finding.status}, risk={finding.risk_level or 'n/a'} "
                f"score={finding.risk_score if finding.risk_score is not None else 'n/a'})"
            )
            if finding.description:
                lines.append(f"  - {_escape_md(finding.description)}")
            if finding.recommendation:
                lines.append(f"  - **Recommendation:** {_escape_md(finding.recommendation)}")
        lines.append("")
        lines.append(f"## Evidence ({len(evidence)})")
        for item in evidence:
            lines.append(
                f"- `{item.sha256[:16]}…` {item.tool} — {item.collection_method or 'collected'}"
            )
        lines.append("")
        open_cases = [c for c in cases if c.status != "closed"]
        lines.append(f"## Cases ({len(open_cases)} open)")
        for case in open_cases:
            lines.append(f"- {case.title} (severity={case.severity}, status={case.status})")
        return "\n".join(lines) + "\n"

    def _render_html(self, title, engagement, rules, assets, findings, evidence, cases) -> str:
        e = html_lib.escape
        parts = [f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>{e(title)}</title></head><body>"]
        parts.append(f"<h1>{e(title)}</h1>")
        if engagement:
            parts.append(f"<p>Engagement: <strong>{e(engagement.name)}</strong> ({e(engagement.status)})</p>")
        parts.append("<h2>Scope</h2><ul>")
        for rule in rules or []:
            parts.append(f"<li><strong>{e(rule['effect'])}</strong> {e(rule['action'])} &rarr; <code>{e(rule['target'])}</code></li>")
        parts.append("</ul>")
        parts.append(f"<h2>Assets ({len(assets)})</h2><ul>")
        for asset in assets:
            parts.append(f"<li>{e(asset.target)} ({e(asset.asset_type)}, criticality={e(asset.criticality)})</li>")
        parts.append("</ul>")
        parts.append(f"<h2>Findings ({len(findings)})</h2><ul>")
        for finding in findings:
            parts.append(
                f"<li><strong>[{e(finding.severity.upper())}]</strong> {e(finding.title)}"
                f" <em>({e(finding.status)}, risk={e(finding.risk_level or 'n/a')})</em></li>"
            )
        parts.append("</ul>")
        parts.append(f"<h2>Evidence ({len(evidence)})</h2><ul>")
        for item in evidence:
            parts.append(f"<li><code>{e(item.sha256[:16])}&hellip;</code> {e(item.tool)}</li>")
        parts.append("</ul>")
        parts.append("</body></html>")
        return "".join(parts)

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Report:
        return Report(
            id=row["id"],
            engagement_id=row["engagement_id"],
            title=row["title"],
            format=row["format"],
            content=row["content"],
            created_at=row["created_at"],
            created_by=row["created_by"],
        )