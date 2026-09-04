"""SOC alert pipeline (spec 08#17 SOC ALERT PIPELINE).

Stages for every ingested event:

1. Normalize — arbitrary event -> canonical record (EventStore.ingest).
2. Enrich   — resolve the event's entity against KSEC: asset (with
              criticality), known IOCs, open findings.
3. Correlate — recent events sharing the same IP/domain/host; count and
              distinct sources. Confidence from volume.
4. Rule evaluation — deterministic detection rules; also a severity gate so
              high/critical events always alert.
5. Risk score — deterministic: base severity + asset criticality + IOC
              weight + correlation volume + rule boost (0..10).
6. Alert    — create the alert when a rule fired or the gate passed.
7. Case     — auto-open a case for high-risk alerts (rule-driven).
"""
from __future__ import annotations

from ksec.assets.service import AssetService
from ksec.cases.service import CaseService
from ksec.db.connection import Database
from ksec.soc.alerts import Alert, AlertService
from ksec.soc.normalizer import EventStore, NormalizedEvent, normalize_severity
from ksec.soc.rules import SEVERITY_RANK, DetectionRule, RuleStore

# Risk contribution weights (deterministic).
SEVERITY_BASE = {"info": 1, "low": 2, "medium": 4, "high": 7, "critical": 9}
IOC_WEIGHT = {"low": 1.0, "medium": 1.5, "high": 2.0}
CASE_OPEN_MIN_RISK = 7.0

# Entity lookup keys ordered by precedence for enrichment/correlation.
def _entity_keys(event: NormalizedEvent) -> list[str]:
    keys = []
    for key in (event.ip, event.domain, event.host):
        if key and key not in keys:
            keys.append(key)
    return keys


class SocPipeline:
    def __init__(
        self,
        db: Database,
        *,
        events: EventStore | None = None,
        rules: RuleStore | None = None,
        alerts: AlertService | None = None,
        assets: AssetService | None = None,
        cases: CaseService | None = None,
        intel=None,
        notifications=None,
    ):
        self.db = db
        self.events = events or EventStore(db)
        self.rules = rules or RuleStore(db)
        self.alerts = alerts or AlertService(db)
        self.assets = assets
        self.cases = cases
        self.intel = intel
        self.notifications = notifications

    # -- public API --------------------------------------------------------

    def ingest(self, raw_event: dict) -> dict:
        """Run one event through the full pipeline. Returns a stage report.

        Idempotent: re-ingesting an already-seen event_id returns the stored
        event with created=False and does not duplicate alerts.
        """
        event, created = self.events.ingest(raw_event)
        if not created:
            return {
                "event_id": event.event_id,
                "created": False,
                "duplicate": True,
                "alerted": False,
                "stages": {"normalize": "duplicate — already ingested"},
            }

        enrichment = self._enrich(event)
        correlation = self._correlate(event)
        matched_rules = self._evaluate_rules(event)
        gate = event.severity in ("high", "critical")
        risk = self._risk_score(event, enrichment, correlation, matched_rules)
        severity = self._final_severity(event, matched_rules, risk)

        report = {
            "event_id": event.event_id,
            "created": True,
            "normalized": event.to_dict(),
            "enrichment": enrichment,
            "correlation": correlation,
            "rules_matched": [r.to_dict() for r in matched_rules],
            "severity_gate": gate,
            "risk_score": round(risk, 1),
            "severity": severity,
            "alerted": False,
        }

        should_alert = bool(matched_rules) or gate
        if not should_alert:
            report["alerted"] = False
            report["reason_not_alerted"] = "no rule matched and severity below gate"
            return report

        alert, case = self._create_alert(
            event, enrichment, correlation, matched_rules, risk, severity
        )
        report["alerted"] = True
        report["alert"] = _alert_dict(alert)
        report["case"] = _case_dict(case) if case else None
        # Event-driven notification (spec 02#30): SOC alerts notify via the
        # configured providers. Best-effort — never affects the pipeline.
        if self.notifications is not None:
            try:
                self.notifications.record(
                    channel="soc",
                    event_type="soc.alert",
                    title=f"[{severity.upper()}] {alert.summary}",
                    body=(
                        f"Alert #{alert.id} (risk {risk:.1f}/10)"
                        f" from {event.source}: {event.event_type}"
                    ),
                )
            except Exception:
                pass
        return report

    def _enrich(self, event: NormalizedEvent) -> dict:
        """Stage 2: resolve entity context (asset, IOC, findings)."""
        entity = _entity_keys(event)
        asset = None
        if self.assets is not None and entity:
            # Find the most recently registered asset matching any entity key.
            rows = self.db.query_all(
                "SELECT id FROM assets WHERE target IN ({}) ORDER BY id DESC LIMIT 1".format(
                    ",".join("?" * len(entity))
                ),
                entity,
            )
            if rows:
                asset = self.assets.get(rows[0]["id"])

        ioc = None
        if self.intel is not None and entity:
            for key in entity:
                matches = self.intel.correlate(key)
                if matches:
                    ioc = matches[0]
                    break

        findings = []
        if entity:
            for key in entity:
                for row in self.db.query_all(
                    "SELECT id, title, severity, status FROM findings"
                    " WHERE (LOWER(title) LIKE ? OR LOWER(description) LIKE ?)"
                    " AND status != 'false_positive' ORDER BY id DESC LIMIT 3",
                    (f"%{key.lower()}%", f"%{key.lower()}%"),
                ):
                    findings.append(dict(row))

        return {
            "entity": entity,
            "asset": _asset_dict(asset) if asset else None,
            "ioc": (
                {
                    "id": ioc.id,
                    "type": ioc.type,
                    "value": ioc.value,
                    "confidence": ioc.confidence,
                    "actor_id": ioc.actor_id,
                }
                if ioc
                else None
            ),
            "related_findings": findings,
        }

    def _correlate(self, event: NormalizedEvent) -> dict:
        """Stage 3: same-entity events inside a window (volume signal)."""
        all_related: dict[str, list] = {}
        for key in _entity_keys(event):
            for related in self.events.recent_for_entity(key, exclude_event_id=event.event_id):
                all_related.setdefault(related.event_id, related)
        related = sorted(all_related.values(), key=lambda e: e.id, reverse=True)
        sources = sorted({e.source for e in related})
        return {
            "related_event_count": len(related),
            "distinct_sources": sources,
            "related_event_ids": [e.event_id for e in related[:10]],
        }

    def _evaluate_rules(self, event: NormalizedEvent) -> list[DetectionRule]:
        """Stage 4: deterministic rule evaluation.

        Single-event rules match against this event directly; windowed rules
        (count-based, e.g. "5 failures in 5 minutes") are evaluated against
        the stored events inside their time window and fire when the incoming
        event crosses the threshold.
        """
        matched = []
        for rule in self.rules.list(enabled_only=True):
            if rule.windowed:
                continue
            if rule.matches(event):
                matched.append(rule)
        for rule in self.rules.windowed_rules():
            if self.rules.evaluate_windowed(rule, event):
                matched.append(rule)
        return matched

    def _risk_score(self, event, enrichment, correlation, rules) -> float:
        """Stage 5: deterministic 0..10 score."""
        score = float(SEVERITY_BASE[event.severity])

        asset = enrichment.get("asset")
        if asset:
            score += {"low": 0.0, "medium": 0.5, "high": 1.0, "critical": 2.0}.get(
                asset.get("criticality", "low"), 0.0
            )

        ioc = enrichment.get("ioc")
        if ioc:
            score += IOC_WEIGHT.get(ioc.get("confidence", "low"), 1.0)
            if ioc.get("actor_id"):
                score += 0.5

        volume = correlation.get("related_event_count", 0)
        if volume >= 10:
            score += 2.0
        elif volume >= 5:
            score += 1.5
        elif volume >= 3:
            score += 1.0
        elif volume >= 1:
            score += 0.5

        if correlation.get("distinct_sources"):
            score += min(1.0, 0.25 * len(correlation["distinct_sources"]))

        for rule in rules:
            score += float(rule.risk_boost)

        return max(0.0, min(10.0, score))

    def _final_severity(self, event, rules, risk: float) -> str:
        """Highest of event/rule severity; escalated when risk is very high."""
        rank = SEVERITY_RANK[event.severity]
        for rule in rules:
            rank = max(rank, SEVERITY_RANK.get(rule.severity, rank))
        if risk >= 9.0 and rank < SEVERITY_RANK["critical"]:
            rank = SEVERITY_RANK["critical"]
        elif risk >= 7.0 and rank < SEVERITY_RANK["high"]:
            rank = SEVERITY_RANK["high"]
        return {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}[rank]

    def _create_alert(
        self, event, enrichment, correlation, rules, risk: float, severity: str
    ) -> tuple[Alert, object | None]:
        """Stage 6-7: create alert (+ auto-open case)."""
        rule = rules[0] if rules else None
        summary_parts = [severity.upper(), event.event_type]
        entity = _entity_keys(event)
        if entity:
            summary_parts.append(entity[0])
        if rule:
            summary_parts.append(f"(rule {rule.name})")
        summary = " ".join(summary_parts)

        details = {
            "entity": entity,
            "related_event_count": correlation.get("related_event_count", 0),
            "distinct_sources": correlation.get("distinct_sources", []),
            "ioc_id": (enrichment.get("ioc") or {}).get("id"),
            "asset_id": (enrichment.get("asset") or {}).get("id"),
            "matched_rule": rule.name if rule else None,
            "severity_gate": not rule,
        }

        case = None
        case_id = None
        open_case = rule.open_case if rule else risk >= CASE_OPEN_MIN_RISK
        if open_case and self.cases is not None:
            case = self.cases.create(
                title=f"{severity.upper()} alert: {event.event_type} {entity[0] if entity else ''}".strip(),
                description=(
                    f"Auto-opened from SOC alert for {event.event_id} ({event.source}). "
                    f"Risk {risk:.1f}/10."
                ),
                severity=severity,
            )
            case_id = case.id

        alert = self.alerts.create(
            source=f"rule:{rule.name}" if rule else "severity gate",
            type=event.event_type,
            severity=severity,
            risk_score=round(risk, 1),
            summary=summary,
            details=details,
            rule_id=rule.id if rule else None,
            event_id=event.id,
            asset_id=(enrichment.get("asset") or {}).get("id"),
            finding_id=(enrichment.get("related_findings") or [{}])[0].get("id"),
            case_id=case_id,
            ioc_id=(enrichment.get("ioc") or {}).get("id"),
        )
        return alert, case


def _asset_dict(asset) -> dict:
    return {
        "id": asset.id,
        "target": asset.target,
        "asset_type": asset.asset_type,
        "criticality": asset.criticality,
        "owner": asset.owner,
        "source": asset.source,
    }


def _case_dict(case) -> dict:
    return {
        "id": case.id,
        "engagement_id": case.engagement_id,
        "title": case.title,
        "description": case.description,
        "severity": case.severity,
        "status": case.status,
        "owner": case.owner,
        "created_at": case.created_at,
    }


def _alert_dict(alert) -> dict:
    return {
        "id": alert.id,
        "alert_id": alert.alert_id,
        "source": alert.source,
        "type": alert.type,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "status": alert.status,
        "rule_id": alert.rule_id,
        "event_id": alert.event_id,
        "asset_id": alert.asset_id,
        "finding_id": alert.finding_id,
        "case_id": alert.case_id,
        "ioc_id": alert.ioc_id,
        "summary": alert.summary,
        "created_at": alert.created_at,
        "acknowledged_at": alert.acknowledged_at,
        "resolved_at": alert.resolved_at,
    }