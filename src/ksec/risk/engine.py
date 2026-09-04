"""Deterministic, explainable risk engine (spec: RISK ENGINE).

Risk is calculated from severity, asset criticality, exploitability,
exposure, business impact, confidence and evidence quality. The calculation
is versioned (``RISK_VERSION``) and every result carries its reasoning.
"""
from __future__ import annotations

from dataclasses import dataclass

RISK_VERSION = "1.0"

SEVERITY_SCORES = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
CRITICALITY_SCORES = {"low": 1, "medium": 2, "high": 3, "critical": 4}
EXPLOITABILITY_SCORES = {"none": 0, "low": 1, "medium": 2, "high": 3}
EXPOSURE_SCORES = {"internal": 1, "limited": 2, "internet": 3}
IMPACT_SCORES = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCE = {"low": 0.5, "medium": 0.75, "high": 1.0}
EVIDENCE_QUALITY = {"none": 0.0, "partial": 0.4, "reproducible": 0.8, "verified": 1.2}

# Weights sum to 1.0.
_WEIGHTS = {
    "severity": 0.30,
    "criticality": 0.15,
    "exploitability": 0.20,
    "exposure": 0.15,
    "impact": 0.20,
}


def _normalize(mapping: dict, key: str, default: str) -> str:
    return key if key in mapping else default


def _factor(mapping: dict, key: str, minimum: int, maximum: int) -> tuple[str, float]:
    """Return (normalized_key, factor normalized to 0-10)."""
    normalized = _normalize(mapping, key, next(iter(mapping)))
    value = mapping[normalized]
    return normalized, ((value - minimum) / (maximum - minimum)) * 10.0


@dataclass(frozen=True)
class RiskResult:
    score: float
    level: str
    reasoning: str
    version: str = RISK_VERSION


def level_for_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 2.0:
        return "Low"
    return "Info"


def calculate_risk(
    *,
    severity: str = "info",
    asset_criticality: str = "low",
    exploitability: str = "none",
    exposure: str = "internal",
    business_impact: str = "low",
    confidence: str = "medium",
    evidence_quality: str = "none",
) -> RiskResult:
    severity_n, severity_factor = _factor(SEVERITY_SCORES, severity, 1, 5)
    criticality_n, criticality_factor = _factor(CRITICALITY_SCORES, asset_criticality, 1, 4)
    exploitability_n, exploitability_factor = _factor(
        EXPLOITABILITY_SCORES, exploitability, 0, 3
    )
    exposure_n, exposure_factor = _factor(EXPOSURE_SCORES, exposure, 1, 3)
    impact_n, impact_factor = _factor(IMPACT_SCORES, business_impact, 1, 4)

    confidence_n = _normalize(CONFIDENCE, confidence, "medium")
    evidence_n = _normalize(EVIDENCE_QUALITY, evidence_quality, "none")

    base = (
        _WEIGHTS["severity"] * severity_factor
        + _WEIGHTS["criticality"] * criticality_factor
        + _WEIGHTS["exploitability"] * exploitability_factor
        + _WEIGHTS["exposure"] * exposure_factor
        + _WEIGHTS["impact"] * impact_factor
    )
    score = base * CONFIDENCE[confidence_n]
    score = min(10.0, score + EVIDENCE_QUALITY[evidence_n])
    score = round(score, 2)
    level = level_for_score(score)

    reasoning = (
        f"risk v{RISK_VERSION}: severity={severity_n}(w={_WEIGHTS['severity']}),"
        f" criticality={criticality_n}(w={_WEIGHTS['criticality']}),"
        f" exploitability={exploitability_n}(w={_WEIGHTS['exploitability']}),"
        f" exposure={exposure_n}(w={_WEIGHTS['exposure']}),"
        f" impact={impact_n}(w={_WEIGHTS['impact']}),"
        f" confidence={confidence_n}, evidence_quality={evidence_n}"
        f" -> base={base:.2f}, score={score:.2f}, level={level}"
    )
    return RiskResult(score=score, level=level, reasoning=reasoning)