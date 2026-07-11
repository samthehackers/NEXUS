"""Transparent, weighted risk scoring (no black-box ML) -- consistent with
MIRAGE's risk engine design so scores mean the same thing across TrustGeeks
tools.
"""

from __future__ import annotations

from nexus.models import Severity

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.LOW: 2.5,
    Severity.MEDIUM: 5.0,
    Severity.HIGH: 7.5,
    Severity.CRITICAL: 10.0,
}


def severity_to_score(severity: Severity) -> float:
    return SEVERITY_WEIGHTS[severity]


def combine_scores(scores: list[float]) -> float:
    """Combine multiple risk scores (e.g. along an attack path).

    Uses a diminishing-returns sum so that many low-risk hops don't
    outweigh one critical hop, while still rewarding compounding risk.
    """
    if not scores:
        return 0.0
    ordered = sorted(scores, reverse=True)
    total = 0.0
    for i, s in enumerate(ordered):
        total += s / (1 + i * 0.5)
    return round(total, 2)


# Weights for the composite score. Kept explicit (not learned) so an analyst
# can see exactly why a number is what it is -- change these constants rather
# than tuning a model.
COMPOSITE_WEIGHTS = {
    "severity": 0.35,
    "cvss": 0.25,
    "business_criticality": 0.25,
    "path_length_penalty": 0.15,
}


def composite_risk_score(
    severity: Severity,
    cvss_score: float | None = None,
    business_criticality: float | None = None,
    path_length: int | None = None,
    max_reasonable_path_length: int = 6,
) -> float:
    """Combine detection severity with CVSS, business criticality of the
    affected asset, and attack-path length into a single 0-10 score.

    All inputs beyond `severity` are optional: NEXUS does not invent a CVSS
    score or a path length it wasn't given. Missing components are simply
    left out of the weighted average (weights renormalize over the
    components that ARE present), so a finding with no CVSS/path data still
    gets a sensible score from severity alone.

    `path_length` shortens risk the *longer* the path is (a target 5 hops
    away is less immediately reachable than one 1 hop away) -- it is
    expressed here as a bonus for SHORT paths, scaled 0-10.
    """
    components: dict[str, float] = {"severity": severity_to_score(severity)}

    if cvss_score is not None:
        components["cvss"] = max(0.0, min(10.0, cvss_score))
    if business_criticality is not None:
        components["business_criticality"] = max(0.0, min(10.0, business_criticality))
    if path_length is not None:
        # 1-hop path -> 10.0 (max urgency), longer paths taper toward 0.
        capped = min(path_length, max_reasonable_path_length)
        components["path_length_penalty"] = 10.0 * (1 - (capped - 1) / max_reasonable_path_length)

    total_weight = sum(COMPOSITE_WEIGHTS[k] for k in components)
    score = sum(components[k] * COMPOSITE_WEIGHTS[k] for k in components) / total_weight
    return round(score, 2)
