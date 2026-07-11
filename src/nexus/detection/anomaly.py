"""Behavioral anomaly detectors.

Each detector is a pure function: list[LogEvent] -> list[Finding]. They are
intentionally simple, explainable heuristics (not black-box ML) so a SOC
analyst can see exactly *why* something fired -- matching the transparency
principle used in MIRAGE's risk engine. Detectors are independent and can be
run individually or all together via run_all_detectors().
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import timedelta

from nexus.detection.scoring import severity_to_score
from nexus.intel.mitre import techniques_for_rule
from nexus.models import Finding, LogEvent, Severity

# --- tunable thresholds -----------------------------------------------------
IMPOSSIBLE_TRAVEL_WINDOW_MINUTES = 60
OFF_HOURS_START_HOUR = 22  # 10 PM
OFF_HOURS_END_HOUR = 6  # 6 AM
MASS_ACCESS_RESOURCE_THRESHOLD = 15
MASS_ACCESS_WINDOW_MINUTES = 10
PRIVILEGED_ACTION_KEYWORDS = (
    "admin",
    "sudo",
    "root",
    "privilege",
    "iam:",
    "createuser",
    "attachpolicy",
    "assumerole",
)
ESCALATION_ACTION_KEYWORDS = (
    "addpolicy",
    "attachpolicy",
    "assumerole",
    "grant",
    "addtogroup",
    "usermod",
    "setuid",
)


def _is_privileged(action: str) -> bool:
    return any(k in action.lower() for k in PRIVILEGED_ACTION_KEYWORDS)


def _is_escalation(action: str) -> bool:
    return any(k in action.lower() for k in ESCALATION_ACTION_KEYWORDS)


def _new_finding(rule: str, severity: Severity, title: str, description: str,
                  user: str | None, host: str | None, related: list[str],
                  timestamp) -> Finding:
    return Finding(
        finding_id=str(uuid.uuid4()),
        rule=rule,
        severity=severity,
        title=title,
        description=description,
        user=user,
        host=host,
        related_event_ids=related,
        risk_score=severity_to_score(severity),
        timestamp=timestamp,
        attack_techniques=techniques_for_rule(rule),
    )


def detect_impossible_travel(events: list[LogEvent]) -> list[Finding]:
    """Flag a user authenticating from two different countries within a
    time window too short for physical travel between them.

    Assumption: any change of country within IMPOSSIBLE_TRAVEL_WINDOW_MINUTES
    is treated as impossible travel. This is a simplification (no real
    geo-distance/speed model) and is documented as such -- swap in a proper
    geo-velocity check (e.g. haversine distance / plausible travel speed) for
    production use with real IP geolocation data.
    """
    findings: list[Finding] = []
    by_user: dict[str, list[LogEvent]] = defaultdict(list)
    for e in events:
        if e.user and e.country and e.source == e.source.AUTH:
            by_user[e.user].append(e)

    for user, user_events in by_user.items():
        user_events.sort(key=lambda e: e.timestamp)
        for prev, cur in zip(user_events, user_events[1:]):
            if prev.country and cur.country and prev.country != cur.country:
                delta = cur.timestamp - prev.timestamp
                if delta <= timedelta(minutes=IMPOSSIBLE_TRAVEL_WINDOW_MINUTES):
                    findings.append(_new_finding(
                        rule="impossible_travel",
                        severity=Severity.HIGH,
                        title=f"Impossible travel for user {user}",
                        description=(
                            f"{user} logged in from {prev.country} at {prev.timestamp} "
                            f"then from {cur.country} at {cur.timestamp} "
                            f"({delta.total_seconds() / 60:.1f} min apart)."
                        ),
                        user=user,
                        host=cur.host,
                        related=[prev.event_id, cur.event_id],
                        timestamp=cur.timestamp,
                    ))
    return findings


def detect_off_hours_privileged_access(events: list[LogEvent]) -> list[Finding]:
    """Flag privileged actions occurring outside normal business hours."""
    findings: list[Finding] = []
    for e in events:
        if not _is_privileged(e.action):
            continue
        hour = e.timestamp.hour
        if hour >= OFF_HOURS_START_HOUR or hour < OFF_HOURS_END_HOUR:
            findings.append(_new_finding(
                rule="off_hours_privileged_access",
                severity=Severity.MEDIUM,
                title=f"Off-hours privileged action by {e.user or 'unknown user'}",
                description=(
                    f"Privileged action '{e.action}' performed at {e.timestamp} "
                    f"(outside {OFF_HOURS_END_HOUR}:00-{OFF_HOURS_START_HOUR}:00)."
                ),
                user=e.user,
                host=e.host,
                related=[e.event_id],
                timestamp=e.timestamp,
            ))
    return findings


def detect_mass_resource_access(events: list[LogEvent]) -> list[Finding]:
    """Flag a user touching an unusually large number of distinct resources
    in a short window -- a common signature of data staging/exfil or
    automated recon.
    """
    findings: list[Finding] = []
    by_user: dict[str, list[LogEvent]] = defaultdict(list)
    for e in events:
        if e.user and e.resource:
            by_user[e.user].append(e)

    for user, user_events in by_user.items():
        user_events.sort(key=lambda e: e.timestamp)
        window: list[LogEvent] = []
        for e in user_events:
            window.append(e)
            window[:] = [w for w in window
                         if e.timestamp - w.timestamp <= timedelta(minutes=MASS_ACCESS_WINDOW_MINUTES)]
            distinct_resources = {w.resource for w in window}
            if len(distinct_resources) >= MASS_ACCESS_RESOURCE_THRESHOLD:
                findings.append(_new_finding(
                    rule="mass_resource_access",
                    severity=Severity.HIGH,
                    title=f"Mass resource access by {user}",
                    description=(
                        f"{user} accessed {len(distinct_resources)} distinct resources "
                        f"within {MASS_ACCESS_WINDOW_MINUTES} minutes (ending {e.timestamp})."
                    ),
                    user=user,
                    host=e.host,
                    related=[w.event_id for w in window],
                    timestamp=e.timestamp,
                ))
                window.clear()  # avoid duplicate overlapping findings
    return findings


def detect_privilege_escalation_chain(events: list[LogEvent]) -> list[Finding]:
    """Flag a user performing 2+ escalation-type actions in sequence,
    which often precedes lateral movement or ransomware deployment.
    """
    findings: list[Finding] = []
    by_user: dict[str, list[LogEvent]] = defaultdict(list)
    for e in events:
        if e.user and _is_escalation(e.action):
            by_user[e.user].append(e)

    for user, user_events in by_user.items():
        if len(user_events) >= 2:
            user_events.sort(key=lambda e: e.timestamp)
            findings.append(_new_finding(
                rule="privilege_escalation_chain",
                severity=Severity.CRITICAL,
                title=f"Privilege escalation chain by {user}",
                description=(
                    f"{user} performed {len(user_events)} escalation-related actions: "
                    f"{', '.join(e.action for e in user_events)}."
                ),
                user=user,
                host=user_events[-1].host,
                related=[e.event_id for e in user_events],
                timestamp=user_events[-1].timestamp,
            ))
    return findings


DETECTORS = (
    detect_impossible_travel,
    detect_off_hours_privileged_access,
    detect_mass_resource_access,
    detect_privilege_escalation_chain,
)


def run_all_detectors(events: list[LogEvent]) -> list[Finding]:
    findings: list[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(events))
    return sorted(findings, key=lambda f: f.risk_score, reverse=True)
