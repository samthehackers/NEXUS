from pathlib import Path

from nexus.detection.anomaly import (
    detect_impossible_travel,
    detect_mass_resource_access,
    detect_off_hours_privileged_access,
    detect_privilege_escalation_chain,
    run_all_detectors,
)
from nexus.ingest.parsers import load_events

SAMPLE_LOGS = Path(__file__).parent.parent / "src" / "nexus" / "data" / "sample_auth_logs.json"


def _events():
    return load_events(SAMPLE_LOGS, "auth")


def test_impossible_travel_detected():
    findings = detect_impossible_travel(_events())
    assert len(findings) == 1
    assert findings[0].user == "jane.doe"
    assert findings[0].severity.value == "high"


def test_off_hours_privileged_access_detected():
    findings = detect_off_hours_privileged_access(_events())
    assert any(f.user == "mark.admin" for f in findings)


def test_privilege_escalation_chain_detected():
    findings = detect_privilege_escalation_chain(_events())
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"
    assert findings[0].user == "mark.admin"


def test_mass_resource_access_detected():
    findings = detect_mass_resource_access(_events())
    assert len(findings) >= 1
    assert findings[0].user == "svc.backup"


def test_no_false_positive_on_empty_events():
    assert run_all_detectors([]) == []


def test_run_all_detectors_sorted_by_risk_desc():
    findings = run_all_detectors(_events())
    scores = [f.risk_score for f in findings]
    assert scores == sorted(scores, reverse=True)
    assert len(findings) >= 4  # one per detector type triggered by sample data
