from pathlib import Path

from nexus.detection.anomaly import run_all_detectors
from nexus.ingest.parsers import load_events
from nexus.intel.ioc import StaticReputationEnricher, enrich_events, enrich_findings
from nexus.intel.mitre import known_rules, techniques_for_rule

SAMPLE_LOGS = Path(__file__).parent.parent / "src" / "nexus" / "data" / "sample_auth_logs.json"


def test_every_detector_rule_has_attack_mapping():
    # Guards against a new detector shipping without ATT&CK context.
    from nexus.detection.anomaly import DETECTORS

    mapped_rules = set(known_rules())
    detector_rule_names = {
        "detect_impossible_travel": "impossible_travel",
        "detect_off_hours_privileged_access": "off_hours_privileged_access",
        "detect_mass_resource_access": "mass_resource_access",
        "detect_privilege_escalation_chain": "privilege_escalation_chain",
    }
    for detector in DETECTORS:
        rule = detector_rule_names[detector.__name__]
        assert rule in mapped_rules
        assert len(techniques_for_rule(rule)) > 0


def test_unmapped_rule_returns_empty_list():
    assert techniques_for_rule("not_a_real_rule") == []


def test_findings_carry_attack_techniques():
    events = load_events(SAMPLE_LOGS, "auth")
    findings = run_all_detectors(events)
    assert all(f.attack_techniques for f in findings)


def test_static_reputation_enricher_matches_known_ip():
    enricher = StaticReputationEnricher({
        "ips": {"45.10.0.9": {"reputation": "malicious", "description": "known C2 relay"}},
        "domains": {},
        "hashes": {},
    })
    match = enricher.lookup("45.10.0.9", "ip")
    assert match is not None
    assert match.reputation == "malicious"


def test_static_reputation_enricher_no_match_returns_none():
    enricher = StaticReputationEnricher()
    assert enricher.lookup("1.2.3.4", "ip") is None


def test_enrich_events_and_findings_end_to_end():
    events = load_events(SAMPLE_LOGS, "auth")
    findings = run_all_detectors(events)
    enricher = StaticReputationEnricher({
        "ips": {"45.10.0.9": {"reputation": "malicious", "description": "known C2 relay"}},
        "domains": {},
        "hashes": {},
    })
    event_matches = enrich_events(events, enricher)
    enriched = enrich_findings(findings, event_matches)

    impossible_travel = [f for f in enriched if f.rule == "impossible_travel"]
    assert impossible_travel
    assert any(m.indicator == "45.10.0.9" for m in impossible_travel[0].ioc_matches)


def test_enrich_findings_does_not_mutate_originals():
    events = load_events(SAMPLE_LOGS, "auth")
    findings = run_all_detectors(events)
    original_ioc_state = [f.ioc_matches for f in findings]
    enricher = StaticReputationEnricher()
    enrich_findings(findings, enrich_events(events, enricher))
    assert [f.ioc_matches for f in findings] == original_ioc_state
