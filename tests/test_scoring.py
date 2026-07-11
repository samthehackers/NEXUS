from nexus.detection.scoring import combine_scores, composite_risk_score, severity_to_score
from nexus.models import Severity


def test_severity_to_score_ordering():
    assert severity_to_score(Severity.LOW) < severity_to_score(Severity.MEDIUM)
    assert severity_to_score(Severity.MEDIUM) < severity_to_score(Severity.HIGH)
    assert severity_to_score(Severity.HIGH) < severity_to_score(Severity.CRITICAL)


def test_combine_scores_empty():
    assert combine_scores([]) == 0.0


def test_combine_scores_diminishing_returns():
    # Two equal scores should be less than double a single score (diminishing returns).
    single = combine_scores([10.0])
    double = combine_scores([10.0, 10.0])
    assert single < double < single * 2


def test_composite_risk_score_severity_only():
    score = composite_risk_score(Severity.HIGH)
    assert 0 < score <= 10


def test_composite_risk_score_increases_with_cvss():
    low_cvss = composite_risk_score(Severity.MEDIUM, cvss_score=2.0)
    high_cvss = composite_risk_score(Severity.MEDIUM, cvss_score=9.5)
    assert high_cvss > low_cvss


def test_composite_risk_score_increases_with_business_criticality():
    low = composite_risk_score(Severity.MEDIUM, business_criticality=1.0)
    high = composite_risk_score(Severity.MEDIUM, business_criticality=9.0)
    assert high > low


def test_composite_risk_score_shorter_path_scores_higher():
    short_path = composite_risk_score(Severity.HIGH, path_length=1)
    long_path = composite_risk_score(Severity.HIGH, path_length=6)
    assert short_path > long_path


def test_composite_risk_score_clamps_out_of_range_inputs():
    # CVSS/criticality outside 0-10 should be clamped, not blow up the formula.
    score = composite_risk_score(Severity.LOW, cvss_score=99.0, business_criticality=-5.0)
    assert 0 <= score <= 10
