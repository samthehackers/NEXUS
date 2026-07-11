from nexus.detection.anomaly import run_all_detectors
from nexus.graph.engine import build_graph
from nexus.graph.ranking import find_attack_paths
from nexus.ingest.parsers import load_events
from nexus.models import Asset, GraphEdge
from nexus.report.generator import generate_html_report, generate_json_report, write_reports
from pathlib import Path

SAMPLE_LOGS = Path(__file__).parent.parent / "src" / "nexus" / "data" / "sample_auth_logs.json"


def _sample_graph_and_paths():
    assets = [
        Asset(asset_id="entry", kind="host", criticality=1.0),
        Asset(asset_id="target", kind="host", criticality=9.0),
    ]
    edges = [GraphEdge(source="entry", target="target", relation="can_reach", weight=1.0)]
    graph = build_graph(assets, edges)
    return find_attack_paths(graph, entry_points=["entry"], criticality_threshold=7.0)


def test_generate_json_report_structure():
    events = load_events(SAMPLE_LOGS, "auth")
    findings = run_all_detectors(events)
    paths = _sample_graph_and_paths()
    report = generate_json_report(findings, paths)

    assert "summary" in report
    assert report["summary"]["total_findings"] == len(findings)
    assert report["summary"]["total_attack_paths"] == len(paths)


def test_generate_html_report_contains_findings():
    events = load_events(SAMPLE_LOGS, "auth")
    findings = run_all_detectors(events)
    html = generate_html_report(findings, [])
    assert "NEXUS Security Report" in html
    if findings:
        assert findings[0].rule in html


def test_write_reports_creates_files(tmp_path):
    events = load_events(SAMPLE_LOGS, "auth")
    findings = run_all_detectors(events)
    paths = _sample_graph_and_paths()
    json_path, html_path = write_reports(findings, paths, tmp_path)
    assert json_path.exists()
    assert html_path.exists()
