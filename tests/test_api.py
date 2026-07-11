import json
from pathlib import Path

from fastapi.testclient import TestClient

from nexus.api.main import app

client = TestClient(app)

SAMPLE_LOGS = Path(__file__).parent.parent / "src" / "nexus" / "data" / "sample_auth_logs.json"
SAMPLE_TOPOLOGY = Path(__file__).parent.parent / "src" / "nexus" / "data" / "sample_topology.json"


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_analyze_logs_endpoint():
    events = json.loads(SAMPLE_LOGS.read_text())
    r = client.post("/analyze/logs", json={"log_type": "auth", "events": events})
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["total_findings"] > 0


def test_analyze_logs_endpoint_bad_type():
    r = client.post("/analyze/logs", json={"log_type": "nonsense", "events": []})
    assert r.status_code == 422


def test_analyze_graph_endpoint():
    topo = json.loads(SAMPLE_TOPOLOGY.read_text())
    r = client.post("/analyze/graph", json={
        "assets": topo["assets"],
        "edges": topo["edges"],
        "entry_points": ["workstation-12"],
        "criticality_threshold": 7.0,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["total_attack_paths"] > 0


def test_analyze_graph_endpoint_bad_entry_point():
    topo = json.loads(SAMPLE_TOPOLOGY.read_text())
    r = client.post("/analyze/graph", json={
        "assets": topo["assets"],
        "edges": topo["edges"],
        "entry_points": ["does-not-exist"],
    })
    assert r.status_code == 422
