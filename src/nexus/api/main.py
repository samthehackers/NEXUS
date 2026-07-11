"""Minimal FastAPI service exposing NEXUS analysis over HTTP.

Run with: uvicorn nexus.api.main:app --reload
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from nexus import __version__
from nexus.detection.anomaly import run_all_detectors
from nexus.graph.engine import build_graph
from nexus.graph.ranking import find_attack_paths
from nexus.ingest.parsers import load_events
from nexus.report.generator import generate_json_report

app = FastAPI(title="NEXUS", version=__version__, description="TrustGeeks Security")


class AnalyzeLogsRequest(BaseModel):
    log_type: str
    events: list[dict]


class AnalyzeGraphRequest(BaseModel):
    assets: list[dict]
    edges: list[dict]
    entry_points: list[str]
    criticality_threshold: float = 7.0


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/analyze/logs")
def analyze_logs(req: AnalyzeLogsRequest) -> dict:
    """Analyze a batch of raw log records (passed inline as JSON) for anomalies."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
        import json
        json.dump(req.events, tmp)
        tmp_path = tmp.name
    try:
        events = load_events(tmp_path, req.log_type)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    findings = run_all_detectors(events)
    return generate_json_report(findings, [])


@app.post("/analyze/graph")
def analyze_graph(req: AnalyzeGraphRequest) -> dict:
    """Build an attack graph from inline topology JSON and rank attack paths."""
    from nexus.models import Asset, GraphEdge

    try:
        assets = [Asset(**a) for a in req.assets]
        edges = [GraphEdge(**e) for e in req.edges]
        graph = build_graph(assets, edges)
        paths = find_attack_paths(
            graph, req.entry_points, criticality_threshold=req.criticality_threshold
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return generate_json_report([], paths)
