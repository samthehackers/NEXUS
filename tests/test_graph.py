from pathlib import Path

import pytest

from nexus.graph.engine import build_graph, load_topology
from nexus.graph.ranking import find_attack_paths
from nexus.models import Asset, GraphEdge

SAMPLE_TOPOLOGY = Path(__file__).parent.parent / "src" / "nexus" / "data" / "sample_topology.json"


def test_load_topology():
    assets, edges = load_topology(SAMPLE_TOPOLOGY)
    assert len(assets) == 6
    assert len(edges) == 5


def test_build_graph_rejects_unknown_edge_reference():
    assets = [Asset(asset_id="a", kind="host", criticality=1.0)]
    edges = [GraphEdge(source="a", target="ghost", relation="can_reach", weight=1.0)]
    with pytest.raises(ValueError):
        build_graph(assets, edges)


def test_find_attack_paths_reaches_critical_db():
    assets, edges = load_topology(SAMPLE_TOPOLOGY)
    graph = build_graph(assets, edges)
    paths = find_attack_paths(graph, entry_points=["workstation-12"], criticality_threshold=7.0)

    assert len(paths) > 0
    targets = {p.target for p in paths}
    assert "db-prod-01" in targets
    assert "backup-vault" in targets
    # highest risk path should be first
    assert paths[0].total_risk == max(p.total_risk for p in paths)


def test_find_attack_paths_unknown_entry_point_raises():
    assets, edges = load_topology(SAMPLE_TOPOLOGY)
    graph = build_graph(assets, edges)
    with pytest.raises(ValueError):
        find_attack_paths(graph, entry_points=["does-not-exist"])


def test_find_attack_paths_no_targets_returns_empty():
    assets, edges = load_topology(SAMPLE_TOPOLOGY)
    graph = build_graph(assets, edges)
    paths = find_attack_paths(graph, entry_points=["workstation-12"], criticality_threshold=99.0)
    assert paths == []
