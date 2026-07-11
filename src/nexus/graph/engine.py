"""Builds a directed attack graph from an asset/edge topology definition.

Topology JSON shape:
{
  "assets": [{"asset_id": "...", "kind": "host|user|resource",
              "criticality": 0-10, "tags": ["..."]}],
  "edges":  [{"source": "...", "target": "...", "relation": "...",
              "weight": 1.0}]
}

`weight` represents traversal *difficulty* (higher = harder for an attacker
to move across that edge). This lets us use standard shortest-path
algorithms to find the *easiest* route to a critical asset.
"""

from __future__ import annotations

import json
from pathlib import Path

import networkx as nx

from nexus.models import Asset, GraphEdge


def load_topology(path: str | Path) -> tuple[list[Asset], list[GraphEdge]]:
    data = json.loads(Path(path).read_text())
    if "assets" not in data or "edges" not in data:
        raise ValueError(f"{path} must contain top-level 'assets' and 'edges' keys")

    assets = [Asset(**a) for a in data["assets"]]
    edges = [GraphEdge(**e) for e in data["edges"]]
    return assets, edges


def build_graph(assets: list[Asset], edges: list[GraphEdge]) -> nx.DiGraph:
    graph = nx.DiGraph()
    for asset in assets:
        graph.add_node(
            asset.asset_id,
            kind=asset.kind,
            criticality=asset.criticality,
            cvss_score=asset.cvss_score,
            tags=asset.tags,
        )
    for edge in edges:
        if edge.source not in graph or edge.target not in graph:
            raise ValueError(
                f"edge references unknown asset: {edge.source} -> {edge.target}"
            )
        graph.add_edge(edge.source, edge.target, relation=edge.relation, weight=edge.weight)
    return graph
