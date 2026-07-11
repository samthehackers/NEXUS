"""Discovers and ranks attack paths from entry points to critical assets.

Approach: for each (entry_point, critical_asset) pair, enumerate simple
paths up to a bounded depth (enumeration on large graphs is expensive, so we
cap both path length and the number of paths considered per pair), score
each path by combining edge traversal difficulty with the criticality of the
assets touched, then return the highest-risk paths first. This mirrors how a
red teamer reasons about lateral movement: easiest route to the most
valuable target wins.
"""

from __future__ import annotations

import uuid

import networkx as nx

from nexus.detection.scoring import combine_scores
from nexus.models import AttackPath

DEFAULT_CRITICALITY_THRESHOLD = 7.0
DEFAULT_MAX_PATH_LENGTH = 6
DEFAULT_MAX_PATHS_PER_TARGET = 5


def _critical_targets(graph: nx.DiGraph, threshold: float) -> list[str]:
    return [
        n for n, attrs in graph.nodes(data=True)
        if attrs.get("criticality", 0) >= threshold
    ]


def _path_risk(graph: nx.DiGraph, path: list[str]) -> float:
    # Traversal ease: invert edge weight (lower weight = easier = riskier).
    edge_risk_scores = []
    for u, v in zip(path, path[1:]):
        weight = graph[u][v].get("weight", 1.0)
        edge_risk_scores.append(10.0 / max(weight, 0.1))

    target_attrs = graph.nodes[path[-1]]
    target_criticality = target_attrs.get("criticality", 1.0)
    # CVSS is optional (populated externally from a vuln scanner). When
    # present on the target asset, a short path to a highly vulnerable,
    # highly critical asset scores higher than the same path to a hardened one.
    target_cvss = target_attrs.get("cvss_score")
    cvss_bonus = (target_cvss * 0.5) if target_cvss is not None else 0.0

    return combine_scores(edge_risk_scores) + target_criticality + cvss_bonus


def find_attack_paths(
    graph: nx.DiGraph,
    entry_points: list[str],
    criticality_threshold: float = DEFAULT_CRITICALITY_THRESHOLD,
    max_path_length: int = DEFAULT_MAX_PATH_LENGTH,
    max_paths_per_target: int = DEFAULT_MAX_PATHS_PER_TARGET,
) -> list[AttackPath]:
    for ep in entry_points:
        if ep not in graph:
            raise ValueError(f"entry point '{ep}' is not a known asset in the graph")

    targets = _critical_targets(graph, criticality_threshold)
    results: list[AttackPath] = []

    for entry in entry_points:
        for target in targets:
            if entry == target:
                continue
            try:
                paths = list(nx.all_simple_paths(
                    graph, source=entry, target=target, cutoff=max_path_length
                ))
            except nx.NodeNotFound:
                continue

            scored = sorted(
                ((p, _path_risk(graph, p)) for p in paths),
                key=lambda item: item[1],
                reverse=True,
            )[:max_paths_per_target]

            for path_nodes, risk in scored:
                results.append(AttackPath(
                    path_id=str(uuid.uuid4()),
                    nodes=path_nodes,
                    total_risk=round(risk, 2),
                    entry_point=entry,
                    target=target,
                    rationale=(
                        f"{len(path_nodes) - 1}-hop path from '{entry}' to critical asset "
                        f"'{target}' (criticality "
                        f"{graph.nodes[target].get('criticality', 0)}) via "
                        f"{' -> '.join(path_nodes)}."
                    ),
                ))

    return sorted(results, key=lambda ap: ap.total_risk, reverse=True)
