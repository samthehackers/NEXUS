"""Generates human-readable reports from findings + attack paths.

v0.2 adds: MITRE ATT&CK / IOC columns in the findings table, and an
interactive attack-graph visualization (vis-network, loaded from
cdnjs.cloudflare.com) built directly from the ranked attack paths so an
analyst can see the graph, not just a path list.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Template

from nexus.models import AttackPath, Finding

_HTML_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NEXUS Security Report</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/standalone/umd/vis-network.min.js"></script>
<style>
  body { font-family: -apple-system, Segoe UI, sans-serif; margin: 2rem; background: #0b0f14; color: #dfe6ee; }
  h1 { color: #4fd1c5; }
  h2 { color: #63b3ed; border-bottom: 1px solid #2d3748; padding-bottom: .3rem; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; }
  th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #2d3748; font-size: .85rem; }
  th { color: #a0aec0; text-transform: uppercase; font-size: .7rem; }
  .sev-critical { color: #fc8181; font-weight: bold; }
  .sev-high { color: #f6ad55; font-weight: bold; }
  .sev-medium { color: #f6e05e; }
  .sev-low { color: #9ae6b4; }
  .meta { color: #718096; font-size: .85rem; margin-bottom: 1.5rem; }
  .tag { display: inline-block; background: #1a2332; border: 1px solid #2d3748; border-radius: 4px;
         padding: 1px 6px; margin: 1px; font-size: .75rem; color: #90cdf4; }
  #attack-graph { width: 100%; height: 480px; background: #0f1620; border: 1px solid #2d3748; border-radius: 6px; margin-bottom: 2rem; }
</style>
</head>
<body>
  <h1>NEXUS Security Report</h1>
  <div class="meta">Generated {{ generated_at }} · TrustGeeks Security</div>

  <h2>Attack Graph</h2>
  <div id="attack-graph"></div>

  <h2>Findings ({{ findings|length }})</h2>
  <table>
    <tr><th>Severity</th><th>Rule</th><th>Title</th><th>User</th><th>Host</th><th>Risk</th><th>ATT&amp;CK</th><th>IOC</th><th>Time</th></tr>
    {% for f in findings %}
    <tr>
      <td class="sev-{{ f.severity.value }}">{{ f.severity.value|upper }}</td>
      <td>{{ f.rule }}</td>
      <td>{{ f.title }}</td>
      <td>{{ f.user or "-" }}</td>
      <td>{{ f.host or "-" }}</td>
      <td>{{ f.risk_score }}</td>
      <td>
        {% for t in f.attack_techniques %}<span class="tag">{{ t.technique_id }}</span>{% endfor %}
        {% if not f.attack_techniques %}-{% endif %}
      </td>
      <td>
        {% for m in f.ioc_matches %}<span class="tag">{{ m.indicator }} ({{ m.reputation }})</span>{% endfor %}
        {% if not f.ioc_matches %}-{% endif %}
      </td>
      <td>{{ f.timestamp }}</td>
    </tr>
    {% if f.llm_summary %}
    <tr><td colspan="9" style="color:#a0aec0; font-style: italic;">{{ f.llm_summary }}</td></tr>
    {% endif %}
    {% endfor %}
  </table>

  <h2>Top Attack Paths ({{ paths|length }})</h2>
  <table>
    <tr><th>Entry</th><th>Target</th><th>Risk</th><th>Path</th></tr>
    {% for p in paths %}
    <tr>
      <td>{{ p.entry_point }}</td>
      <td>{{ p.target }}</td>
      <td>{{ p.total_risk }}</td>
      <td>{{ p.nodes|join(" &rarr; ") }}</td>
    </tr>
    {% endfor %}
  </table>

  <script>
    const graphData = {{ graph_json|safe }};
    const container = document.getElementById('attack-graph');
    if (graphData.nodes.length > 0) {
      const nodes = new vis.DataSet(graphData.nodes);
      const edges = new vis.DataSet(graphData.edges);
      new vis.Network(container, { nodes, edges }, {
        nodes: { shape: 'dot', size: 16, font: { color: '#dfe6ee' } },
        edges: { arrows: 'to', color: { color: '#4a5568', highlight: '#4fd1c5' }, smooth: true },
        physics: { stabilization: true },
      });
    } else {
      container.innerHTML = '<p style="color:#718096; padding: 1rem;">No attack paths to visualize.</p>';
    }
  </script>
</body>
</html>
""")


def _paths_to_vis_graph(paths: list[AttackPath]) -> dict:
    """Builds vis-network node/edge data from the ranked attack paths.

    Entry points and critical targets are colored distinctly so an analyst
    can immediately see where attacks start and what they reach.
    """
    entry_points = {p.entry_point for p in paths}
    targets = {p.target for p in paths}

    node_ids: set[str] = set()
    for p in paths:
        node_ids.update(p.nodes)

    def _color(node_id: str) -> str:
        if node_id in targets:
            return "#fc8181"  # critical asset - red
        if node_id in entry_points:
            return "#68d391"  # entry point - green
        return "#63b3ed"  # intermediate hop - blue

    nodes = [{"id": n, "label": n, "color": _color(n)} for n in sorted(node_ids)]

    edge_set: set[tuple[str, str]] = set()
    for p in paths:
        for u, v in zip(p.nodes, p.nodes[1:]):
            edge_set.add((u, v))
    edges = [{"from": u, "to": v} for u, v in sorted(edge_set)]

    return {"nodes": nodes, "edges": edges}


def generate_json_report(findings: list[Finding], paths: list[AttackPath]) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": [json.loads(f.model_dump_json()) for f in findings],
        "attack_paths": [json.loads(p.model_dump_json()) for p in paths],
        "summary": {
            "total_findings": len(findings),
            "critical_findings": sum(1 for f in findings if f.severity.value == "critical"),
            "total_attack_paths": len(paths),
            "highest_risk_path": paths[0].total_risk if paths else 0,
        },
    }


def generate_html_report(findings: list[Finding], paths: list[AttackPath]) -> str:
    return _HTML_TEMPLATE.render(
        generated_at=datetime.now(timezone.utc).isoformat(),
        findings=findings,
        paths=paths,
        graph_json=json.dumps(_paths_to_vis_graph(paths)),
    )


def write_reports(findings: list[Finding], paths: list[AttackPath], out_dir: str | Path) -> tuple[Path, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "nexus_report.json"
    html_path = out_dir / "nexus_report.html"
    json_path.write_text(json.dumps(generate_json_report(findings, paths), indent=2))
    html_path.write_text(generate_html_report(findings, paths))
    return json_path, html_path
