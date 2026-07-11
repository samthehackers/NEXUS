# NEXUS

**AI-powered behavioral detection & attack path engine — TrustGeeks Security**

NEXUS answers the question a SOC analyst actually needs answered: not just
*"is this alert weird?"* but *"if I ignore this, what can the attacker
reach?"*

It ingests security logs (auth, cloud, generic), runs explainable behavioral
detectors against them, and maps every flagged user/host onto a live attack
graph to compute ranked paths to your most critical assets. It's part of the
TrustGeeks open-source suite alongside [SENTINEL](#) (purple team platform),
[TrustMap](#) (recon orchestrator), and [MIRAGE](#) (phishing/social
engineering detection).

## Why

Most SOC tooling produces alert fatigue: thousands of findings, no sense of
priority. NEXUS closes the loop between *detection* and *impact* by scoring
every finding against how close it puts an attacker to a critical asset —
using transparent, explainable heuristics rather than a black box.

## Features

- **Log ingestion**: normalizes auth logs, CloudTrail-style cloud logs, and
  generic JSON events into one event model.
- **Behavioral detection**: impossible travel, off-hours privileged access,
  mass resource access, privilege escalation chains — each rule is a
  readable function you can audit and extend.
- **MITRE ATT&CK mapping**: every finding is tagged with the ATT&CK
  technique(s) it maps to, from an explicit, hand-maintained table
  (`nexus/intel/mitre.py`) — not an inferred/ML mapping.
- **Composite risk scoring**: combines severity with optional CVSS
  (from your own vuln scanner), business criticality, and attack-path
  length into one 0-10 score with visible, fixed weights.
- **Attack graph engine**: builds a directed graph of hosts/users/resources
  and computes ranked attack paths to critical assets using weighted
  traversal difficulty.
- **Interactive graph visualization**: the HTML report renders the actual
  attack graph (vis-network) — entry points, hops, and critical targets
  color-coded — not just a path list.
- **Threat-intel / IOC enrichment**: pluggable interface
  (`nexus/intel/ioc.py`) with a reference static-reputation-list
  implementation. Bring your own live feed (AbuseIPDB, VirusTotal, etc.) by
  implementing the same interface with your API key.
- **Streaming ingestion**: a tested Redis Streams consumer
  (`nexus/streaming/`) for real-time log ingestion via consumer groups.
  Kafka/RabbitMQ backends can implement the same `StreamConsumer` interface.
- **LLM investigation summaries**: turns a raw finding + its attack-path
  context into an analyst-readable narrative via the Anthropic API
  (`nexus/llm/investigate.py`). Requires your own `ANTHROPIC_API_KEY` —
  NEXUS never fabricates a summary without one.
- **Reporting**: JSON (machine-readable) and HTML (human-readable, with
  the interactive graph) reports.
- **CLI** (Typer) and a minimal **REST API** (FastAPI) for automation.

## Installation

```bash
git clone https://github.com/samthehackers/NEXUS.git
cd nexus
pip install -e ".[dev]"
```

## Quick start

```bash
# Detect anomalies in an auth log
nexus detect --logs src/nexus/data/sample_auth_logs.json --log-type auth

# Rank attack paths from an entry point to critical assets
nexus graph --topology src/nexus/data/sample_topology.json --entry-point workstation-12

# Full pipeline: detect + map onto attack graph + report
nexus run \
  --logs src/nexus/data/sample_auth_logs.json --log-type auth \
  --topology src/nexus/data/sample_topology.json \
  --entry-point workstation-12 \
  --out ./nexus-report

# Same, with IOC enrichment and LLM investigation summaries
nexus run \
  --logs src/nexus/data/sample_auth_logs.json --log-type auth \
  --topology src/nexus/data/sample_topology.json \
  --entry-point workstation-12 \
  --ioc-feed src/nexus/data/sample_ioc_feed.json \
  --llm-summary \
  --out ./nexus-report
```

`--llm-summary` requires `ANTHROPIC_API_KEY` in your environment. Without
it, NEXUS skips summarization with a warning rather than fabricating one.

Open `nexus-report/nexus_report.html` for the human-readable report,
complete with an interactive attack graph.

### As an API

```bash
uvicorn nexus.api.main:app --reload
# POST /analyze/logs   { "log_type": "auth", "events": [...] }
# POST /analyze/graph  { "assets": [...], "edges": [...], "entry_points": [...] }
```

## Input formats

See [`src/nexus/data/sample_auth_logs.json`](src/nexus/data/sample_auth_logs.json)
and [`src/nexus/data/sample_topology.json`](src/nexus/data/sample_topology.json)
for concrete examples. Full field definitions are in
[`ARCHITECTURE.md`](ARCHITECTURE.md).

## Detectors included in v0.1

| Rule | What it catches |
|---|---|
| `impossible_travel` | Same user authenticating from two countries too fast to be physical travel |
| `off_hours_privileged_access` | Privileged/admin actions outside business hours |
| `mass_resource_access` | A user touching an unusually large number of resources in a short window (staging/exfil signature) |
| `privilege_escalation_chain` | Sequential escalation-type actions (policy grants, role assumption, group changes) |

These are heuristic, not ML-based — every finding tells you exactly which
rule and events triggered it. See `ARCHITECTURE.md` for how to add new
detectors or swap in a statistical/ML model behind the same interface.

## Roadmap

Delivered in v0.2: MITRE ATT&CK mapping, composite risk scoring (CVSS +
business criticality + path length), interactive attack-graph
visualization, pluggable IOC/threat-intel enrichment, a Redis Streams
ingestion path, and LLM-powered investigation summaries.

Still open: real geo-IP velocity for `impossible_travel` (currently a
country-change heuristic), a Kafka/RabbitMQ `StreamConsumer` implementation
for teams already running those brokers, and a live threat-intel connector
(AbuseIPDB/VirusTotal) for anyone who wants enrichment beyond a static
reputation list. Contributions welcome — see `CONTRIBUTING.md`.

## License

MIT — see `LICENSE`.
