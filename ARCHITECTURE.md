# NEXUS Architecture

## Pipeline overview

```
raw logs (auth/cloud/generic JSON)
        │
        ▼
  nexus.ingest.parsers          -- normalizes into LogEvent
        │
        ▼
  nexus.detection.anomaly       -- rule-based detectors -> Finding[]
        │
        ▼
topology JSON (assets + edges)
        │
        ▼
  nexus.graph.engine            -- builds directed graph (networkx)
        │
        ▼
  nexus.graph.ranking           -- finds & scores paths to critical assets
        │
        ▼
  nexus.report.generator        -- JSON + HTML report
```

The CLI (`nexus.cli`) and API (`nexus.api.main`) are thin wrappers around
this pipeline — all real logic lives in the library modules and is tested
independently of either interface.

## Data model (`nexus/models.py`)

- **LogEvent** — normalized representation of any log line, regardless of
  source format. `source`, `timestamp`, `user`, `host`, `action` are the
  fields detectors key off of.
- **Finding** — output of a detector: severity, human-readable rationale,
  a risk score, and the `related_event_ids` that triggered it (full
  traceability — no finding without evidence).
- **Asset / GraphEdge** — the attack graph's nodes and directed edges.
  `criticality` (0-10) marks how valuable an asset is; edge `weight` marks
  how hard it is to traverse (lower = easier).
- **AttackPath** — a scored path from an entry point to a critical asset,
  with a human-readable `rationale`.

## Detection design

Detectors in `nexus/detection/anomaly.py` are pure functions:
`list[LogEvent] -> list[Finding]`. This is deliberate:

- **Explainable by construction.** Every finding cites the exact events and
  rule that produced it — no black box.
- **Independently testable.** Each detector has its own unit tests against
  fixture data with a known, hand-verified expected outcome.
- **Easy to extend.** Adding a detector means writing one function and
  registering it in the `DETECTORS` tuple. A statistical or ML-based
  detector can be dropped in as long as it returns `Finding` objects — the
  rest of the pipeline doesn't care how a finding was produced.

Risk scoring (`nexus/detection/scoring.py`) uses fixed severity weights and
a diminishing-returns combination function, so scores are comparable across
detectors and across the attack graph. This mirrors MIRAGE's transparent
weighted risk engine so TrustGeeks tools share a consistent notion of "risk."

## Attack graph design

`nexus/graph/engine.py` builds a `networkx.DiGraph` from a topology
definition. `nexus/graph/ranking.py` enumerates simple paths (bounded by
`max_path_length`, capped per-target by `max_paths_per_target` to keep
enumeration tractable on larger graphs) from each entry point to every asset
at or above a criticality threshold, and scores each path by combining edge
traversal difficulty with target criticality.

This is intentionally a clear, auditable graph algorithm (not ML) for v0.1.
A future version could add: probabilistic edge weights informed by
detection findings (an edge becomes "easier" if a Finding shows credential
reuse across it), and a proper geo-velocity model for `impossible_travel`.

## Known limitations (v0.1, documented intentionally)

- `impossible_travel` uses country-change-within-a-window as a
  simplification, not real geo-distance/plausible-speed calculation.
- Path enumeration is exponential in theory; the `max_path_length` and
  `max_paths_per_target` caps bound this for real-world topologies but very
  dense graphs (thousands of edges) will need a smarter algorithm
  (e.g. k-shortest-paths via Yen's algorithm) rather than `all_simple_paths`.
- No persistence layer yet — this is a pipeline/library + CLI/API, not a
  standing service with a database. That's a natural v0.2 addition
  (PostgreSQL for findings history, scheduled ingestion).

## v0.2 additions

**MITRE ATT&CK mapping** (`nexus/intel/mitre.py`) — a static, hand-maintained
`rule -> [AttackTechnique]` table. Every `Finding` gets `attack_techniques`
populated automatically in `_new_finding()`. A new detector without a table
entry still produces valid findings (empty list, not an error) — extend the
table when you add the detector.

**Composite risk scoring** (`nexus/detection/scoring.composite_risk_score`)
— combines severity, optional CVSS, optional business criticality, and
optional path length into one 0-10 score via a fixed weighted average.
Weights are explicit constants (`COMPOSITE_WEIGHTS`), not learned, and
missing components simply drop out of the average rather than being
guessed. The attack-path ranking in `graph/ranking.py` uses the same idea
(CVSS-on-target as an optional bonus) directly in `_path_risk`.

**IOC / threat-intel enrichment** (`nexus/intel/ioc.py`) — `IOCEnricher` is
a `Protocol` (one method: `lookup`). `StaticReputationEnricher` is the
shipped reference implementation, backed by a local JSON file. To use a
live feed (AbuseIPDB, VirusTotal, GreyNoise, ...), implement `IOCEnricher`
around your own HTTP client and API key and pass it into `enrich_events` /
`enrich_findings` instead. NEXUS does not ship live external calls by
default — that's a deliberate choice, not a gap: a security tool shouldn't
silently depend on network calls to third parties without the deployer
choosing that.

**Streaming ingestion** (`nexus/streaming/`) — `StreamConsumer` (abstract
base, `base.py`) defines `poll()` / `run_forever()`. `RedisStreamConsumer`
(`redis_stream.py`) is the shipped implementation, using consumer groups
(`XREADGROUP`/`XACK`) so multiple workers can share a stream safely. Tested
against `fakeredis` — no live broker required to run the test suite. A
malformed message on the stream is skipped (and acked, so it doesn't block
the group) rather than crashing the consumer; routing skipped messages to a
dead-letter stream is a known gap, not yet built. Kafka/RabbitMQ backends
would implement the same `StreamConsumer` interface.

**LLM investigation summaries** (`nexus/llm/investigate.py`) — a real
integration with the Anthropic API (`anthropic` SDK), not a template
string. `build_investigation_prompt()` is a pure function (no network call)
that assembles only facts already present on the `Finding`/`AttackPath` —
the system prompt explicitly instructs the model not to invent details.
`LLMInvestigator` takes an injectable client so the whole flow is
unit-tested with a fake client (see `tests/test_llm.py`) without hitting
the network or requiring a real key. Requires `ANTHROPIC_API_KEY` at
runtime for real use; fails loudly (`RuntimeError`) rather than returning a
fabricated summary if no key/client is available. The CLI catches that
error and skips summarization with a warning instead of aborting the run.

## Extending NEXUS

To add a new detector:
1. Write a function `detect_x(events: list[LogEvent]) -> list[Finding]` in
   `nexus/detection/anomaly.py`.
2. Add it to the `DETECTORS` tuple.
3. Add unit tests in `tests/test_anomaly.py` with fixture data that
   deterministically triggers (and doesn't trigger) the rule.

To add a new log source:
1. Write a `parse_x(record: dict) -> LogEvent` function in
   `nexus/ingest/parsers.py`.
2. Register it in `_PARSERS`.
3. Add fixture-based tests in `tests/test_ingest.py`.
