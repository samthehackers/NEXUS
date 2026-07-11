"""Threat-intelligence / IOC enrichment.

NEXUS ships one reference enricher backed by a static, user-supplied
reputation list (JSON file of known-bad IPs/domains/hashes). It does
**not** ship with live calls to any commercial feed (AbuseIPDB, VirusTotal,
GreyNoise, etc.) baked in -- those require an API key and rate-limited
network calls that belong to the deployer, not to this library.

To use a live feed: implement `IOCEnricher` (one method: `enrich`), wire in
your HTTP client and API key, and pass your enricher into `enrich_events` /
`enrich_findings` instead of `StaticReputationEnricher`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from nexus.models import Finding, IOCMatch, LogEvent


class IOCEnricher(Protocol):
    """Interface any threat-intel backend must implement."""

    def lookup(self, indicator: str, indicator_type: str) -> IOCMatch | None:
        """Return an IOCMatch if the indicator is known-bad, else None."""
        ...


class StaticReputationEnricher:
    """Reference implementation backed by a local JSON reputation list.

    Reputation file format:
    {
      "ips": {"1.2.3.4": {"reputation": "malicious", "description": "..."}},
      "domains": {"evil.example.com": {"reputation": "suspicious"}},
      "hashes": {}
    }

    This is intentionally simple and offline -- suitable for a curated
    internal blocklist or a periodically-exported feed, not a live lookup.
    """

    def __init__(self, reputation_data: dict | None = None):
        self._data = reputation_data or {"ips": {}, "domains": {}, "hashes": {}}

    @classmethod
    def from_file(cls, path: str | Path) -> "StaticReputationEnricher":
        data = json.loads(Path(path).read_text())
        return cls(data)

    def lookup(self, indicator: str, indicator_type: str) -> IOCMatch | None:
        bucket_key = {"ip": "ips", "domain": "domains", "hash": "hashes"}.get(indicator_type)
        if bucket_key is None:
            return None
        bucket = self._data.get(bucket_key, {})
        entry = bucket.get(indicator)
        if entry is None:
            return None
        return IOCMatch(
            indicator=indicator,
            indicator_type=indicator_type,
            source="static_reputation_list",
            reputation=entry.get("reputation", "unknown"),
            description=entry.get("description"),
        )


def enrich_events(events: list[LogEvent], enricher: IOCEnricher) -> dict[str, list[IOCMatch]]:
    """Look up every source_ip present in a batch of events.

    Returns a mapping of event_id -> IOC matches found for that event (empty
    list if none). Only IPs are checked here since that's the field LogEvent
    reliably carries; domain/hash enrichment applies at the Finding level
    once a detector surfaces one (see enrich_findings).
    """
    results: dict[str, list[IOCMatch]] = {}
    for event in events:
        matches: list[IOCMatch] = []
        if event.source_ip:
            match = enricher.lookup(event.source_ip, "ip")
            if match:
                matches.append(match)
        results[event.event_id] = matches
    return results


def enrich_findings(
    findings: list[Finding], event_ioc_matches: dict[str, list[IOCMatch]]
) -> list[Finding]:
    """Attach IOC matches to findings based on their related event IDs.

    Returns new Finding objects (does not mutate in place) with
    `ioc_matches` populated from any related event that had a hit.
    """
    enriched: list[Finding] = []
    for finding in findings:
        matches: list[IOCMatch] = []
        for event_id in finding.related_event_ids:
            matches.extend(event_ioc_matches.get(event_id, []))
        enriched.append(finding.model_copy(update={"ioc_matches": matches}))
    return enriched
