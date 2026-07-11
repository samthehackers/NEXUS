"""Parsers that normalize raw log formats into nexus.models.LogEvent.

Supported formats today:
  - auth   : generic authentication/login logs
  - cloud  : CloudTrail-style cloud API call logs
  - generic: already-normalized JSON events

Design note: each parser is intentionally forgiving about missing fields
(logs in the real world are messy) but always produces a valid LogEvent,
raising a clear ValueError if the record is unusable.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from dateutil import parser as dateparser

from nexus.models import EventSource, LogEvent


def _require(record: dict[str, Any], *keys: str) -> None:
    missing = [k for k in keys if k not in record]
    if missing:
        raise ValueError(f"log record missing required field(s): {missing} -> {record}")


def parse_auth_log(record: dict[str, Any]) -> LogEvent:
    _require(record, "user", "timestamp", "action")
    return LogEvent(
        event_id=str(record.get("event_id", uuid.uuid4())),
        source=EventSource.AUTH,
        timestamp=dateparser.parse(str(record["timestamp"])),
        user=record.get("user"),
        host=record.get("host"),
        source_ip=record.get("source_ip"),
        country=record.get("country"),
        action=record["action"],
        resource=record.get("resource"),
        success=bool(record.get("success", True)),
        raw=record,
    )


def parse_cloud_log(record: dict[str, Any]) -> LogEvent:
    _require(record, "eventTime", "eventName")
    identity = record.get("userIdentity", {}) or {}
    return LogEvent(
        event_id=str(record.get("eventID", uuid.uuid4())),
        source=EventSource.CLOUD,
        timestamp=dateparser.parse(str(record["eventTime"])),
        user=identity.get("userName") or identity.get("arn"),
        host=record.get("sourceIPAddress"),
        source_ip=record.get("sourceIPAddress"),
        country=record.get("awsRegion"),
        action=record["eventName"],
        resource=(record.get("requestParameters") or {}).get("bucketName")
        or (record.get("requestParameters") or {}).get("resourceName"),
        success=record.get("errorCode") is None,
        raw=record,
    )


def parse_generic_log(record: dict[str, Any]) -> LogEvent:
    _require(record, "timestamp", "action")
    return LogEvent(
        event_id=str(record.get("event_id", uuid.uuid4())),
        source=EventSource.GENERIC,
        timestamp=dateparser.parse(str(record["timestamp"])),
        user=record.get("user"),
        host=record.get("host"),
        source_ip=record.get("source_ip"),
        country=record.get("country"),
        action=record["action"],
        resource=record.get("resource"),
        success=bool(record.get("success", True)),
        raw=record,
    )


_PARSERS = {
    "auth": parse_auth_log,
    "cloud": parse_cloud_log,
    "generic": parse_generic_log,
}


def get_parser(log_type: str):
    """Return the parser function for a given log_type ('auth' | 'cloud' |
    'generic'). Raises ValueError for an unknown type. Used by streaming
    consumers that parse one record at a time rather than a whole file.
    """
    if log_type not in _PARSERS:
        raise ValueError(f"unknown log_type '{log_type}', expected one of {list(_PARSERS)}")
    return _PARSERS[log_type]


def load_events(path: str | Path, log_type: str) -> list[LogEvent]:
    """Load a JSON file containing a list of raw log records and normalize them.

    Raises ValueError for an unknown log_type, and re-raises parsing errors
    with the offending record index attached so bad data is easy to locate.
    """
    if log_type not in _PARSERS:
        raise ValueError(f"unknown log_type '{log_type}', expected one of {list(_PARSERS)}")

    parser_fn = _PARSERS[log_type]
    raw = json.loads(Path(path).read_text())
    if not isinstance(raw, list):
        raise ValueError(f"{path} must contain a JSON array of log records")

    events: list[LogEvent] = []
    for i, record in enumerate(raw):
        try:
            events.append(parser_fn(record))
        except Exception as exc:  # noqa: BLE001 - re-raise with context
            raise ValueError(f"failed to parse record {i} in {path}: {exc}") from exc
    return events
