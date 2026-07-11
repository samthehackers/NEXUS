"""Redis Streams consumer for real-time log ingestion.

Redis Streams was chosen over Kafka/RabbitMQ for the reference
implementation because it needs no broker cluster to stand up -- a single
`redis-server` (or a hosted Redis) is enough, and it's fully testable
in-process with `fakeredis`. Kafka/RabbitMQ consumers can implement the
same `StreamConsumer` interface (see base.py) for production deployments
that already run those brokers.

Each stream entry is expected to be a JSON-encoded log record under the
field name given by `field_name` (default "data"). Consumer group semantics
(XREADGROUP + XACK) are used so multiple NEXUS workers can share a stream
without double-processing, and so a crashed worker's unacked messages can be
reclaimed.
"""

from __future__ import annotations

import json
from typing import Any

from nexus.ingest.parsers import get_parser
from nexus.models import LogEvent
from nexus.streaming.base import StreamConsumer


class RedisStreamConsumer(StreamConsumer):
    def __init__(
        self,
        redis_client: Any,
        stream_name: str,
        group_name: str,
        consumer_name: str,
        log_type: str = "generic",
        field_name: str = "data",
    ):
        """
        Args:
            redis_client: an instance satisfying the redis-py client
                interface (real `redis.Redis(...)` or a `fakeredis` instance
                for tests). Injected rather than constructed here so this
                class has no hard dependency on a live Redis connection.
            stream_name: the Redis stream key to read from.
            group_name / consumer_name: Redis consumer-group identifiers.
            log_type: which nexus.ingest parser to apply to each record.
            field_name: the field in each stream entry holding the JSON log record.
        """
        self._redis = redis_client
        self._stream = stream_name
        self._group = group_name
        self._consumer = consumer_name
        self._parser = get_parser(log_type)
        self._field_name = field_name
        self._ensure_group()

    def _ensure_group(self) -> None:
        try:
            self._redis.xgroup_create(self._stream, self._group, id="0", mkstream=True)
        except Exception as exc:  # noqa: BLE001
            # BUSYGROUP means the group already exists -- that's fine, anything
            # else is a real problem and should propagate.
            if "BUSYGROUP" not in str(exc):
                raise

    def poll(self, max_messages: int = 100) -> list[LogEvent]:
        response = self._redis.xreadgroup(
            groupname=self._group,
            consumername=self._consumer,
            streams={self._stream: ">"},
            count=max_messages,
        )
        if not response:
            return []

        events: list[LogEvent] = []
        ids_to_ack: list[str] = []
        for _stream_name, entries in response:
            for entry_id, fields in entries:
                ids_to_ack.append(entry_id)
                raw = fields.get(self._field_name) or fields.get(self._field_name.encode())
                if raw is None:
                    continue
                if isinstance(raw, bytes):
                    raw = raw.decode()
                try:
                    record = json.loads(raw)
                    events.append(self._parser(record))
                except (json.JSONDecodeError, ValueError):
                    # A malformed message shouldn't take down the consumer --
                    # skip it (still ack it below so it doesn't block the group)
                    # but this is a real gap noted in ARCHITECTURE.md: v0.2
                    # should route these to a dead-letter stream instead of
                    # silently dropping them.
                    continue

        if ids_to_ack:
            self._redis.xack(self._stream, self._group, *ids_to_ack)
        return events

    def publish(self, record: dict) -> str:
        """Convenience helper (mainly for tests/demos): publish one raw log
        record onto the stream in the expected format.
        """
        return self._redis.xadd(self._stream, {self._field_name: json.dumps(record)})
