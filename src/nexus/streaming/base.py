"""Base interface for streaming log ingestion backends.

NEXUS v0.2 ships a Redis Streams implementation (simplest to run and test
without standing up a broker). Kafka and RabbitMQ backends can implement
this same interface -- the detection pipeline downstream doesn't care which
backend produced the events.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

from nexus.models import LogEvent


class StreamConsumer(ABC):
    """A consumer that reads raw log records from a stream, normalizes them,
    and hands them to a callback for detection.
    """

    @abstractmethod
    def poll(self, max_messages: int = 100) -> list[LogEvent]:
        """Fetch and normalize up to `max_messages` pending events.

        Returns an empty list if none are available -- callers should poll
        in a loop, not treat an empty result as an error.
        """
        raise NotImplementedError

    def run_forever(self, on_events: Callable[[list[LogEvent]], None],
                     poll_interval_seconds: float = 1.0, max_iterations: int | None = None) -> None:
        """Convenience loop: poll, hand events to a callback, sleep, repeat.

        `max_iterations` is provided purely so this loop is testable without
        actually running forever -- production callers omit it.
        """
        import time

        iterations = 0
        while max_iterations is None or iterations < max_iterations:
            events = self.poll()
            if events:
                on_events(events)
            iterations += 1
            if max_iterations is None or iterations < max_iterations:
                time.sleep(poll_interval_seconds)
