import json

import fakeredis
import pytest

from nexus.streaming.redis_stream import RedisStreamConsumer


@pytest.fixture
def fake_redis():
    return fakeredis.FakeStrictRedis(decode_responses=False)


def test_consumer_ensures_group_created(fake_redis):
    RedisStreamConsumer(fake_redis, "logs", "nexus-group", "worker-1", log_type="auth")
    groups = fake_redis.xinfo_groups("logs")
    assert any(g["name"] == b"nexus-group" or g["name"] == "nexus-group" for g in groups)


def test_consumer_creating_group_twice_does_not_raise(fake_redis):
    RedisStreamConsumer(fake_redis, "logs", "nexus-group", "worker-1", log_type="auth")
    # second consumer joining same group/stream should not raise BUSYGROUP
    RedisStreamConsumer(fake_redis, "logs", "nexus-group", "worker-2", log_type="auth")


def test_publish_and_poll_round_trip(fake_redis):
    consumer = RedisStreamConsumer(fake_redis, "logs", "nexus-group", "worker-1", log_type="auth")
    record = {"user": "alice", "timestamp": "2026-07-09T10:00:00Z", "action": "login", "country": "NG"}
    consumer.publish(record)

    events = consumer.poll()
    assert len(events) == 1
    assert events[0].user == "alice"
    assert events[0].action == "login"


def test_poll_with_no_messages_returns_empty_list(fake_redis):
    consumer = RedisStreamConsumer(fake_redis, "empty-stream", "nexus-group", "worker-1", log_type="auth")
    assert consumer.poll() == []


def test_malformed_message_is_skipped_not_raised(fake_redis):
    consumer = RedisStreamConsumer(fake_redis, "logs", "nexus-group", "worker-1", log_type="auth")
    fake_redis.xadd("logs", {"data": "not-valid-json"})
    events = consumer.poll()
    assert events == []  # skipped, no crash


def test_run_forever_respects_max_iterations(fake_redis):
    consumer = RedisStreamConsumer(fake_redis, "logs", "nexus-group", "worker-1", log_type="auth")
    record = {"user": "bob", "timestamp": "2026-07-09T10:00:00Z", "action": "login"}
    consumer.publish(record)

    seen = []
    consumer.run_forever(lambda events: seen.extend(events), poll_interval_seconds=0, max_iterations=2)
    assert len(seen) == 1
    assert seen[0].user == "bob"
