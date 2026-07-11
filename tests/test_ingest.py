import json

import pytest

from nexus.ingest.parsers import load_events, parse_auth_log, parse_cloud_log


def test_parse_auth_log_basic():
    record = {"user": "alice", "timestamp": "2026-07-09T10:00:00Z", "action": "login", "country": "NG"}
    event = parse_auth_log(record)
    assert event.user == "alice"
    assert event.action == "login"
    assert event.country == "NG"
    assert event.success is True


def test_parse_auth_log_missing_field_raises():
    with pytest.raises(ValueError):
        parse_auth_log({"user": "alice"})


def test_parse_cloud_log_basic():
    record = {
        "eventTime": "2026-07-09T10:00:00Z",
        "eventName": "PutBucketPolicy",
        "userIdentity": {"userName": "svc-ci"},
        "sourceIPAddress": "10.0.0.5",
        "awsRegion": "us-east-1",
    }
    event = parse_cloud_log(record)
    assert event.user == "svc-ci"
    assert event.action == "PutBucketPolicy"
    assert event.success is True


def test_load_events_from_file(tmp_path):
    records = [
        {"user": "bob", "timestamp": "2026-07-09T10:00:00Z", "action": "login"},
        {"user": "bob", "timestamp": "2026-07-09T10:05:00Z", "action": "logout"},
    ]
    path = tmp_path / "logs.json"
    path.write_text(json.dumps(records))
    events = load_events(path, "auth")
    assert len(events) == 2


def test_load_events_unknown_type(tmp_path):
    path = tmp_path / "logs.json"
    path.write_text("[]")
    with pytest.raises(ValueError):
        load_events(path, "not-a-real-type")


def test_load_events_bad_record_reports_index(tmp_path):
    path = tmp_path / "logs.json"
    path.write_text(json.dumps([{"user": "x", "timestamp": "2026-07-09T10:00:00Z", "action": "a"}, {"user": "y"}]))
    with pytest.raises(ValueError, match="record 1"):
        load_events(path, "auth")
