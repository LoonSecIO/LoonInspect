from datetime import UTC, datetime, timedelta

from app.core.scheduling import Schedule, latest_due, next_due, validate_schedule
from app.mdm.recent_activity import activity_selector, classify

T = datetime(2026, 10, 1, 10, tzinfo=UTC)
SCOPE = {"selector": "department.id==1", "sections": ["operating_system"], "quarantine": []}
POLL = {**SCOPE, "start": T.isoformat(), "end": (T + timedelta(minutes=15)).isoformat(), "complete": True}


def test_recent_scope_includes_both_clocks_and_groups_the_saved_selector():
    for version, contact in [("11.30", "lastContactTime"), ("11.31", "lastContact")]:
        query = activity_selector(POLL, version)
        assert query.startswith("(department.id==1);(")
        assert f"general.{contact}>=" in query and "general.reportDate<=" in query


def test_coverage_fixture():
    reported = T + timedelta(minutes=7)
    assert classify(reported, "operating_system", SCOPE, [POLL]) == ("coveredMiss", POLL)
    assert classify(reported, "hardware", SCOPE, [POLL])[0] == "incomparableScope"
    assert classify(reported, "operating_system", SCOPE, [{**POLL, "complete": False}])[0] == "failedWindow"
    assert classify(T + timedelta(minutes=16), "operating_system", SCOPE, [POLL])[0] == "afterLastWindow"
    assert classify(T - timedelta(minutes=1), "operating_system", SCOPE, [POLL])[0] == "uncovered"


def test_catchup_uses_last_quarter_hour():
    schedule = Schedule("quarter_hourly", "UTC")
    validate_schedule("recent_activity", schedule)
    now = T + timedelta(days=4, minutes=47)
    assert latest_due(schedule, T, now) == now - timedelta(minutes=2)
    assert next_due(schedule, now) == now + timedelta(minutes=13)
