"""
Tests for detector.py — confirms the sliding-window, per-IP threshold
logic correctly raises incidents when it should, and doesn't when it
shouldn't.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime, timedelta

from detectors import DetectionEngine
from models import Event, EventType


def make_event(ip: str, user: str, seconds_offset: int) -> Event:
    """Helper: builds a fake FAILED_PASSWORD event at a controlled time offset."""
    base_time = datetime(2026, 1, 1, 12, 0, 0)
    return Event(
        type=EventType.FAILED_PASSWORD,
        timestamp=base_time + timedelta(seconds=seconds_offset),
        raw_msg="test",
        ip=ip,
        user=user,
    )


def test_no_incident_below_threshold():
    engine = DetectionEngine(threshold=3, window_seconds=120)
    engine.process(make_event("1.1.1.1", "admin", 0))
    result = engine.process(make_event("1.1.1.1", "admin", 5))
    assert result is None  # only 2 attempts so far, threshold is 3


def test_incident_fires_at_threshold():
    engine = DetectionEngine(threshold=3, window_seconds=120)
    engine.process(make_event("1.1.1.1", "admin", 0))
    engine.process(make_event("1.1.1.1", "admin", 5))
    result = engine.process(make_event("1.1.1.1", "admin", 10))
    assert result is not None
    assert result.attempt_count == 3
    assert result.ip == "1.1.1.1"


def test_attempts_outside_window_dont_count():
    engine = DetectionEngine(threshold=3, window_seconds=120)
    engine.process(make_event("1.1.1.1", "admin", 0))
    engine.process(make_event("1.1.1.1", "admin", 5))
    # this 3rd attempt happens 200s later — outside the 120s window,
    # so the first two should have "expired" and NOT count anymore
    result = engine.process(make_event("1.1.1.1", "admin", 200))
    assert result is None


def test_different_ips_tracked_separately():
    engine = DetectionEngine(threshold=3, window_seconds=120)
    engine.process(make_event("1.1.1.1", "admin", 0))
    engine.process(make_event("2.2.2.2", "admin", 1))
    engine.process(make_event("1.1.1.1", "admin", 2))
    result = engine.process(make_event("2.2.2.2", "admin", 3))
    # 2.2.2.2 only has 2 attempts total — 1.1.1.1's attempts shouldn't count toward it
    assert result is None


def test_non_failed_password_events_ignored():
    engine = DetectionEngine(threshold=3, window_seconds=120)
    accepted_event = Event(
        type=EventType.ACCEPTED_PASSWORD,
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        raw_msg="test",
        ip="1.1.1.1",
        user="admin",
    )
    result = engine.process(accepted_event)
    assert result is None  # only FAILED_PASSWORD events should ever trigger detection