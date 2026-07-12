from collections import defaultdict
from datetime import datetime, timedelta

from models import Event, EventType, Incident


class DetectionEngine:
    def __init__(self, threshold: int = 3, window_seconds: int = 120):
        self.threshold = threshold
        self.window_seconds = window_seconds
        # ip -> list of (timestamp, user) for each failed attempt
        self._attempts: dict[str, list[tuple[datetime, str | None]]] = defaultdict(list)

    def process(self, event: Event) -> Incident | None:
        if event.type != EventType.FAILED_PASSWORD or not event.ip:
            return None  # only failed_password events count toward brute-force detection

        now = event.timestamp
        window_start = now - timedelta(seconds=self.window_seconds)

        # record this attempt
        self._attempts[event.ip].append((now, event.user))

        # drop anything outside the window — this is what makes it "sliding"
        self._attempts[event.ip] = [
            (ts, user) for (ts, user) in self._attempts[event.ip] if ts >= window_start
        ]

        recent = self._attempts[event.ip]
        if len(recent) >= self.threshold:
            incident = Incident(
                ip=event.ip,
                user=event.user,
                attempt_count=len(recent),
                window_seconds=self.window_seconds,
                first_seen=recent[0][0],
                last_seen=recent[-1][0],
            )
            self._attempts[event.ip] = []  # reset after raising, avoid re-firing every single attempt after
            return incident

        return None 