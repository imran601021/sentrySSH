import re
from datetime import datetime

from models import Event, EventType

# IPv4 (203.0.113.5) and IPv6 (::1, 2001:db8::1) both use this shape
_IP = r"(?P<ip>[0-9a-fA-F:.]+)"

_PATTERNS: list[tuple[EventType, re.Pattern]] = [
    (
        EventType.FAILED_PASSWORD,
        re.compile(
            rf"Failed password for (invalid user )?(?P<user>\S+) "
            rf"from {_IP} port (?P<port>\d+)"
        ),
    ),
    (
        EventType.INVALID_USER,
        re.compile(
            rf"Invalid user (?P<user>\S+) from {_IP} port (?P<port>\d+)"
        ),
    ),
    (
        EventType.ACCEPTED_PASSWORD,
        re.compile(
            rf"Accepted password for (?P<user>\S+) from {_IP} port (?P<port>\d+)"
        ),
    ),
    (
        EventType.ACCEPTED_PUBKEY,
        re.compile(
            rf"Accepted publickey for (?P<user>\S+) from {_IP} port (?P<port>\d+)"
        ),
    ),
    (
        EventType.CONNECTION_CLOSED,
        re.compile(
            rf"Connection closed by (?:invalid user (?P<user>\S+) )?{_IP} port (?P<port>\d+)"
        ),
    ),
]


def parse_entry(entry: dict) -> Event:
    message = entry.get("MESSAGE", "")

    ts_micros = entry.get("__REALTIME_TIMESTAMP")
    timestamp = (
        datetime.fromtimestamp(int(ts_micros) / 1_000_000)
        if ts_micros
        else datetime.now()
    )

    for event_type, pattern in _PATTERNS:
        match = pattern.search(message)
        if match:
            groups = match.groupdict()
            return Event(
                type=event_type,
                timestamp=timestamp,
                raw_msg=message,
                ip=groups.get("ip"),
                user=groups.get("user"),
                port=int(groups["port"]) if groups.get("port") else None,
            )

    return Event(type=EventType.UNKNOWN, timestamp=timestamp, raw_msg=message)


if __name__ == "__main__":
    # Real lines captured from your own terminal output — no journalctl needed to test this
    fake_lines = [
        "Connection closed by ::1 port 45272 [preauth]",
        "Invalid user baduser from ::1 port 40022",
        "Failed password for invalid user baduser from ::1 port 40022 ssh2",
        "Connection closed by 192.168.0.1 port 36334",
        "Connection closed by invalid user baduser ::1 port 40022 [preauth]",
        "Accepted password for imran from ::1 port 40022 ssh2",
        "pam_unix(sshd:auth): check pass; user unknown",  # should fall through to UNKNOWN
    ]
    for line in fake_lines:
        print(parse_entry({"MESSAGE": line}))