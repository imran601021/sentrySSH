from enum import Enum
from datetime import datetime
from dataclasses import dataclass


class EventType(str, Enum):
    FAILED_PASSWORD = "failed_password"
    INVALID_USER = "invalid_user"
    ACCEPTED_PASSWORD = "accepted_password"
    ACCEPTED_PUBKEY = "accepted_pubkey"
    CONNECTION_CLOSED = "connection_closed"
    SUDO_FAILURE = "sudo_failure"
    UNKNOWN = "unknown"


@dataclass
class Event:
    type: EventType
    timestamp: datetime
    raw_msg: str
    ip: str | None = None
    user: str | None = None
    port: int | None = None

    def __repr__(self) -> str:
        bits = [f"[{self.timestamp.strftime('%H:%M:%S')}]", self.type.value]
        if self.user:
            bits.append(f"user={self.user}")
        if self.ip:
            bits.append(f"ip={self.ip}")
        return " ".join(bits)