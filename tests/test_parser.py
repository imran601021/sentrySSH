import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parser import parse_entry
from models import EventType


def test_failed_password_invalid_user():
    entry = {"MESSAGE": "Failed password for invalid user baduser from ::1 port 40022 ssh2"}
    event = parse_entry(entry)
    assert event.type == EventType.FAILED_PASSWORD
    assert event.user == "baduser"
    assert event.ip == "::1"
    assert event.port == 40022


def test_invalid_user():
    entry = {"MESSAGE": "Invalid user test from 203.0.113.5 port 51234"}
    event = parse_entry(entry)
    assert event.type == EventType.INVALID_USER
    assert event.user == "test"
    assert event.ip == "203.0.113.5"


def test_accepted_password():
    entry = {"MESSAGE": "Accepted password for imran from ::1 port 40022 ssh2"}
    event = parse_entry(entry)
    assert event.type == EventType.ACCEPTED_PASSWORD
    assert event.user == "imran"


def test_connection_closed_plain():
    entry = {"MESSAGE": "Connection closed by ::1 port 45272 [preauth]"}
    event = parse_entry(entry)
    assert event.type == EventType.CONNECTION_CLOSED
    assert event.ip == "::1"


def test_connection_closed_invalid_user_variant():
    entry = {"MESSAGE": "Connection closed by invalid user baduser ::1 port 40022 [preauth]"}
    event = parse_entry(entry)
    assert event.type == EventType.CONNECTION_CLOSED
    assert event.user == "baduser"


def test_unrelated_pam_noise_falls_through():
    entry = {"MESSAGE": "pam_unix(sshd:auth): check pass; user unknown"}
    event = parse_entry(entry)
    assert event.type == EventType.UNKNOWN
