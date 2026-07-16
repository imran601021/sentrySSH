from models import EventType
from parser import parse_entry
from tailer import JournalctlSource
from detectors import DetectionEngine
from storage import init_db, save_incident
from alerter import send_telegram_alert
import os


def run():
    source = JournalctlSource(
        unit=os.environ.get("SSH_IDS_UNIT", "sshd")
    )  # change to "ssh" if that's your unit
    engine = DetectionEngine(threshold=3, window_seconds=120)
    init_db()

    print("SSH-IDS | layers 1-4 | watching live sshd journal (Ctrl+C to stop)\n")

    try:
        for raw_entry in source.stream():
            event = parse_entry(raw_entry)
            if event.type == EventType.UNKNOWN:
                continue

            print(event)

            incident = engine.process(event)
            if incident:
                print(incident)
                save_incident(incident)
                send_telegram_alert(incident)

    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    run()
