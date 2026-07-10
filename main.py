from models import EventType
from parser import parse_entry
from tailer import JournalctlSource

def run():
    source = JournalctlSource(unit="sshd")  # change to "ssh" if that's your unit
    print("SSH-IDS | layers 1-3 | watching live sshd journal (Ctrl+C to stop)\n")

    try:
        for raw_entry in source.stream():
            event = parse_entry(raw_entry)
            if event.type == EventType.UNKNOWN:
                continue
            print(event)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == '__main__':
    run()
