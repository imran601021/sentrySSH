import json 
import subprocess
from abc import ABC,abstractmethod
from collections.abc import Iterator


class LogSource(ABC):
    @abstractmethod
    def stream(self) -> Iterator[dict]:
        ...

class JournalctlSource(LogSource):
    def __init__(self,unit:str = "sshd"):
        self.unit = unit

    def stream(self) -> Iterator[dict]:
        cmd = ["journalctl", "-f", "-o", "json", "-u", self.unit, "-n", "0"]
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        try:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
        finally:
            process.terminate()


if __name__ == '__main__':
    source = JournalctlSource(unit="sshd")
    print("Watching sshd journal... (CTRL+C to stop)" )
    for entry in source.stream():
        print(entry.get("MESSAGE","<no message field>"))
