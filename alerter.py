import os
import requests

from models import Incident

TELEGRAM_TOKEN = os.environ.get("SSH_IDS_TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("SSH_IDS_TELEGRAM_CHAT_ID")


def send_telegram_alert(incident: Incident) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("Telegram credentials not set — skipping alert.")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    text = (
        f"🚨 SSH-IDS Alert\n"
        f"{incident.attempt_count} failed attempts from {incident.ip}\n"
        f"User tried: {incident.user}\n"
        f"Window: {incident.window_seconds}s"
    )

    try:
        response = requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=5)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Failed to send Telegram alert: {e}")


if __name__ == "__main__":
    from datetime import datetime

    fake = Incident(
        ip="203.0.113.5",
        user="admin",
        attempt_count=3,
        window_seconds=120,
        first_seen=datetime.now(),
        last_seen=datetime.now(),
    )
    send_telegram_alert(fake)
    print("Sent (check your Telegram).")