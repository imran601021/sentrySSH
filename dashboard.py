from flask import Flask, jsonify, render_template
from functools import wraps
from flask import request, Response
import os
from storage import get_recent_incidents

DASHBOARD_USER = os.environ.get("SSH_IDS_DASHBOARD_USER", "admin")
DASHBOARD_PASS = os.environ.get("SSH_IDS_DASHBOARD_PASS")

from collections import defaultdict
from time import time

_failed_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
BLOCK_WINDOW_SECONDS = 300  # 5 minutes


def is_rate_limited(ip: str) -> bool:
    now = time()
    _failed_attempts[ip] = [
        t for t in _failed_attempts[ip] if now - t < BLOCK_WINDOW_SECONDS
    ]
    return len(_failed_attempts[ip]) >= MAX_ATTEMPTS


def record_failed_attempt(ip: str) -> None:
    _failed_attempts[ip].append(time())


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.remote_addr
        if is_rate_limited(client_ip):
            return Response("Too many failed attempts. Try again later.", 429)

        auth = request.authorization
        if (
            not auth
            or auth.username != DASHBOARD_USER
            or auth.password != DASHBOARD_PASS
        ):
            record_failed_attempt(client_ip)
            return Response(
                "Login required",
                401,
                {"WWW-Authenticate": 'Basic realm="SSH-IDS Dashboard"'},
            )
        return f(*args, **kwargs)

    return decorated


app = Flask(__name__)


@app.route("/")
@require_auth
def index():
    return render_template("index.html")


@app.route("/api/incidents")
@require_auth
def api_incidents():
    incidents = get_recent_incidents(limit=50)
    return jsonify(incidents)


@app.route("/health")
def health():
    return {"status": "ok"}, 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
