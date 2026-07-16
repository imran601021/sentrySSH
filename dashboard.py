from flask import Flask, jsonify, render_template
# ⬇️ ADD these new imports right here
from functools import wraps
from flask import request, Response
import os

from storage import get_recent_incidents

# ⬇️ ADD these two lines + the require_auth function here, before app.run()
DASHBOARD_USER = os.environ.get("SSH_IDS_DASHBOARD_USER", "admin")
DASHBOARD_PASS = os.environ.get("SSH_IDS_DASHBOARD_PASS")


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != DASHBOARD_USER or auth.password != DASHBOARD_PASS:
            return Response(
                "Login required", 401,
                {"WWW-Authenticate": 'Basic realm="SSH-IDS Dashboard"'}
            )
        return f(*args, **kwargs)
    return decorated


app = Flask(__name__)


@app.route("/")
@require_auth          # ⬅️ ADD this line above the existing route
def index():
    return render_template("index.html")


@app.route("/api/incidents")
@require_auth          # ⬅️ ADD this line above the existing route
def api_incidents():
    incidents = get_recent_incidents(limit=50)
    return jsonify(incidents)


if __name__ == "__main__":
  app.run(host="127.0.0.1", port=5000)