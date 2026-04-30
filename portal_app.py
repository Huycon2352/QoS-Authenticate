import json
import os
import time
import uuid
from flask import Flask, request, render_template_string

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SESSION_FILE = os.path.join(BASE_DIR, "sessions.json")
SESSION_TTL_SECONDS = 60

app = Flask(__name__)

PAGE = """
<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SDN Authentication Portal</title>
</head>
<body>
  <h1>SDN Authentication Portal</h1>
  <p>Client IP: <strong>{{ client_ip }}</strong></p>
  {% if message %}
    <p style="color: green;">{{ message }}</p>
  {% endif %}
  {% if error %}
    <p style="color: red;">{{ error }}</p>
  {% endif %}
  <form method="post" action="/authenticate">
    <label>User ID</label><br>
    <input name="user_id" value="user1"><br><br>

    <label>Role</label><br>
    <select name="role">
      <option value="max">max</option>
      <option value="normal" selected>normal</option>
      <option value="least">least</option>
    </select><br><br>

    <button type="submit">Authenticate</button>
  </form>
  <p>Session TTL: {{ ttl }} seconds</p>
</body>
</html>
"""


def load_sessions():
    try:
        with open(SESSION_FILE, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except Exception:
        return {}

    sessions = data.get("sessions", {})
    if not isinstance(sessions, dict):
        return {}

    now = time.time()
    cleaned = {}
    for session_id, meta in sessions.items():
        try:
            expires_at = float(meta.get("expires_at", 0))
            if now < expires_at:
                cleaned[session_id] = meta
        except (TypeError, ValueError, AttributeError):
            continue
    return cleaned


def save_sessions(sessions):
    tmp_path = SESSION_FILE + ".tmp"
    payload = {"sessions": sessions}
    with open(tmp_path, "w") as f:
        json.dump(payload, f, indent=4)
    os.replace(tmp_path, SESSION_FILE)


def detect_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        candidate = forwarded_for.split(",")[0].strip()
        if candidate:
            return candidate
    return request.remote_addr or ""


@app.route("/", methods=["GET"])
def index():
    return render_template_string(
        PAGE,
        client_ip=detect_client_ip(),
        message=None,
        error=None,
        ttl=SESSION_TTL_SECONDS,
    )


@app.route("/authenticate", methods=["POST"])
def authenticate():
    sessions = load_sessions()
    user_id = (request.form.get("user_id") or "guest").strip()
    role = (request.form.get("role") or "least").strip()
    client_ip = detect_client_ip()
    session_id = str(uuid.uuid4())
    expires_at = time.time() + SESSION_TTL_SECONDS

    sessions[session_id] = {
        "user_id": user_id,
        "role": role,
        "expires_at": expires_at,
        "client_ip": client_ip,
    }
    save_sessions(sessions)

    message = f"Authenticated: {user_id} ({role}), session={session_id}"
    return render_template_string(
        PAGE,
        client_ip=client_ip,
        message=message,
        error=None,
        ttl=SESSION_TTL_SECONDS,
    )


@app.route("/sessions", methods=["GET"])
def sessions_view():
    return {
        "sessions": load_sessions(),
        "count": len(load_sessions()),
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
