"""
Day 7 - Secure Analyst Authentication & Threat Access Control
----------------------------------------------------------------
Builds a full authentication layer (bcrypt + JWT + RBAC + session
management + account locking + auth logging) on top of the Day 6
Threat Intelligence Backend, and uses it to protect the threat APIs.

Run:
    pip install -r requirements.txt
    python app.py
Server starts at http://127.0.0.1:5000
Dashboard:        http://127.0.0.1:5000/dashboard

Demo accounts (created automatically on first run):
    admin     / AdminPass123     (role: admin)
    analyst1  / AnalystPass123   (role: analyst)
    monitor1  / MonitorPass123   (role: monitor)
"""

from flask import Flask, request, jsonify, render_template
import time
import re
import uuid
from datetime import datetime
from collections import defaultdict, deque

from auth.register import register_user, seed_demo_users, users
from auth.login import authenticate
from auth.logout import logout_user
from auth.session_manager import list_active_sessions, revoke_all_sessions_for_user
from auth.role_manager import VALID_ROLES, role_label
from auth.auth_logs import log_event, get_logs
from auth.access_control import jwt_required, get_client_ip

app = Flask(__name__)
app.secret_key = "change-this-secret-key-in-production"

seed_demo_users()

# ---------------------------------------------------------------------------
# IN-MEMORY THREAT-INTEL "DATABASE" (carried over from Day 6)
# ---------------------------------------------------------------------------

login_attempts = []                         # simulated external login attempts
failed_attempts_by_ip = defaultdict(list)
blocked_ips = set()
attack_logs = []
incidents = {}
request_timestamps = defaultdict(deque)

FAILED_LOGIN_THRESHOLD = 3
FAILED_LOGIN_WINDOW_SECONDS = 300
RATE_LIMIT_MAX_REQUESTS = 100
RATE_LIMIT_WINDOW_SECONDS = 60

SUSPICIOUS_PATTERNS = [
    r"(\%27)|(\')|(--)|(\%23)|(#)",
    r"<script.*?>",
    r"union\s+select",
    r"\.\./\.\.",
    r"etc/passwd",
]

# ---------------------------------------------------------------------------
# STANDARDIZED JSON RESPONSE HELPERS
# ---------------------------------------------------------------------------


def success_response(data=None, message="success", status_code=200):
    payload = {
        "status": "success",
        "message": message,
        "data": data,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    return jsonify(payload), status_code


def error_response(message="error", status_code=400, error_code="BAD_REQUEST"):
    payload = {
        "status": "error",
        "error_code": error_code,
        "message": message,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    return jsonify(payload), status_code


# ---------------------------------------------------------------------------
# MIDDLEWARE
# ---------------------------------------------------------------------------


@app.before_request
def before_request():
    request.start_time = time.time()
    client_ip = get_client_ip()

    if client_ip in blocked_ips:
        log_attack_event(client_ip, request.path, "BLOCKED_IP_ACCESS_ATTEMPT")
        return error_response("Your IP has been blocked due to suspicious activity.",
                               403, "IP_BLOCKED")

    if is_rate_limited(client_ip):
        log_attack_event(client_ip, request.path, "RATE_LIMIT_EXCEEDED")
        return error_response("Too many requests. Slow down.", 429, "RATE_LIMITED")

    suspicious = detect_suspicious_payload()
    if suspicious:
        log_attack_event(client_ip, request.path, f"SUSPICIOUS_PAYLOAD_PATTERN: {suspicious}")

    print(f"[REQUEST] {request.method} {request.path} from {client_ip}")


@app.after_request
def after_request(response):
    duration = time.time() - getattr(request, "start_time", time.time())
    print(f"[RESPONSE] {request.path} status={response.status_code} duration={duration:.4f}s")
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# ---------------------------------------------------------------------------
# HELPERS (threat-intel side, unchanged from Day 6)
# ---------------------------------------------------------------------------


def is_rate_limited(ip):
    now = time.time()
    dq = request_timestamps[ip]
    dq.append(now)
    while dq and dq[0] < now - RATE_LIMIT_WINDOW_SECONDS:
        dq.popleft()
    return len(dq) > RATE_LIMIT_MAX_REQUESTS


def flatten_values(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from flatten_values(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from flatten_values(v)
    else:
        yield obj


def detect_suspicious_payload():
    haystacks = list(request.args.values())
    if request.is_json:
        body = request.get_json(silent=True) or {}
        haystacks.extend(str(v) for v in flatten_values(body))
    for value in haystacks:
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, str(value), re.IGNORECASE):
                return pattern
    return None


def log_attack_event(ip, path, reason):
    event = {
        "id": str(uuid.uuid4())[:8],
        "ip": ip,
        "path": path,
        "reason": reason,
        "time": datetime.utcnow().isoformat() + "Z",
    }
    attack_logs.append(event)
    print(f"[ALERT] Suspicious activity from {ip} on {path}: {reason}")
    return event


def calculate_threat_score(ip):
    score = 0
    score += len(failed_attempts_by_ip.get(ip, [])) * 10
    score += len([a for a in attack_logs if a["ip"] == ip]) * 15
    return min(score, 100)


# ===========================================================================
# AUTHENTICATION API  (auth/login.py, register.py, logout.py, session_manager.py)
# ===========================================================================


@app.route("/api/auth/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True)
    if not data:
        return error_response("Request body must be JSON.", 400, "INVALID_JSON")

    user, error = register_user(
        data.get("username"), data.get("password"), data.get("role"),
        ip=get_client_ip(),
    )
    if error:
        return error_response(error, 422, "VALIDATION_ERROR")

    return success_response(user, "User registered successfully.", 201)


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True)
    if not data:
        return error_response("Request body must be JSON.", 400, "INVALID_JSON")

    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return error_response("Fields 'username' and 'password' are required.",
                               422, "VALIDATION_ERROR")

    result, error, status_code = authenticate(username, password, ip=get_client_ip())
    if error:
        return error_response(error, status_code, "AUTH_FAILED")

    return success_response(result, "Login successful.", 200)


@app.route("/api/auth/logout", methods=["POST"])
@jwt_required()
def api_logout():
    token = request.headers.get("Authorization", "").split(" ", 1)[1].strip()
    logout_user(token, request.user["username"], get_client_ip())
    return success_response(None, "Logged out successfully.")


@app.route("/api/auth/me", methods=["GET"])
@jwt_required()
def api_me():
    return success_response({
        "username": request.user["username"],
        "role": request.user["role"],
        "role_label": role_label(request.user["role"]),
    }, "Current session.")


@app.route("/api/auth/logs", methods=["GET"])
@jwt_required(roles=["admin"])
def api_auth_logs():
    return success_response(get_logs(limit=200), "Authentication timeline.")


@app.route("/api/auth/sessions", methods=["GET"])
@jwt_required(roles=["admin"])
def api_sessions():
    return success_response(list_active_sessions(), "Active sessions.")


@app.route("/api/auth/users/<username>/lock", methods=["POST"])
@jwt_required(roles=["admin"])
def api_lock_user(username):
    user = users.get(username)
    if not user:
        return error_response(f"User '{username}' not found.", 404, "NOT_FOUND")
    user["disabled"] = True
    revoked = revoke_all_sessions_for_user(username)
    log_event("ACCOUNT_DISABLED_BY_ADMIN", username, get_client_ip(),
              f"disabled by {request.user['username']}, {revoked} session(s) revoked")
    return success_response({"username": username, "disabled": True},
                             "Account disabled and all sessions revoked.")


@app.route("/api/auth/users/<username>/unlock", methods=["POST"])
@jwt_required(roles=["admin"])
def api_unlock_user(username):
    user = users.get(username)
    if not user:
        return error_response(f"User '{username}' not found.", 404, "NOT_FOUND")
    user["disabled"] = False
    user["failed_attempts"] = 0
    user["locked_until"] = None
    log_event("ACCOUNT_ENABLED_BY_ADMIN", username, get_client_ip(),
              f"re-enabled by {request.user['username']}")
    return success_response({"username": username, "disabled": False}, "Account re-enabled.")


@app.route("/api/auth/users", methods=["GET"])
@jwt_required(roles=["admin"])
def api_list_users():
    safe = [{k: v for k, v in u.items() if k != "password_hash"} for u in users.values()]
    return success_response(safe, f"{len(safe)} user(s).")


# ===========================================================================
# THREAT-INTEL API  (now protected by JWT + RBAC instead of demo tokens)
# ===========================================================================


@app.route("/api/login-attempt", methods=["POST"])
def login_attempt():
    """Public endpoint: represents EXTERNAL login attempts on the monitored
    system (not this app's own auth) — that's what Day 6's threat engine
    watches for brute-force patterns."""
    if not request.is_json:
        return error_response("Request body must be JSON.", 400, "INVALID_CONTENT_TYPE")
    data = request.get_json(silent=True)
    if not data:
        return error_response("Empty or invalid JSON body.", 400, "INVALID_JSON")

    username = data.get("username")
    success = data.get("success")
    if not username or success is None:
        return error_response("Fields 'username' and 'success' are required.",
                               422, "VALIDATION_ERROR")

    ip = get_client_ip()
    record = {
        "id": str(uuid.uuid4())[:8],
        "username": username,
        "ip": ip,
        "success": bool(success),
        "time": datetime.utcnow().isoformat() + "Z",
    }
    login_attempts.append(record)

    if not success:
        failed_attempts_by_ip[ip].append(time.time())
        cutoff = time.time() - FAILED_LOGIN_WINDOW_SECONDS
        failed_attempts_by_ip[ip] = [t for t in failed_attempts_by_ip[ip] if t > cutoff]
        if len(failed_attempts_by_ip[ip]) >= FAILED_LOGIN_THRESHOLD:
            log_attack_event(ip, "/api/login-attempt",
                              f"Repeated failed logins "
                              f"({len(failed_attempts_by_ip[ip])} in {FAILED_LOGIN_WINDOW_SECONDS}s)")

    return success_response(record, "Login attempt recorded.", 201)


@app.route("/api/threat-summary", methods=["GET"])
@jwt_required(roles=["admin", "analyst", "monitor"])
def threat_summary():
    suspicious = [
        {"ip": ip, "failed_count": len(times), "threat_score": calculate_threat_score(ip)}
        for ip, times in failed_attempts_by_ip.items()
        if len(times) >= FAILED_LOGIN_THRESHOLD
    ]
    summary = {
        "total_login_attempts": len(login_attempts),
        "total_failed_logins": sum(1 for a in login_attempts if not a["success"]),
        "total_blocked_ips": len(blocked_ips),
        "total_attack_events": len(attack_logs),
        "suspicious_ip_count": len(suspicious),
        "suspicious_ips": suspicious,
    }
    return success_response(summary, "Threat summary generated.")


@app.route("/api/suspicious-ips", methods=["GET"])
@jwt_required(roles=["admin", "analyst", "monitor"])
def suspicious_ips():
    result = [
        {
            "ip": ip, "failed_attempts": len(times),
            "threat_score": calculate_threat_score(ip), "blocked": ip in blocked_ips,
        }
        for ip, times in failed_attempts_by_ip.items()
        if len(times) >= FAILED_LOGIN_THRESHOLD
    ]
    return success_response(result, f"{len(result)} suspicious IP(s) found.")


@app.route("/api/block-ip", methods=["POST"])
@jwt_required(roles=["admin"])
def block_ip():
    data = request.get_json(silent=True)
    if not data or not data.get("ip"):
        return error_response("Field 'ip' is required.", 422, "VALIDATION_ERROR")
    ip = data["ip"]
    blocked_ips.add(ip)
    incident_id = str(uuid.uuid4())[:8]
    incidents[incident_id] = {
        "incident_id": incident_id, "ip": ip, "action": "IP_BLOCKED",
        "reason": data.get("reason", "Manually blocked by admin."),
        "blocked_by": request.user["username"],
        "time": datetime.utcnow().isoformat() + "Z",
    }
    return success_response(incidents[incident_id], f"IP {ip} has been blocked.", 201)


@app.route("/api/attack-logs", methods=["GET"])
@jwt_required(roles=["admin", "analyst", "monitor"])
def get_attack_logs():
    return success_response(attack_logs, f"{len(attack_logs)} attack log(s) found.")


@app.route("/api/incident/<incident_id>", methods=["GET"])
@jwt_required(roles=["admin", "analyst"], audit_label="incident_evidence_access")
def get_incident(incident_id):
    """Restricted to admin + analyst only — monitoring staff cannot view
    incident evidence. Every access is written to the audit trail."""
    incident = incidents.get(incident_id)
    if not incident:
        return error_response(f"Incident '{incident_id}' not found.", 404, "NOT_FOUND")
    return success_response(incident, "Incident found.")


# ---------------------------------------------------------------------------
# ERROR HANDLING
# ---------------------------------------------------------------------------


@app.errorhandler(404)
def not_found(e):
    return error_response("The requested endpoint does not exist.", 404, "NOT_FOUND")


@app.errorhandler(405)
def method_not_allowed(e):
    return error_response("This HTTP method is not allowed on this endpoint.",
                           405, "METHOD_NOT_ALLOWED")


@app.errorhandler(500)
def server_error(e):
    return error_response("An internal server error occurred.", 500, "SERVER_ERROR")


@app.errorhandler(Exception)
def handle_uncaught(e):
    print(f"[UNCAUGHT EXCEPTION] {e}")
    return error_response("Something went wrong on the server.", 500, "UNCAUGHT_EXCEPTION")


# ---------------------------------------------------------------------------
# ROOT / DASHBOARD
# ---------------------------------------------------------------------------


@app.route("/", methods=["GET"])
def index():
    return success_response({
        "service": "Secure Threat Intelligence Backend (Day 7 — with Authentication)",
        "auth_endpoints": [
            "POST /api/auth/register",
            "POST /api/auth/login",
            "POST /api/auth/logout            (token required)",
            "GET  /api/auth/me                (token required)",
            "GET  /api/auth/logs              (admin only)",
            "GET  /api/auth/sessions          (admin only)",
            "GET  /api/auth/users             (admin only)",
            "POST /api/auth/users/<u>/lock    (admin only)",
            "POST /api/auth/users/<u>/unlock  (admin only)",
        ],
        "threat_endpoints": [
            "POST /api/login-attempt          (public)",
            "GET  /api/threat-summary         (any authenticated role)",
            "GET  /api/suspicious-ips         (any authenticated role)",
            "POST /api/block-ip               (admin only)",
            "GET  /api/attack-logs            (any authenticated role)",
            "GET  /api/incident/<id>          (admin, analyst — audited)",
        ],
        "demo_accounts": [
            {"username": "admin", "password": "AdminPass123", "role": "admin"},
            {"username": "analyst1", "password": "AnalystPass123", "role": "analyst"},
            {"username": "monitor1", "password": "MonitorPass123", "role": "monitor"},
        ],
    }, "Secure Threat Intelligence API is running.")


@app.route("/dashboard", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
