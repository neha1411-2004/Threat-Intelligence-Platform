"""
auth_logs.py
------------
Authentication Logging & Monitoring.

Every security-relevant authentication event (registration, login success/
failure, lockouts, logout, access-denied, evidence access, etc.) is recorded
here so the system has a full authentication timeline for auditing.
"""

import uuid
from datetime import datetime

# In-memory authentication timeline (swap for a DB table in production)
auth_logs = []


def log_event(event, username=None, ip=None, detail=""):
    """Record one authentication-timeline entry and print it (console monitoring)."""
    entry = {
        "id": str(uuid.uuid4())[:8],
        "event": event,
        "username": username,
        "ip": ip,
        "detail": detail,
        "time": datetime.utcnow().isoformat() + "Z",
    }
    auth_logs.append(entry)
    print(f"[AUTH] {event} | user={username} ip={ip} | {detail}")
    return entry


def get_logs(limit=None):
    logs = list(reversed(auth_logs))  # newest first
    if limit:
        return logs[:limit]
    return logs


def get_logs_for_user(username):
    return [e for e in auth_logs if e["username"] == username]
