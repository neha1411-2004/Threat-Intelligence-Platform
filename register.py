"""
register.py
------------
User Registration & Secure Password Hashing.

Passwords are NEVER stored in plain text. bcrypt salts and hashes every
password before it touches the "database" (in-memory dict here).
"""

import bcrypt
from datetime import datetime
from .auth_logs import log_event
from .role_manager import is_valid_role

# In-memory user "database": username -> user record
users = {}


def register_user(username, password, role, ip=None):
    """
    Validate input, hash the password, and create a new user account.
    Returns (user_record_safe, error_message).
    """
    if not username or not password or not role:
        return None, "Fields 'username', 'password' and 'role' are required."

    if username in users:
        log_event("REGISTRATION_FAILED", username, ip, "username already exists")
        return None, "That username is already taken."

    if not is_valid_role(role):
        return None, "Role must be one of: admin, analyst, monitor."

    if len(password) < 8:
        return None, "Password must be at least 8 characters long."

    # bcrypt hashing — generates its own random salt internally
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    users[username] = {
        "username": username,
        "password_hash": password_hash,
        "role": role,
        "failed_attempts": 0,
        "locked_until": None,
        "disabled": False,
        "created_at": datetime.utcnow().isoformat() + "Z",
    }

    log_event("USER_REGISTERED", username, ip, f"role={role}")

    safe_record = {k: v for k, v in users[username].items() if k != "password_hash"}
    return safe_record, None


def seed_demo_users():
    """Pre-create a few demo accounts so the lab can be tested immediately."""
    demo_accounts = [
        ("admin", "AdminPass123", "admin"),
        ("analyst1", "AnalystPass123", "analyst"),
        ("monitor1", "MonitorPass123", "monitor"),
    ]
    for username, password, role in demo_accounts:
        if username not in users:
            register_user(username, password, role, ip="seed-script")
