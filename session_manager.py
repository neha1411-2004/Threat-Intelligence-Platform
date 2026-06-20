"""
session_manager.py
-------------------
Secure Session Management using JWT (JSON Web Tokens).

Each successful login issues a signed JWT with a short expiry (session
timeout). The token's unique id (jti) is also tracked server-side in
`active_sessions` so a session can be explicitly revoked on logout —
plain JWTs can't be "deleted", so we keep a server-side allow-list.
"""

import jwt
import uuid
from datetime import datetime, timedelta

# In a real deployment this MUST come from an environment variable / secrets
# manager, never hardcoded in source.
SECRET_KEY = "lab-secret-key-change-this-in-production"
ALGORITHM = "HS256"
SESSION_TIMEOUT_MINUTES = 30

# jti -> session metadata (lets us list/revoke active sessions server-side)
active_sessions = {}


def create_session(username, role, ip=None):
    """Issue a new JWT for a freshly authenticated user."""
    jti = str(uuid.uuid4())
    now = datetime.utcnow()
    expires = now + timedelta(minutes=SESSION_TIMEOUT_MINUTES)

    payload = {
        "sub": username,     # subject = who the token belongs to
        "role": role,
        "jti": jti,          # unique token id, used for server-side revocation
        "iat": now,          # issued-at
        "exp": expires,      # expiry -> built-in session timeout
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    # Older PyJWT versions (<2.0) return bytes instead of str, which breaks
    # JSON serialization downstream. Normalize to str regardless of version.
    if isinstance(token, bytes):
        token = token.decode("utf-8")


    active_sessions[jti] = {
        "jti": jti,
        "username": username,
        "role": role,
        "ip": ip,
        "issued_at": now.isoformat() + "Z",
        "expires_at": expires.isoformat() + "Z",
    }
    return token


def validate_session(token):
    """
    Decode + verify a JWT. Returns (payload, error_message).
    Checks: signature valid, not expired, and not revoked (logged out).
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None, "Session expired. Please log in again."
    except jwt.InvalidTokenError:
        return None, "Invalid authentication token."

    jti = payload.get("jti")
    if jti not in active_sessions:
        return None, "Session has been logged out or revoked."

    return payload, None


def revoke_session(token):
    """Used on logout — removes the session from the server-side allow-list."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM],
                              options={"verify_exp": False})
    except jwt.InvalidTokenError:
        return False

    jti = payload.get("jti")
    if jti in active_sessions:
        del active_sessions[jti]
        return True
    return False


def list_active_sessions():
    return list(active_sessions.values())


def revoke_all_sessions_for_user(username):
    """Used when an admin disables/locks a user — kills all their open sessions."""
    to_remove = [jti for jti, s in active_sessions.items() if s["username"] == username]
    for jti in to_remove:
        del active_sessions[jti]
    return len(to_remove)