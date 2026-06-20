"""
logout.py
---------
Secure Logout.

Logging out revokes the session server-side (removes it from the active
session allow-list in session_manager). After this, the same JWT will be
rejected even though it hasn't technically expired yet — this is what
makes logout immediate rather than waiting for natural token expiry.
"""

from .session_manager import revoke_session
from .auth_logs import log_event


def logout_user(token, username=None, ip=None):
    revoked = revoke_session(token)
    if revoked:
        log_event("LOGOUT", username, ip, "session revoked")
    else:
        log_event("LOGOUT_FAILED", username, ip, "session not found or already expired")
    return revoked
