"""
access_control.py
------------------
Access Control Mechanisms.

`jwt_required` is the single decorator every protected route uses. It:
  1. Extracts + validates the JWT from the Authorization header.
  2. Rejects expired / revoked / malformed tokens.
  3. Enforces role-based access control (RBAC) via role_manager.
  4. Optionally writes an audit-trail entry for sensitive resources
     (e.g. incident/evidence access).
"""

from functools import wraps
from flask import request, jsonify
from .session_manager import validate_session
from .role_manager import role_allowed
from .auth_logs import log_event


def get_client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "unknown"


def _error(message, status_code, error_code):
    return jsonify({
        "status": "error",
        "error_code": error_code,
        "message": message,
    }), status_code


def jwt_required(roles=None, audit_label=None):
    """
    @jwt_required()                       -> any authenticated user
    @jwt_required(roles=["admin"])        -> admin only
    @jwt_required(roles=["admin","analyst"], audit_label="incident_access")
                                           -> RBAC + audit trail entry
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = get_client_ip()
            auth_header = request.headers.get("Authorization", "")

            if not auth_header.startswith("Bearer "):
                log_event("ACCESS_DENIED", None, ip, "missing Authorization header")
                return _error("Missing or malformed Authorization header.",
                               401, "MISSING_TOKEN")

            token = auth_header.split(" ", 1)[1].strip()
            payload, error = validate_session(token)
            if error:
                log_event("ACCESS_DENIED", None, ip, error)
                return _error(error, 401, "INVALID_TOKEN")

            username, role = payload["sub"], payload["role"]

            if roles and not role_allowed(role, roles):
                log_event("ACCESS_DENIED", username, ip,
                          f"role '{role}' not permitted (needs one of {roles})")
                return _error("You do not have permission for this action.",
                               403, "FORBIDDEN")

            # make the authenticated identity available to the route
            request.user = {"username": username, "role": role}
            request.client_ip = ip

            if audit_label:
                log_event("RESOURCE_ACCESS", username, ip,
                          f"{audit_label} -> {request.path}")

            return f(*args, **kwargs)
        return wrapper
    return decorator
