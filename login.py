"""
login.py
--------
Login Validation, Failed-Login Tracking, Account Locking,
IP-Based Login Restriction & Suspicious-Authentication Detection.
"""

import bcrypt
import time
from collections import defaultdict
from .register import users
from .auth_logs import log_event
from .session_manager import create_session

# ---------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------
MAX_FAILED_ATTEMPTS_PER_USER = 5
ACCOUNT_LOCK_SECONDS = 300          # 5 minutes

MAX_FAILED_ATTEMPTS_PER_IP = 8      # across ANY username (credential stuffing)
IP_BLOCK_WINDOW_SECONDS = 300
IP_BLOCK_DURATION_SECONDS = 600     # 10 minutes

SUSPICIOUS_DISTINCT_USERNAMES_THRESHOLD = 4  # same IP trying many usernames fast

# ---------------------------------------------------------------------
# STATE
# ---------------------------------------------------------------------
failed_attempts_by_ip = defaultdict(list)     # ip -> [timestamps]
usernames_tried_by_ip = defaultdict(set)      # ip -> {usernames attempted}
blocked_login_ips = {}                        # ip -> unblock_timestamp


def _purge_old(ip):
    cutoff = time.time() - IP_BLOCK_WINDOW_SECONDS
    failed_attempts_by_ip[ip] = [t for t in failed_attempts_by_ip[ip] if t > cutoff]


def _is_ip_blocked(ip):
    until = blocked_login_ips.get(ip)
    if until and until > time.time():
        return True
    if until:  # expired block, clean up
        del blocked_login_ips[ip]
    return False


def _is_account_locked(user):
    return bool(user.get("locked_until") and user["locked_until"] > time.time())


def authenticate(username, password, ip="unknown"):
    """
    Validates credentials and returns (result_dict, error_message, status_code).
    On success, result_dict contains a fresh JWT.
    """
    # 1. IP-based login restriction — block known-bad IPs before even checking creds
    if _is_ip_blocked(ip):
        remaining = int(blocked_login_ips[ip] - time.time())
        log_event("LOGIN_BLOCKED_IP", username, ip, f"IP blocked, {remaining}s remaining")
        return None, f"Too many failed logins from this IP. Try again in {remaining}s.", 429

    user = users.get(username)

    # 2. Unknown username
    if not user:
        _register_failed_ip_attempt(username, ip)
        log_event("LOGIN_FAILED", username, ip, "unknown username")
        return None, "Invalid username or password.", 401

    # 3. Account disabled by an admin
    if user.get("disabled"):
        log_event("LOGIN_BLOCKED_DISABLED", username, ip, "account disabled by admin")
        return None, "This account has been disabled. Contact an administrator.", 403

    # 4. Account locked from too many prior failures
    if _is_account_locked(user):
        remaining = int(user["locked_until"] - time.time())
        log_event("LOGIN_BLOCKED_ACCOUNT_LOCKED", username, ip, f"{remaining}s remaining")
        return None, f"Account locked due to failed attempts. Try again in {remaining}s.", 423

    # 5. Wrong password
    if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"]):
        user["failed_attempts"] += 1
        _register_failed_ip_attempt(username, ip)
        log_event("LOGIN_FAILED", username, ip, f"attempt {user['failed_attempts']}")

        if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS_PER_USER:
            user["locked_until"] = time.time() + ACCOUNT_LOCK_SECONDS
            log_event("ACCOUNT_LOCKED", username, ip,
                      f"{MAX_FAILED_ATTEMPTS_PER_USER} failed attempts, "
                      f"locked {ACCOUNT_LOCK_SECONDS}s")
            return None, "Too many failed attempts. Account locked.", 423

        return None, "Invalid username or password.", 401

    # ---- success ----
    user["failed_attempts"] = 0
    user["locked_until"] = None
    token = create_session(username, user["role"], ip)
    log_event("LOGIN_SUCCESS", username, ip, f"role={user['role']}")

    return {
        "token": token,
        "username": username,
        "role": user["role"],
    }, None, 200


def _register_failed_ip_attempt(username, ip):
    """Tracks failed attempts + distinct usernames per IP; blocks/flags as needed."""
    now = time.time()
    failed_attempts_by_ip[ip].append(now)
    usernames_tried_by_ip[ip].add(username)
    _purge_old(ip)

    # IP-based login restriction
    if len(failed_attempts_by_ip[ip]) >= MAX_FAILED_ATTEMPTS_PER_IP:
        blocked_login_ips[ip] = now + IP_BLOCK_DURATION_SECONDS
        log_event("IP_BLOCKED_LOGIN", None, ip,
                  f"{len(failed_attempts_by_ip[ip])} failed logins in "
                  f"{IP_BLOCK_WINDOW_SECONDS}s -> blocked {IP_BLOCK_DURATION_SECONDS}s")

    # Suspicious-authentication detection: many distinct usernames from one IP
    # quickly = classic credential-stuffing / username-enumeration pattern.
    if len(usernames_tried_by_ip[ip]) >= SUSPICIOUS_DISTINCT_USERNAMES_THRESHOLD:
        log_event("SUSPICIOUS_AUTH_PATTERN", None, ip,
                  f"{len(usernames_tried_by_ip[ip])} distinct usernames attempted "
                  f"from this IP (possible credential stuffing)")
