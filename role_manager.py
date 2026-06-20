"""
role_manager.py
----------------
Role-Based Access Control (RBAC) definitions.

Three roles for this lab, matching Exercise 7.1:
  - admin   -> Threat Administrator   (full control, can block IPs, lock users)
  - analyst -> Security Analyst       (can investigate incidents/evidence)
  - monitor -> Monitoring Staff       (read-only visibility, no sensitive access)
"""

ROLES = {
    "admin": {"label": "Threat Administrator", "level": 3},
    "analyst": {"label": "Security Analyst", "level": 2},
    "monitor": {"label": "Monitoring Staff", "level": 1},
}

VALID_ROLES = set(ROLES.keys())


def is_valid_role(role):
    return role in VALID_ROLES


def role_label(role):
    return ROLES.get(role, {}).get("label", role)


def role_allowed(user_role, allowed_roles):
    """True if user_role is one of the roles permitted for an action."""
    if not allowed_roles:
        return True
    return user_role in allowed_roles


def has_minimum_level(user_role, minimum_role):
    """Hierarchical check: does user_role have >= privilege level of minimum_role?"""
    user_level = ROLES.get(user_role, {}).get("level", 0)
    min_level = ROLES.get(minimum_role, {}).get("level", 0)
    return user_level >= min_level
