"""
rbac/access_control.py
=======================
Implements Role-Based Access Control (RBAC).

Permission matrix
─────────────────────────────────────────────────────────────────
Action                        Student   Lecturer   Admin
─────────────────────────────────────────────────────────────────
view_own_grades               ✓
upload_assignment             ✓
view_personal_data            ✓
send_message                  ✓         ✓
review_submissions                      ✓
give_feedback                           ✓
view_all_grades                         ✓
manage_users                                        ✓
view_audit_log                                      ✓
enforce_access_rules                                ✓
monitor_system                                      ✓
─────────────────────────────────────────────────────────────────

Each check is done at the boundary of every user action so that even
if a session token is stolen, actions are still gated by role.
"""

import logging
from functools import wraps

logger = logging.getLogger(__name__)

# ── Permission definitions ─────────────────────────────────────────────────
PERMISSIONS: dict[str, set[str]] = {
    "student": {
        "view_own_grades",
        "upload_assignment",
        "view_personal_data",
        "send_message",
        "view_own_profile",
    },
    "lecturer": {
        "review_submissions",
        "give_feedback",
        "view_all_grades",
        "send_message",
        "view_own_profile",
    },
    "admin": {
        "manage_users",
        "view_audit_log",
        "enforce_access_rules",
        "monitor_system",
        "view_all_grades",
        "view_own_profile",
        "delete_user",
        "unlock_user",
    },
}


class AccessControl:
    """Enforces the RBAC permission matrix."""

    def is_allowed(self, role: str, action: str) -> bool:
        """
        Return True if `role` is permitted to perform `action`.
        Logs both grants and denials for audit purposes.
        """
        allowed = action in PERMISSIONS.get(role, set())
        if allowed:
            logger.debug("RBAC GRANT  role=%s action=%s", role, action)
        else:
            logger.warning("RBAC DENY   role=%s action=%s", role, action)
        return allowed

    def require_permission(self, session: dict, action: str) -> bool:
        """
        Convenience wrapper: check session dict and print a message.
        Returns True if granted.
        """
        if not session:
            print("  ✗ Not authenticated.")
            return False
        role = session.get("role", "")
        if self.is_allowed(role, action):
            return True
        print(f"  ✗ Access denied. Your role ('{role}') cannot perform '{action}'.")
        return False

    def list_permissions(self, role: str) -> list[str]:
        """Return the sorted list of permissions for a given role."""
        return sorted(PERMISSIONS.get(role, set()))
