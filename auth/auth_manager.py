"""
auth/auth_manager.py
====================
Handles user authentication:
  - User registration (password hashing via DataProtector)
  - Login with brute-force protection (account lockout after 5 failures)
  - Session token issuance and validation
  - Audit logging of all authentication events
  - First-run demo user seeding
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timedelta

from crypto.data_protector import DataProtector

logger = logging.getLogger(__name__)

USER_STORE   = Path("data/users.json")
AUDIT_LOG    = Path("logs/auth_audit.log")
MAX_FAILURES = 5        # lockout after this many consecutive bad passwords
LOCKOUT_MINS = 15       # lockout duration in minutes
SESSION_MINS = 30       # session token validity window


class AuthManager:
    """Manages user accounts, credentials, and sessions."""

    def __init__(self, data_protector: DataProtector):
        self.dp       = data_protector
        self._users   = self._load_users()
        self._sessions: dict[str, dict] = {}   # token → {username, role, expires}
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        USER_STORE.parent.mkdir(parents=True, exist_ok=True)

    # ── Persistence ────────────────────────────────────────────────────────

    def _load_users(self) -> dict:
        if USER_STORE.exists():
            return json.loads(USER_STORE.read_text())
        return {}

    def _save_users(self) -> None:
        USER_STORE.write_text(json.dumps(self._users, indent=2))

    # ── Audit logging ──────────────────────────────────────────────────────

    def _audit(self, event: str, username: str, detail: str = "") -> None:
        """Append a timestamped entry to the auth audit log."""
        ts  = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        msg = f"[{ts}] {event:20s} user={username} {detail}\n"
        with AUDIT_LOG.open("a") as f:
            f.write(msg)
        logger.info(msg.strip())

    # ── Registration ────────────────────────────────────────────────────────

    def register_user(self, username: str, password: str, role: str) -> bool:
        """
        Register a new user.
        Roles: 'student', 'lecturer', 'admin'.
        Returns False if username already exists.
        """
        if username in self._users:
            self._audit("REGISTER_FAIL", username, "already exists")
            return False

        valid_roles = {"student", "lecturer", "admin"}
        if role not in valid_roles:
            raise ValueError(f"Invalid role '{role}'. Must be one of {valid_roles}.")

        pw_record = self.dp.hash_password(password)

        self._users[username] = {
            "role":             role,
            "password":         pw_record,
            "failed_attempts":  0,
            "locked_until":     None,
            "created_at":       datetime.utcnow().isoformat(),
        }
        self._save_users()

        # Generate RSA key pair for the user
        self.dp.generate_rsa_keypair(username)

        self._audit("REGISTER_OK", username, f"role={role}")
        return True

    # ── Login ───────────────────────────────────────────────────────────────

    def login(self, username: str, password: str) -> str | None:
        """
        Authenticate a user.
        Returns a session token string on success, or None on failure.
        Implements account lockout after MAX_FAILURES consecutive failures.
        """
        if username not in self._users:
            self._audit("LOGIN_FAIL", username, "unknown user")
            return None

        record = self._users[username]

        # Check lockout
        if record["locked_until"]:
            locked_until = datetime.fromisoformat(record["locked_until"])
            if datetime.utcnow() < locked_until:
                remaining = int((locked_until - datetime.utcnow()).total_seconds() / 60) + 1
                self._audit("LOGIN_LOCKED", username, f"locked for ~{remaining}m")
                print(f"  ✗ Account locked. Try again in ~{remaining} minute(s).")
                return None
            else:
                # Lockout expired — reset counter
                record["failed_attempts"] = 0
                record["locked_until"]    = None

        # Verify password
        if not self.dp.verify_password(password, record["password"]):
            record["failed_attempts"] += 1
            remaining_attempts = MAX_FAILURES - record["failed_attempts"]

            if record["failed_attempts"] >= MAX_FAILURES:
                record["locked_until"] = (
                    datetime.utcnow() + timedelta(minutes=LOCKOUT_MINS)
                ).isoformat()
                record["failed_attempts"] = 0
                self._save_users()
                self._audit("LOGIN_LOCKED", username, f"locked for {LOCKOUT_MINS}m after failures")
                print(f"  ✗ Too many failed attempts. Account locked for {LOCKOUT_MINS} minutes.")
            else:
                self._save_users()
                self._audit("LOGIN_FAIL", username, f"bad password ({record['failed_attempts']}/{MAX_FAILURES})")
                print(f"  ✗ Incorrect password. {remaining_attempts} attempt(s) remaining.")
            return None

        # Success — reset failure counter, issue token
        record["failed_attempts"] = 0
        record["locked_until"]    = None
        self._save_users()

        token   = self.dp.generate_session_token()
        expires = datetime.utcnow() + timedelta(minutes=SESSION_MINS)
        self._sessions[token] = {
            "username": username,
            "role":     record["role"],
            "expires":  expires.isoformat(),
        }
        self._audit("LOGIN_OK", username, f"role={record['role']}")
        return token

    # ── Session validation ──────────────────────────────────────────────────

    def validate_session(self, token: str) -> dict | None:
        """
        Return session info dict {'username', 'role'} if token is valid
        and not expired.  Returns None otherwise.
        """
        session = self._sessions.get(token)
        if not session:
            return None
        if datetime.utcnow() > datetime.fromisoformat(session["expires"]):
            del self._sessions[token]
            self._audit("SESSION_EXPIRED", session["username"])
            return None
        return {"username": session["username"], "role": session["role"]}

    def logout(self, token: str) -> None:
        """Invalidate a session token."""
        session = self._sessions.pop(token, None)
        if session:
            self._audit("LOGOUT", session["username"])

    # ── User info ────────────────────────────────────────────────────────────

    def get_user_role(self, username: str) -> str | None:
        user = self._users.get(username)
        return user["role"] if user else None

    def list_users(self) -> list[dict]:
        """Return a sanitised list of users (no passwords)."""
        return [
            {
                "username":   u,
                "role":       d["role"],
                "created_at": d["created_at"],
                "locked":     bool(d.get("locked_until")),
            }
            for u, d in self._users.items()
        ]

    def delete_user(self, username: str) -> bool:
        """Remove a user account (admin only — enforced in AccessControl)."""
        if username in self._users:
            del self._users[username]
            self._save_users()
            self._audit("DELETE_USER", username)
            return True
        return False

    # ── Demo seeding ─────────────────────────────────────────────────────────

    def seed_demo_users(self) -> None:
        """
        Populate the store with three demo accounts on first run.
        In a real deployment this would not exist; accounts are provisioned
        through an admin console.
        """
        demo_accounts = [
            ("alice_student", "Student@1234!", "student"),
            ("bob_lecturer",  "Lecturer@1234!", "lecturer"),
            ("carol_admin",   "Admin@1234!",   "admin"),
        ]
        seeded = False
        for uname, pwd, role in demo_accounts:
            if uname not in self._users:
                self.register_user(uname, pwd, role)
                seeded = True

        if seeded:
            print("\n  [INFO] Demo accounts created:")
            print("   Username        | Password        | Role")
            print("   --------------- | --------------- | --------")
            for uname, pwd, role in demo_accounts:
                print(f"   {uname:<15} | {pwd:<15} | {role}")
            print()
