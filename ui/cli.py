"""
ui/cli.py
=========
Interactive command-line interface for the Secure Learning Platform.

Presents role-aware menus; every action is gated by AccessControl before
any data operation occurs.  All user input is treated as untrusted.
"""

import getpass
import logging
from pathlib import Path

from auth.auth_manager import AuthManager
from rbac.access_control import AccessControl
from crypto.data_protector import DataProtector
from data.platform_data import PlatformData

logger = logging.getLogger(__name__)


class CLI:
    def __init__(self, auth: AuthManager, ac: AccessControl, dp: DataProtector):
        self.auth    = auth
        self.ac      = ac
        self.dp      = dp
        self.pdata   = PlatformData(dp)
        self.session = None    # {username, role}
        self.token   = None

    # ── Main loop ────────────────────────────────────────────────────────────

    def run(self) -> None:
        while True:
            if not self.session:
                self._main_menu()
            else:
                role = self.session["role"]
                if role == "student":
                    self._student_menu()
                elif role == "lecturer":
                    self._lecturer_menu()
                elif role == "admin":
                    self._admin_menu()

    # ── Unauthenticated menu ─────────────────────────────────────────────────

    def _main_menu(self) -> None:
        print("\n" + "─" * 50)
        print("  1) Login")
        print("  2) Exit")
        print("─" * 50)
        choice = input("  Select: ").strip()
        if choice == "1":
            self._do_login()
        elif choice == "2":
            print("  Goodbye.")
            raise SystemExit(0)

    def _do_login(self) -> None:
        username = input("  Username: ").strip()
        password = getpass.getpass("  Password: ")
        token = self.auth.login(username, password)
        if token:
            self.token   = token
            self.session = self.auth.validate_session(token)
            role         = self.session["role"]
            print(f"\n  ✓ Welcome, {username}! Logged in as [{role.upper()}].")
        else:
            print("  ✗ Login failed.")

    def _do_logout(self) -> None:
        self.auth.logout(self.token)
        print(f"  ✓ Logged out.")
        self.session = None
        self.token   = None

    # ── Student menu ─────────────────────────────────────────────────────────

    def _student_menu(self) -> None:
        u = self.session["username"]
        print(f"\n{'─'*50}")
        print(f"  STUDENT MENU  [{u}]")
        print("─" * 50)
        print("  1) View my grades")
        print("  2) Upload assignment")
        print("  3) View personal data")
        print("  4) Send message to lecturer")
        print("  5) Read inbox")
        print("  6) Logout")
        print("─" * 50)
        choice = input("  Select: ").strip()

        if choice == "1":
            if self.ac.require_permission(self.session, "view_own_grades"):
                grades = self.pdata.get_grades(u)
                self._print_table(
                    ["Module", "Grade", "Recorded By", "Signature", "Timestamp"],
                    [[g.get("module","?"), g.get("grade","?"),
                      g.get("recorded_by","?"),
                      g.get("signature_status","No signature"),
                      g.get("timestamp","?")[:19]]
                     for g in grades] if grades else [["No grades found","","","",""]],
                )

        elif choice == "2":
            if self.ac.require_permission(self.session, "upload_assignment"):
                module  = input("  Module name: ").strip()
                content = input("  Assignment content: ").strip()
                aid = self.pdata.submit_assignment(u, module, content)
                print(f"  ✓ Assignment submitted. ID: {aid}")

        elif choice == "3":
            if self.ac.require_permission(self.session, "view_personal_data"):
                role = self.auth.get_user_role(u)
                print(f"\n  Username : {u}")
                print(f"  Role     : {role}")
                perms = self.ac.list_permissions(role)
                print(f"  Permissions: {', '.join(perms)}")

        elif choice == "4":
            if self.ac.require_permission(self.session, "send_message"):
                recipient = input("  Recipient username: ").strip()
                body      = input("  Message: ").strip()
                try:
                    self.pdata.send_message(u, recipient, body)
                    print("  ✓ Message sent (RSA-encrypted).")
                except FileNotFoundError:
                    print(f"  ✗ Recipient '{recipient}' not found or has no public key.")

        elif choice == "5":
            msgs = self.pdata.read_messages(u)
            if not msgs:
                print("  Inbox is empty.")
            for m in msgs:
                print(f"\n  From: {m.get('from')} | Sent: {m.get('sent_at','')[:19]}")
                print(f"  {m.get('body', m.get('error', ''))}")

        elif choice == "6":
            self._do_logout()

    # ── Lecturer menu ────────────────────────────────────────────────────────

    def _lecturer_menu(self) -> None:
        u = self.session["username"]
        print(f"\n{'─'*50}")
        print(f"  LECTURER MENU  [{u}]")
        print("─" * 50)
        print("  1) View all grades")
        print("  2) Record a grade")
        print("  3) Review submissions")
        print("  4) Give feedback (send message)")
        print("  5) Read inbox")
        print("  6) Logout")
        print("─" * 50)
        choice = input("  Select: ").strip()

        if choice == "1":
            if self.ac.require_permission(self.session, "view_all_grades"):
                all_grades = self.pdata.get_all_grades()
                for student, gs in all_grades.items():
                    print(f"\n  Student: {student}")
                    self._print_table(
                        ["Module", "Grade", "Recorded By"],
                        [[g.get("module","?"), g.get("grade","?"), g.get("recorded_by","?")]
                         for g in gs],
                    )

        elif choice == "2":
            if self.ac.require_permission(self.session, "give_feedback"):
                student = input("  Student username: ").strip()
                module  = input("  Module: ").strip()
                grade   = input("  Grade: ").strip()
                self.pdata.record_grade(student, module, grade, recorded_by=u)
                print("  ✓ Grade recorded and encrypted.")

        elif choice == "3":
            if self.ac.require_permission(self.session, "review_submissions"):
                all_subs = self.pdata.get_assignments()
                if not all_subs:
                    print("  No submissions found.")
                for sub in all_subs:
                    print(f"\n  ID: {sub.get('id')} | Student: {sub.get('student')} | Module: {sub.get('module')}")
                    print(f"  Submitted: {sub.get('submitted_at','')[:19]}")
                    print(f"  Content  : {sub.get('content','[error]')}")

        elif choice == "4":
            if self.ac.require_permission(self.session, "send_message"):
                recipient = input("  Recipient username: ").strip()
                body      = input("  Feedback message: ").strip()
                try:
                    self.pdata.send_message(u, recipient, body)
                    print("  ✓ Feedback sent (RSA-encrypted).")
                except FileNotFoundError:
                    print(f"  ✗ Recipient '{recipient}' not found.")

        elif choice == "5":
            msgs = self.pdata.read_messages(u)
            if not msgs:
                print("  Inbox is empty.")
            for m in msgs:
                print(f"\n  From: {m.get('from')} | Sent: {m.get('sent_at','')[:19]}")
                print(f"  {m.get('body', m.get('error',''))}")

        elif choice == "6":
            self._do_logout()

    # ── Admin menu ───────────────────────────────────────────────────────────

    def _admin_menu(self) -> None:
        u = self.session["username"]
        print(f"\n{'─'*50}")
        print(f"  ADMIN MENU  [{u}]")
        print("─" * 50)
        print("  1) List all users")
        print("  2) Add new user")
        print("  3) Delete user")
        print("  4) Revoke a user's cryptographic keys")
        print("  5) View audit log (last 20 lines)")
        print("  5) View all grades")
        print("  6) System monitor (show key paths)")
        print("  7) Logout")
        print("─" * 50)
        choice = input("  Select: ").strip()

        if choice == "1":
            if self.ac.require_permission(self.session, "manage_users"):
                users = self.auth.list_users()
                self._print_table(
                    ["Username", "Role", "Locked", "Created"],
                    [[uu["username"], uu["role"], str(uu["locked"]), uu["created_at"][:10]]
                     for uu in users],
                )

        elif choice == "2":
            if self.ac.require_permission(self.session, "manage_users"):
                uname = input("  New username: ").strip()
                pwd   = getpass.getpass("  Password: ")
                role  = input("  Role (student/lecturer/admin): ").strip()
                ok    = self.auth.register_user(uname, pwd, role)
                print("  ✓ User created." if ok else "  ✗ Username already exists.")

        elif choice == "3":
            if self.ac.require_permission(self.session, "delete_user"):
                uname = input("  Username to delete: ").strip()
                ok    = self.auth.delete_user(uname)
                print("  ✓ User deleted." if ok else "  ✗ User not found.")

        elif choice == "4":
            if self.ac.require_permission(self.session, "manage_users"):
                uname = input("  Username whose keys to revoke: ").strip()
                self.dp.revoke_key(uname)
                print(f"  ✓ Keys for '{uname}' have been revoked.")

        elif choice == "5":
            if self.ac.require_permission(self.session, "view_audit_log"):
                log_path = Path("logs/auth_audit.log")
                if log_path.exists():
                    lines = log_path.read_text().splitlines()
                    print("\n  --- Auth Audit Log (last 20) ---")
                    for line in lines[-20:]:
                        print(f"  {line}")
                else:
                    print("  No audit log found.")

        elif choice == "6":
            if self.ac.require_permission(self.session, "view_all_grades"):
                all_grades = self.pdata.get_all_grades()
                for student, gs in all_grades.items():
                    print(f"\n  Student: {student}")
                    self._print_table(
                        ["Module", "Grade", "Recorded By"],
                        [[g.get("module","?"), g.get("grade","?"), g.get("recorded_by","?")]
                         for g in gs],
                    )

        elif choice == "7":
            if self.ac.require_permission(self.session, "monitor_system"):
                print("\n  System Paths:")
                print("  Data store     : data/")
                print("  Key store      : data/keys/")
                print("  Encrypted data : data/encrypted/")
                print("  Audit log      : logs/auth_audit.log")
                print("  User store     : data/users.json (hashed passwords only)")

        elif choice == "8":
            self._do_logout()

    # ── Utility ──────────────────────────────────────────────────────────────

    @staticmethod
    def _print_table(headers: list, rows: list) -> None:
        widths = [max(len(h), max((len(str(r[i])) for r in rows), default=0))
                  for i, h in enumerate(headers)]
        sep  = "  +" + "+".join("-" * (w + 2) for w in widths) + "+"
        head = "  |" + "|".join(f" {h:<{widths[i]}} " for i, h in enumerate(headers)) + "|"
        print(sep)
        print(head)
        print(sep)
        for row in rows:
            print("  |" + "|".join(f" {str(row[i]):<{widths[i]}} " for i in range(len(headers))) + "|")
        print(sep)
