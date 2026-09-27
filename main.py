"""
Secure Online Learning Platform - Main Entry Point
WM242-24: Implementing Secure Systems | Coursework 1
"""

from auth.auth_manager import AuthManager
from rbac.access_control import AccessControl
from crypto.data_protector import DataProtector
from ui.cli import CLI


def main():
    """Initialise all subsystems and launch the CLI."""
    print("=" * 60)
    print("  Secure Online Learning Platform")
    print("  WM242-24 — Implementing Secure Systems")
    print("=" * 60)

    # Initialise core subsystems
    data_protector = DataProtector()
    auth_manager   = AuthManager(data_protector)
    access_control = AccessControl()
    cli            = CLI(auth_manager, access_control, data_protector)

    # Seed demo accounts on first run
    auth_manager.seed_demo_users()

    # Start the interactive menu
    cli.run()


if __name__ == "__main__":
    main()
