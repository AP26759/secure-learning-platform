"""
tests/test_platform.py
=======================
Automated test suite for the Secure Online Learning Platform.
Covers:
  - Password hashing correctness and timing-safe comparison
  - AES-256-GCM encryption round-trip and tamper detection
  - HMAC integrity tag generation and verification
  - RSA key-pair generation and message encryption/decryption
  - Login success, login failure, and account lockout
  - RBAC permission matrix (grants and denials for all roles)
  - Grade encryption and retrieval (module name NOT stored in plaintext)
  - Assignment submission and retrieval
  - Secure messaging (RSA end-to-end)
  - Cross-role data isolation (students cannot see other students' grades)
  - Session token invalidation after logout
"""

import sys
import json
import shutil
import tempfile
import unittest
from pathlib import Path

# ── Bootstrap: point to project root ────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Redirect all persistent storage to a temporary directory so tests are isolated
_TMPDIR = tempfile.mkdtemp(prefix="slp_test_")

import data.platform_data as _pd_module
import auth.auth_manager  as _am_module
import crypto.data_protector as _dp_module

_pd_module.GRADES_FILE       = Path(_TMPDIR) / "grades.json"
_pd_module.ASSIGNMENTS_FILE  = Path(_TMPDIR) / "assignments.json"
_pd_module.MESSAGES_FILE     = Path(_TMPDIR) / "messages.json"
_am_module.USER_STORE        = Path(_TMPDIR) / "users.json"
_am_module.AUDIT_LOG         = Path(_TMPDIR) / "audit.log"
_dp_module.KEY_STORE_PATH    = Path(_TMPDIR) / "keys"
_dp_module.DATA_STORE_PATH   = Path(_TMPDIR) / "encrypted"

from crypto.data_protector import DataProtector
from auth.auth_manager      import AuthManager
from rbac.access_control    import AccessControl
from data.platform_data     import PlatformData

# Shared instances (one DataProtector, one AuthManager for the whole suite)
_DP   = DataProtector()
_AUTH = AuthManager(_DP)
_AC   = AccessControl()
_PD   = PlatformData(_DP)


def _reg(username, password="Test@1234!", role="student"):
    """Register a user only if not already registered."""
    _AUTH.register_user(username, password, role)


# =============================================================================
# 1. Cryptographic unit tests
# =============================================================================

class TestPasswordHashing(unittest.TestCase):

    def test_hash_returns_required_keys(self):
        rec = _DP.hash_password("SecurePass1!")
        for key in ("salt", "hash", "iterations"):
            self.assertIn(key, rec)

    def test_correct_password_verifies(self):
        rec = _DP.hash_password("MyP@ssw0rd")
        self.assertTrue(_DP.verify_password("MyP@ssw0rd", rec))

    def test_wrong_password_fails(self):
        rec = _DP.hash_password("MyP@ssw0rd")
        self.assertFalse(_DP.verify_password("WrongPass1", rec))

    def test_unique_salts_produce_unique_hashes(self):
        r1 = _DP.hash_password("SamePass1!")
        r2 = _DP.hash_password("SamePass1!")
        self.assertNotEqual(r1["hash"], r2["hash"])
        self.assertNotEqual(r1["salt"], r2["salt"])


class TestAESEncryption(unittest.TestCase):

    def test_encrypt_decrypt_roundtrip(self):
        pt  = "Sensitive student data"
        enc = _DP.encrypt(pt, b"alice")
        self.assertEqual(pt, _DP.decrypt(enc))

    def test_tampered_ciphertext_raises(self):
        import base64
        enc = _DP.encrypt("hello", b"alice")
        ct  = bytearray(base64.b64decode(enc["ciphertext"]))
        ct[5] ^= 0xFF
        enc["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        with self.assertRaises(ValueError):
            _DP.decrypt(enc)

    def test_wrong_associated_data_raises(self):
        import base64
        enc = _DP.encrypt("hello", b"alice")
        enc["associated_data"] = base64.b64encode(b"mallory").decode()
        with self.assertRaises(ValueError):
            _DP.decrypt(enc)


class TestHMAC(unittest.TestCase):

    def test_correct_data_verifies(self):
        tag = _DP.compute_hmac("important data")
        self.assertTrue(_DP.verify_hmac("important data", tag))

    def test_tampered_data_rejected(self):
        tag = _DP.compute_hmac("important data")
        self.assertFalse(_DP.verify_hmac("tampered data", tag))


class TestRSAKeyPair(unittest.TestCase):

    def setUp(self):
        _reg("rsa_testuser")

    def test_encrypt_decrypt_roundtrip(self):
        ct = _DP.rsa_encrypt("Secret message", "rsa_testuser")
        pt = _DP.rsa_decrypt(ct, "rsa_testuser")
        self.assertEqual("Secret message", pt)

    def test_missing_user_raises(self):
        with self.assertRaises(FileNotFoundError):
            _DP.rsa_encrypt("hello", "no_such_user_xyz")


# =============================================================================
# 2. Authentication tests
# =============================================================================

class TestAuthLoginSuccess(unittest.TestCase):
    """Isolated class so the lockout test cannot affect these."""

    def setUp(self):
        _reg("login_ok_user", "Test@1234!", "student")

    def test_login_returns_token(self):
        token = _AUTH.login("login_ok_user", "Test@1234!")
        self.assertIsNotNone(token)
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 32)

    def test_login_wrong_password_returns_none(self):
        token = _AUTH.login("login_ok_user", "WrongPass!")
        self.assertIsNone(token)

    def test_login_unknown_user_returns_none(self):
        token = _AUTH.login("nobody_xyz", "anything")
        self.assertIsNone(token)

    def test_session_valid_after_login(self):
        token   = _AUTH.login("login_ok_user", "Test@1234!")
        session = _AUTH.validate_session(token)
        self.assertIsNotNone(session)
        self.assertEqual(session["role"], "student")

    def test_session_invalidated_after_logout(self):
        token = _AUTH.login("login_ok_user", "Test@1234!")
        _AUTH.logout(token)
        self.assertIsNone(_AUTH.validate_session(token))

    def test_duplicate_registration_fails(self):
        ok = _AUTH.register_user("login_ok_user", "Other@123!", "student")
        self.assertFalse(ok)


class TestAuthLockout(unittest.TestCase):
    """Uses a dedicated user so lockout does not affect other tests."""

    def setUp(self):
        _reg("lockout_victim", "Test@1234!", "student")

    def test_lockout_after_five_failures(self):
        for _ in range(5):
            _AUTH.login("lockout_victim", "BadPass!")
        # After 5 failures the account is locked; correct password still fails
        token = _AUTH.login("lockout_victim", "Test@1234!")
        self.assertIsNone(token)


# =============================================================================
# 3. RBAC tests
# =============================================================================

class TestRBAC(unittest.TestCase):

    # Students
    def test_student_can_view_own_grades(self):
        self.assertTrue(_AC.is_allowed("student", "view_own_grades"))

    def test_student_can_upload_assignment(self):
        self.assertTrue(_AC.is_allowed("student", "upload_assignment"))

    def test_student_cannot_manage_users(self):
        self.assertFalse(_AC.is_allowed("student", "manage_users"))

    def test_student_cannot_view_audit_log(self):
        self.assertFalse(_AC.is_allowed("student", "view_audit_log"))

    def test_student_cannot_review_submissions(self):
        self.assertFalse(_AC.is_allowed("student", "review_submissions"))

    # Lecturers
    def test_lecturer_can_review_submissions(self):
        self.assertTrue(_AC.is_allowed("lecturer", "review_submissions"))

    def test_lecturer_can_give_feedback(self):
        self.assertTrue(_AC.is_allowed("lecturer", "give_feedback"))

    def test_lecturer_can_view_all_grades(self):
        self.assertTrue(_AC.is_allowed("lecturer", "view_all_grades"))

    def test_lecturer_cannot_manage_users(self):
        self.assertFalse(_AC.is_allowed("lecturer", "manage_users"))

    def test_lecturer_cannot_view_audit_log(self):
        self.assertFalse(_AC.is_allowed("lecturer", "view_audit_log"))

    # Admins
    def test_admin_can_manage_users(self):
        self.assertTrue(_AC.is_allowed("admin", "manage_users"))

    def test_admin_can_view_audit_log(self):
        self.assertTrue(_AC.is_allowed("admin", "view_audit_log"))

    def test_admin_can_monitor_system(self):
        self.assertTrue(_AC.is_allowed("admin", "monitor_system"))

    def test_admin_cannot_upload_assignment(self):
        self.assertFalse(_AC.is_allowed("admin", "upload_assignment"))

    # Unknown role
    def test_unknown_role_denied(self):
        self.assertFalse(_AC.is_allowed("intruder", "view_own_grades"))


# =============================================================================
# 4. Data layer tests
# =============================================================================

class TestGrades(unittest.TestCase):

    def setUp(self):
        _reg("alice_grade", "Alice@1234!", "student")

    def test_grade_recorded_and_retrieved(self):
        _PD.record_grade("alice_grade", "CS101", "A", "bob_lec")
        grades = _PD.get_grades("alice_grade")
        self.assertTrue(any(g.get("module") == "CS101" and g.get("grade") == "A"
                            for g in grades))

    def test_grade_and_module_name_encrypted_on_disk(self):
        _PD.record_grade("alice_grade", "SECRETMOD", "A+", "bob_lec")
        raw = _pd_module.GRADES_FILE.read_text()
        self.assertNotIn("A+",        raw, "Grade should not appear in plaintext")
        self.assertNotIn("SECRETMOD", raw, "Module name should not appear in plaintext")


class TestAssignments(unittest.TestCase):

    def setUp(self):
        _reg("charlie_assign", "Charlie@1234!", "student")

    def test_assignment_submitted_and_retrieved(self):
        _PD.submit_assignment("charlie_assign", "ENG101", "My essay content")
        subs = _PD.get_assignments("charlie_assign")
        self.assertTrue(any(s.get("content") == "My essay content" for s in subs))

    def test_assignment_content_encrypted_on_disk(self):
        _PD.submit_assignment("charlie_assign", "ENG202", "Top secret essay")
        raw = _pd_module.ASSIGNMENTS_FILE.read_text()
        self.assertNotIn("Top secret essay", raw)


class TestSecureMessaging(unittest.TestCase):

    def setUp(self):
        _reg("dave_msg",  "Dave@1234!",  "student")
        _reg("eve_msg",   "Eve@1234!",   "lecturer")

    def test_message_delivered_and_decrypted(self):
        _PD.send_message("dave_msg", "eve_msg", "Hello lecturer!")
        inbox = _PD.read_messages("eve_msg")
        self.assertTrue(any(m.get("body") == "Hello lecturer!" for m in inbox))

    def test_message_body_not_in_plaintext_on_disk(self):
        _PD.send_message("dave_msg", "eve_msg", "Confidential note")
        raw = _pd_module.MESSAGES_FILE.read_text()
        self.assertNotIn("Confidential note", raw)


# =============================================================================
# 5. Cross-role data isolation
# =============================================================================

class TestDataIsolation(unittest.TestCase):
    """Students should only retrieve their own grades."""

    def setUp(self):
        _reg("frank_iso", "Frank@1234!", "student")
        _reg("grace_iso", "Grace@1234!", "student")

    def test_student_cannot_see_other_student_grades(self):
        _PD.record_grade("frank_iso", "PHY101", "C+", "lec")
        _PD.record_grade("grace_iso", "PHY101", "A+", "lec")
        frank_grades = _PD.get_grades("frank_iso")
        self.assertFalse(any(g.get("grade") == "A+" for g in frank_grades),
                         "Frank should not see Grace's A+ grade")



# =============================================================================
# 6. Digital signature tests (Lab 7)
# =============================================================================

class TestDigitalSignatures(unittest.TestCase):
    """
    RSA-PSS digital signatures on grade records (Lab 7).
    A lecturer signs a grade payload; the student verifies it.
    """

    def setUp(self):
        _reg("sig_student", "Sig@1234!", "student")
        _reg("sig_lecturer", "Sig@1234!", "lecturer")

    def test_signature_verifies_correctly(self):
        payload = "test grade payload"
        sig = _DP.sign_data(payload, "sig_lecturer")
        self.assertTrue(_DP.verify_signature(payload, sig, "sig_lecturer"))

    def test_tampered_payload_fails_verification(self):
        payload = "original payload"
        sig = _DP.sign_data(payload, "sig_lecturer")
        self.assertFalse(_DP.verify_signature("tampered payload", sig, "sig_lecturer"))

    def test_grade_recorded_with_signature(self):
        _PD.record_grade("sig_student", "SIG101", "A", "sig_lecturer")
        grades = _PD.get_grades("sig_student")
        grade = next((g for g in grades if g.get("module") == "SIG101"), None)
        self.assertIsNotNone(grade)
        self.assertIn("VERIFIED", grade.get("signature_status", ""))

    def test_grade_signature_not_in_plaintext_on_disk(self):
        _PD.record_grade("sig_student", "SIG202", "B+", "sig_lecturer")
        raw = _pd_module.GRADES_FILE.read_text()
        # The grade itself must be encrypted; the signature is a base64 blob
        self.assertNotIn("B+", raw)


# =============================================================================
# 7. Key revocation tests (Lab 5)
# =============================================================================

class TestKeyRevocation(unittest.TestCase):
    """
    Key revocation list (Lab 5 — NIST SP 800-57 key lifecycle).
    Revoked keys should be refused for signing operations.
    """

    def setUp(self):
        _reg("revoke_lecturer", "Rev@1234!", "lecturer")

    def test_key_not_revoked_initially(self):
        self.assertFalse(_DP.is_key_revoked("revoke_lecturer"))

    def test_revocation_recorded(self):
        _DP.revoke_key("revoke_lecturer")
        self.assertTrue(_DP.is_key_revoked("revoke_lecturer"))

    def test_revoked_key_shows_in_grade_status(self):
        # Record grade before revocation so signature exists
        _reg("revoke_student", "Rev@1234!", "student")
        _reg("revoke_lec2", "Rev@1234!", "lecturer")
        _PD.record_grade("revoke_student", "REV101", "A", "revoke_lec2")
        # Now revoke the lecturer's key
        _DP.revoke_key("revoke_lec2")
        grades = _PD.get_grades("revoke_student")
        grade = next((g for g in grades if g.get("module") == "REV101"), None)
        self.assertIsNotNone(grade)
        self.assertIn("REVOKED", grade.get("signature_status", ""))


# =============================================================================
# Entry point
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  Secure Learning Platform — Automated Test Suite")
    print("=" * 60)
    loader = unittest.TestLoader()
    suite  = loader.loadTestsFromModule(__import__("__main__"))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    shutil.rmtree(_TMPDIR, ignore_errors=True)
    sys.exit(0 if result.wasSuccessful() else 1)
