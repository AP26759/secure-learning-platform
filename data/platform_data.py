"""
data/platform_data.py
=====================
Business-logic layer: grades, assignments, feedback, secure messaging.

All sensitive data is passed through DataProtector for encryption before
persistence, and decrypted on retrieval.  HMAC tags guard record integrity.
"""

import json
import logging
from pathlib import Path
from datetime import datetime

from crypto.data_protector import DataProtector

logger = logging.getLogger(__name__)

GRADES_FILE      = Path("data/grades.json")
ASSIGNMENTS_FILE = Path("data/assignments.json")
MESSAGES_FILE    = Path("data/messages.json")


def _load_json(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {}


def _save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


class PlatformData:
    """
    Manages encrypted storage and retrieval of grades, assignments, and
    secure messages.  Integrity is verified on every read.
    """

    def __init__(self, data_protector: DataProtector):
        self.dp = data_protector

    # -- Grades -----------------------------------------------------------------

    def record_grade(self, student: str, module: str, grade: str,
                     recorded_by: str) -> None:
        """
        Store an encrypted grade record.
        The module name AND grade are both included inside the AES-256-GCM
        ciphertext so no plaintext course information is visible on disk.
        The dict key is an HMAC-derived opaque identifier.
        """
        grades = _load_json(GRADES_FILE)
        if student not in grades:
            grades[student] = {}

        # Module name is inside the payload -- not exposed as a JSON key
        payload = json.dumps({
            "module":      module,
            "grade":       grade,
            "recorded_by": recorded_by,
            "timestamp":   datetime.utcnow().isoformat(),
        })
        enc_record = self.dp.encrypt(payload, associated_data=student.encode())
        # HMAC integrity tag over the ciphertext bytes
        integrity_tag = self.dp.compute_hmac(enc_record["ciphertext"])
        enc_record["integrity_tag"] = integrity_tag

        # RSA digital signature by the recording lecturer (Lab 7 — non-repudiation).
        # The lecturer signs the plaintext payload so the student can later verify
        # that the grade was genuinely issued by that lecturer and has not been altered.
        if not self.dp.is_key_revoked(recorded_by):
            try:
                enc_record["signature"]    = self.dp.sign_data(payload, recorded_by)
                enc_record["signed_by"]    = recorded_by
            except FileNotFoundError:
                # Lecturer has no RSA key pair yet — signature omitted gracefully
                logger.warning("No RSA key for lecturer '%s'; grade recorded without signature.", recorded_by)
        else:
            logger.warning("Lecturer '%s' key is revoked; grade recorded without signature.", recorded_by)

        # Opaque record key -- HMAC(student:module), truncated to 16 hex chars
        record_key = self.dp.compute_hmac(f"{student}:{module}")[:16]
        grades[student][record_key] = enc_record
        _save_json(GRADES_FILE, grades)
        logger.info("Grade recorded: student=%s module=%s by=%s", student, module, recorded_by)

    def get_grades(self, student: str) -> list:
        """
        Return decrypted grades for `student`, verifying integrity of each.
        """
        grades = _load_json(GRADES_FILE)
        student_grades = grades.get(student, {})
        results = []
        for record_key, enc_record in student_grades.items():
            enc_copy = dict(enc_record)
            tag = enc_copy.pop("integrity_tag", None)
            if tag and not self.dp.verify_hmac(enc_copy["ciphertext"], tag):
                logger.error("INTEGRITY FAILURE for %s / key=%s", student, record_key)
                results.append({"module": "UNKNOWN", "error": "Integrity check failed!"})
                continue
            try:
                payload_str = self.dp.decrypt(enc_copy)
                payload     = json.loads(payload_str)

                # Verify the lecturer's RSA signature if one is present (Lab 7).
                # This confirms the grade was genuinely issued by the named lecturer
                # and has not been modified since signing.
                sig     = enc_record.get("signature")
                signer  = enc_record.get("signed_by")
                if sig and signer:
                    if self.dp.is_key_revoked(signer):
                        payload["signature_status"] = "REVOKED — signer key revoked"
                    elif self.dp.verify_signature(payload_str, sig, signer):
                        payload["signature_status"] = f"VERIFIED (signed by {signer})"
                    else:
                        payload["signature_status"] = "INVALID SIGNATURE — possible tampering"
                else:
                    payload["signature_status"] = "No signature"

                results.append(payload)
            except ValueError as e:
                results.append({"module": "UNKNOWN", "error": str(e)})
        return results

    def get_all_grades(self) -> dict:
        """Return decrypted grades for all students (lecturer/admin access)."""
        grades = _load_json(GRADES_FILE)
        return {student: self.get_grades(student) for student in grades}

    # -- Assignments ------------------------------------------------------------

    def submit_assignment(self, student: str, module: str, content: str) -> str:
        """
        Encrypt and store an assignment submission.
        Returns the assignment ID.
        """
        assignments = _load_json(ASSIGNMENTS_FILE)
        assign_id   = f"{student}_{module}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        payload    = json.dumps({"content": content, "student": student, "module": module,
                                 "submitted_at": datetime.utcnow().isoformat()})
        enc_record = self.dp.encrypt(payload, associated_data=student.encode())
        enc_record["integrity_tag"] = self.dp.compute_hmac(enc_record["ciphertext"])

        assignments[assign_id] = enc_record
        _save_json(ASSIGNMENTS_FILE, assignments)
        logger.info("Assignment submitted: id=%s", assign_id)
        return assign_id

    def get_assignments(self, student: str = None) -> list:
        """
        Retrieve and decrypt assignments.
        If `student` is given, returns only that student's submissions.
        """
        assignments = _load_json(ASSIGNMENTS_FILE)
        results     = []
        for assign_id, enc_record in assignments.items():
            enc_copy = dict(enc_record)
            tag = enc_copy.pop("integrity_tag", None)
            if tag and not self.dp.verify_hmac(enc_copy["ciphertext"], tag):
                results.append({"id": assign_id, "error": "Integrity failure"})
                continue
            try:
                payload = json.loads(self.dp.decrypt(enc_copy))
            except ValueError as e:
                results.append({"id": assign_id, "error": str(e)})
                continue
            # Filter by owner using the student field stored inside the encrypted payload
            if student and payload.get("student") != student:
                continue
            results.append({"id": assign_id, **payload})
        return results

    # -- Secure messaging -------------------------------------------------------

    def send_message(self, sender: str, recipient: str, body: str) -> None:
        """
        Encrypt a message with the recipient's RSA public key so that only
        they can decrypt it, then store it.
        """
        try:
            ct = self.dp.rsa_encrypt(body, recipient)
        except FileNotFoundError:
            logger.error("No public key for recipient '%s'.", recipient)
            raise

        messages  = _load_json(MESSAGES_FILE)
        if recipient not in messages:
            messages[recipient] = []

        messages[recipient].append({
            "from":       sender,
            "ciphertext": ct,
            "sent_at":    datetime.utcnow().isoformat(),
        })
        _save_json(MESSAGES_FILE, messages)
        logger.info("Message sent: from=%s to=%s", sender, recipient)

    def read_messages(self, recipient: str) -> list:
        """Decrypt and return all messages for `recipient`."""
        messages = _load_json(MESSAGES_FILE)
        inbox    = messages.get(recipient, [])
        results  = []
        for msg in inbox:
            try:
                plaintext = self.dp.rsa_decrypt(msg["ciphertext"], recipient)
                results.append({
                    "from":    msg["from"],
                    "body":    plaintext,
                    "sent_at": msg["sent_at"],
                })
            except Exception as e:
                results.append({"from": msg.get("from"), "error": str(e)})
        return results
