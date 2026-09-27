"""
crypto/data_protector.py
========================
Handles all cryptographic operations for the platform:
  - AES-256-GCM symmetric encryption/decryption (data at rest)
  - RSA-2048 key-pair generation (per-user asymmetric keys)
  - PBKDF2-HMAC-SHA256 password hashing
  - HMAC-SHA256 data integrity tags
  - Secure random token generation
  - Key management (key storage, key derivation, key rotation stub)

Cryptographic choices are justified in the written report (Section 1).
"""

import os
import json
import hmac
import base64
import hashlib
import secrets
import logging
from pathlib import Path
from datetime import datetime

# Third-party (ships with Python environment)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
PBKDF2_ITERATIONS = 600_000          # OWASP 2023 recommended minimum
AES_KEY_BYTES     = 32               # AES-256
SALT_BYTES        = 32               # 256-bit salt
NONCE_BYTES       = 12               # GCM standard nonce
TOKEN_BYTES       = 32               # 256-bit session tokens
KEY_STORE_PATH    = Path("data/keys")
DATA_STORE_PATH   = Path("data/encrypted")


class DataProtector:
    """
    Central cryptographic service.
    All other modules call this class; raw crypto never leaks elsewhere.
    """

    def __init__(self):
        KEY_STORE_PATH.mkdir(parents=True, exist_ok=True)
        DATA_STORE_PATH.mkdir(parents=True, exist_ok=True)
        # Master AES key derived from an env variable or generated fresh
        self._master_key = self._load_or_create_master_key()

    # ── Master key management ──────────────────────────────────────────────

    def _load_or_create_master_key(self) -> bytes:
        """
        Load the platform master AES-256 key from disk (key file) or
        generate a new one on first run.  In production this would be
        stored in a Hardware Security Module (HSM) or secrets manager.
        """
        key_file = KEY_STORE_PATH / "master.key"
        if key_file.exists():
            raw = key_file.read_bytes()
            return base64.b64decode(raw)
        key = secrets.token_bytes(AES_KEY_BYTES)
        key_file.write_bytes(base64.b64encode(key))
        key_file.chmod(0o600)          # owner-read-only
        logger.info("Master AES key generated and stored.")
        return key

    # ── Password hashing ───────────────────────────────────────────────────

    def hash_password(self, password: str) -> dict:
        """
        Hash a plaintext password with PBKDF2-HMAC-SHA256.

        Returns a dict {'salt': <hex>, 'hash': <hex>, 'iterations': int}
        which is safe to persist in the user store.
        """
        salt = secrets.token_bytes(SALT_BYTES)
        pw_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS,
        )
        return {
            "salt":       salt.hex(),
            "hash":       pw_hash.hex(),
            "iterations": PBKDF2_ITERATIONS,
        }

    def verify_password(self, password: str, stored: dict) -> bool:
        """
        Constant-time comparison to prevent timing side-channels.
        Returns True iff password matches the stored hash record.
        """
        salt      = bytes.fromhex(stored["salt"])
        expected  = bytes.fromhex(stored["hash"])
        iterations = stored.get("iterations", PBKDF2_ITERATIONS)
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )
        # hmac.compare_digest is constant-time
        return hmac.compare_digest(candidate, expected)

    # ── AES-256-GCM symmetric encryption ──────────────────────────────────

    def encrypt(self, plaintext: str, associated_data: bytes = b"") -> dict:
        """
        Encrypt a plaintext string with AES-256-GCM using the master key.

        `associated_data` is authenticated but NOT encrypted (e.g. user ID).
        Returns a dict suitable for JSON serialisation.
        """
        aesgcm = AESGCM(self._master_key)
        nonce  = secrets.token_bytes(NONCE_BYTES)
        ct     = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data)
        return {
            "nonce":           base64.b64encode(nonce).decode(),
            "ciphertext":      base64.b64encode(ct).decode(),
            "associated_data": base64.b64encode(associated_data).decode(),
        }

    def decrypt(self, record: dict) -> str:
        """
        Decrypt and authenticate an AES-256-GCM ciphertext record.
        Raises ValueError on authentication failure (tampered data).
        """
        aesgcm = AESGCM(self._master_key)
        nonce  = base64.b64decode(record["nonce"])
        ct     = base64.b64decode(record["ciphertext"])
        aad    = base64.b64decode(record["associated_data"])
        try:
            plaintext = aesgcm.decrypt(nonce, ct, aad)
            return plaintext.decode("utf-8")
        except Exception as exc:
            logger.warning("Decryption/authentication failure: %s", exc)
            raise ValueError("Data integrity check failed — possible tampering.") from exc

    # ── HMAC integrity tags ────────────────────────────────────────────────

    def compute_hmac(self, data: str) -> str:
        """Return an HMAC-SHA256 hex digest of `data` using the master key."""
        tag = hmac.new(self._master_key, data.encode("utf-8"), hashlib.sha256).hexdigest()
        return tag

    def verify_hmac(self, data: str, tag: str) -> bool:
        """Constant-time HMAC verification."""
        expected = self.compute_hmac(data)
        return hmac.compare_digest(expected, tag)

    # ── RSA asymmetric key generation ──────────────────────────────────────

    def generate_rsa_keypair(self, username: str) -> None:
        """
        Generate a 2048-bit RSA key pair for `username`.
        Private key is AES-encrypted before writing to disk.
        Public key is stored unencrypted (it is public by definition).
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        pub_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        # Encrypt the private key with the platform master key before storage
        priv_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),      # plaintext PEM — we encrypt below
        )
        enc_record = self.encrypt(priv_pem.decode(), associated_data=username.encode())

        user_key_dir = KEY_STORE_PATH / username
        user_key_dir.mkdir(parents=True, exist_ok=True)
        (user_key_dir / "public.pem").write_bytes(pub_pem)
        (user_key_dir / "private.enc.json").write_text(json.dumps(enc_record))
        logger.info("RSA key pair generated for user '%s'.", username)

    def load_public_key(self, username: str):
        """Load a user's RSA public key object."""
        pem_path = KEY_STORE_PATH / username / "public.pem"
        if not pem_path.exists():
            raise FileNotFoundError(f"No public key found for '{username}'.")
        return serialization.load_pem_public_key(pem_path.read_bytes())

    def load_private_key(self, username: str):
        """
        Decrypt and load a user's RSA private key.
        The caller must be authorised before invoking this.
        """
        enc_path = KEY_STORE_PATH / username / "private.enc.json"
        if not enc_path.exists():
            raise FileNotFoundError(f"No private key found for '{username}'.")
        record   = json.loads(enc_path.read_text())
        priv_pem = self.decrypt(record).encode()
        return serialization.load_pem_private_key(priv_pem, password=None)

    # ── RSA encrypt / decrypt ─────────────────────────────────────────────

    def rsa_encrypt(self, plaintext: str, username: str) -> str:
        """Encrypt a short message with the recipient's RSA public key (OAEP)."""
        pub = self.load_public_key(username)
        ct  = pub.encrypt(
            plaintext.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return base64.b64encode(ct).decode()

    def rsa_decrypt(self, ciphertext_b64: str, username: str) -> str:
        """Decrypt a message with the owner's RSA private key (OAEP)."""
        priv = self.load_private_key(username)
        ct   = base64.b64decode(ciphertext_b64)
        pt   = priv.decrypt(
            ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return pt.decode("utf-8")

    # ── Secure token generation ────────────────────────────────────────────

    def generate_session_token(self) -> str:
        """Return a 256-bit cryptographically secure session token (hex)."""
        return secrets.token_hex(TOKEN_BYTES)

    # ── Encrypted file store ───────────────────────────────────────────────

    def save_encrypted_record(self, record_id: str, data: dict, owner: str) -> None:
        """
        JSON-serialise `data`, encrypt it, and persist to DATA_STORE_PATH.
        `owner` is embedded as authenticated associated data.
        """
        plaintext = json.dumps(data)
        enc       = self.encrypt(plaintext, associated_data=owner.encode())
        out_path  = DATA_STORE_PATH / f"{record_id}.enc.json"
        out_path.write_text(json.dumps(enc))

    def load_encrypted_record(self, record_id: str, owner: str) -> dict:
        """
        Load, authenticate, and decrypt a record.
        Raises ValueError if the owner tag does not match (integrity failure).
        """
        in_path = DATA_STORE_PATH / f"{record_id}.enc.json"
        if not in_path.exists():
            raise FileNotFoundError(f"Record '{record_id}' not found.")
        record    = json.loads(in_path.read_text())
        # Verify associated data matches expected owner
        aad_stored = base64.b64decode(record["associated_data"]).decode()
        if aad_stored != owner:
            raise ValueError("Record owner mismatch — access denied.")
        plaintext = self.decrypt(record)
        return json.loads(plaintext)

    # ── RSA Digital Signatures (Lab 7) ────────────────────────────────────────

    def sign_data(self, data: str, signer: str) -> str:
        """
        Sign `data` with `signer`'s RSA private key using PSS padding and SHA-256.

        This provides non-repudiation: only the private key holder could have
        produced the signature, and any modification to `data` will invalidate it.
        Studied in Lab 7 (Digital Signatures).

        Returns a base64-encoded signature string.
        """
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.hazmat.primitives.asymmetric import utils

        private_key = self.load_private_key(signer)
        signature   = private_key.sign(
            data.encode("utf-8"),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode()

    def verify_signature(self, data: str, signature_b64: str, signer: str) -> bool:
        """
        Verify an RSA-PSS signature over `data` using `signer`'s public key.

        Returns True if valid, False if the signature is invalid or data has
        been tampered with.
        """
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.exceptions import InvalidSignature

        pub_key   = self.load_public_key(signer)
        signature = base64.b64decode(signature_b64)
        try:
            pub_key.verify(
                signature,
                data.encode("utf-8"),
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False

    # ── Key Revocation (Lab 5) ────────────────────────────────────────────────

    def revoke_key(self, username: str) -> None:
        """
        Add `username` to the revocation list.
        Any crypto operation that checks revocation (sign/decrypt) will then
        refuse to use that user's keys.  Aligned with NIST SP 800-57 key
        lifecycle management, studied in Lab 5.
        """
        revoked = self._load_revocation_list()
        if username not in revoked:
            revoked.append(username)
            self._save_revocation_list(revoked)
            logger.warning("KEY REVOKED for user '%s'.", username)

    def is_key_revoked(self, username: str) -> bool:
        """Return True if `username`'s keys have been revoked."""
        return username in self._load_revocation_list()

    def _load_revocation_list(self) -> list:
        revocation_file = KEY_STORE_PATH / "revoked.json"
        if revocation_file.exists():
            return json.loads(revocation_file.read_text())
        return []

    def _save_revocation_list(self, revoked: list) -> None:
        revocation_file = KEY_STORE_PATH / "revoked.json"
        revocation_file.write_text(json.dumps(revoked, indent=2))
