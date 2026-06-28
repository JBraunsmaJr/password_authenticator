import sqlite3
import os
import time
import re
from typing import Optional, List, Any
import pyotp
from argon2.low_level import hash_secret_raw, Type
from lib.crypto import encrypt_bytes, decrypt_bytes, encrypt_record, derive_key
from lib.models import VaultEntry, VaultEntryData


class Vault:
    def __init__(self, db_file: str):
        self.db_file = db_file
        self.conn = sqlite3.connect(self.db_file)
        self.init_db()

    def init_db(self):
        """Initializes the database schema if it doesn't exist."""
        with self.conn:
            self.conn.execute("PRAGMA secure_delete = ON")
            self.conn.execute("PRAGMA journal_mode = WAL")
            self.conn.execute("""
                              CREATE TABLE IF NOT EXISTS vault_meta
                              (
                                  key   TEXT PRIMARY KEY,
                                  value BLOB NOT NULL
                              )
                              """)
            self.conn.execute("""
                              CREATE TABLE IF NOT EXISTS vault_entries
                              (
                                  id         INTEGER PRIMARY KEY AUTOINCREMENT,
                                  nonce      BLOB NOT NULL,
                                  ciphertext BLOB NOT NULL
                              )
                              """)

    def close(self):
        """Closes the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def meta_get(self, key: str) -> Optional[bytes]:
        """Retrieves a binary value from the vault metadata."""
        cur = self.conn.execute("SELECT value FROM vault_meta WHERE key = ?", (key,))
        row = cur.fetchone()
        return row[0] if row else None

    def meta_set(self, key: str, value: bytes):
        """Stores a binary value in the vault metadata."""
        with self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO vault_meta (key, value)
                VALUES (?, ?)
            """, (key, value))

    def meta_get_text(self, key: str, default: str = "") -> str:
        """Retrieves a text value from the vault metadata."""
        value = self.meta_get(key)
        return value.decode() if value is not None else default

    def meta_set_text(self, key: str, value: Any):
        """Stores a text value in the vault metadata."""
        self.meta_set(key, str(value).encode())

    def get_lockout_until(self) -> int:
        """Gets the timestamp until which login is locked."""
        try:
            return int(self.meta_get_text("lockout_until", "0"))
        except ValueError:
            return 0

    def get_failed_attempts(self) -> int:
        """Gets the number of failed login attempts."""
        try:
            return int(self.meta_get_text("failed_attempts", "0"))
        except ValueError:
            return 0

    def is_login_locked(self) -> bool:
        """Checks if the login is currently locked."""
        return int(time.time()) < self.get_lockout_until()

    def login_lock_remaining(self) -> int:
        """Returns the remaining lockout time in seconds."""
        return max(0, self.get_lockout_until() - int(time.time()))

    def record_failed_login(self, max_attempts: int, lockout_seconds: int):
        """Records a failed login attempt and handles lockout logic."""
        attempts = self.get_failed_attempts() + 1
        if attempts >= max_attempts:
            self.meta_set_text("failed_attempts", 0)
            self.meta_set_text("lockout_until", int(time.time()) + lockout_seconds)
        else:
            self.meta_set_text("failed_attempts", attempts)

    def reset_failed_logins(self):
        """Resets failed login attempts and lockout."""
        self.meta_set_text("failed_attempts", 0)
        self.meta_set_text("lockout_until", 0)

    def vault_exists(self) -> bool:
        """Checks if a vault has been initialized."""
        return self.meta_get("encrypted_dek") is not None

    def create_vault(self, master_password: str, twofa_secret: str) -> bytes:
        """Creates a new vault with the given master password and 2FA secret."""
        kdf_salt = os.urandom(16)
        time_cost = 3
        memory_cost = 262144  # 256MB
        parallelism = 4

        kek = derive_key(master_password, kdf_salt, time_cost, memory_cost, parallelism)
        dek = os.urandom(32)

        dek_nonce, encrypted_dek = encrypt_bytes(kek, dek)
        twofa_nonce, encrypted_twofa_secret = encrypt_bytes(dek, twofa_secret.encode())

        self.meta_set("kdf_salt", kdf_salt)
        self.meta_set("dek_nonce", dek_nonce)
        self.meta_set("encrypted_dek", encrypted_dek)
        self.meta_set("twofa_nonce", twofa_nonce)
        self.meta_set("encrypted_twofa_secret", encrypted_twofa_secret)

        self.meta_set_text("argon2_time", time_cost)
        self.meta_set_text("argon2_mem", memory_cost)
        self.meta_set_text("argon2_par", parallelism)

        self.reset_failed_logins()
        return dek

    def unlock_vault(self, master_password: str, twofa_code: str) -> Optional[bytes]:
        """Attempts to unlock the vault and returns the DEK if successful."""
        if self.is_login_locked():
            return None

        kdf_salt = self.meta_get("kdf_salt")
        dek_nonce = self.meta_get("dek_nonce")
        encrypted_dek = self.meta_get("encrypted_dek")

        if not kdf_salt or not dek_nonce or not encrypted_dek:
            return None

        time_cost = int(self.meta_get_text("argon2_time", "3"))
        memory_cost = int(self.meta_get_text("argon2_mem", "65536"))
        parallelism = int(self.meta_get_text("argon2_par", "2"))

        kek = derive_key(master_password, kdf_salt, time_cost, memory_cost, parallelism)

        try:
            dek = decrypt_bytes(kek, dek_nonce, encrypted_dek)
        except Exception:
            return None

        twofa_nonce = self.meta_get("twofa_nonce")
        encrypted_twofa_secret = self.meta_get("encrypted_twofa_secret")

        if not twofa_nonce or not encrypted_twofa_secret:
            return None

        try:
            twofa_secret = decrypt_bytes(dek, twofa_nonce, encrypted_twofa_secret).decode()
        except Exception:
            return None

        if not pyotp.TOTP(twofa_secret).verify(twofa_code, valid_window=1):
            return None

        return dek

    def add_vault_entry(self, service: str, username: str, password: str, secret: str, dek: bytes):
        """Adds a new encrypted entry to the vault."""
        data = VaultEntryData(
            service=service,
            username=username,
            password=password,
            secret=secret
        )
        nonce, ciphertext = encrypt_record(dek, data)
        with self.conn:
            self.conn.execute("""
                              INSERT INTO vault_entries (nonce, ciphertext)
                              VALUES (?, ?)
                              """, (nonce, ciphertext))

    def update_vault_entry(self, entry_id: int, service: str, username: str, password: str, secret: str, dek: bytes):
        """Updates an existing encrypted entry in the vault."""
        data = VaultEntryData(
            service=service,
            username=username,
            password=password,
            secret=secret
        )
        nonce, ciphertext = encrypt_record(dek, data)
        with self.conn:
            self.conn.execute("""
                              UPDATE vault_entries
                              SET nonce      = ?,
                                  ciphertext = ?
                              WHERE id = ?
                              """, (nonce, ciphertext, entry_id))

    def get_vault_entries(self) -> List[VaultEntry]:
        """Retrieves all encrypted entries from the vault."""
        cur = self.conn.execute("SELECT id, nonce, ciphertext FROM vault_entries ORDER BY id")
        rows = cur.fetchall()
        return [VaultEntry(id=row[0], nonce=row[1], ciphertext=row[2]) for row in rows]

    def delete_vault_entry(self, entry_id: int):
        """Deletes an entry from the vault."""
        with self.conn:
            self.conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))

    @staticmethod
    def validate_master_password(password: str) -> tuple[bool, str]:
        """Validates the complexity of the master password."""
        if len(password) < 12:
            return False, "Master password must be at least 12 characters long."

        if not re.search(r"[A-Z]", password):
            return False, "Master password must contain at least one uppercase letter."

        if not re.search(r"[a-z]", password):
            return False, "Master password must contain at least one lowercase letter."

        if not re.search(r"\d", password):
            return False, "Master password must contain at least one number."

        if not re.search(r"[^A-Za-z0-9]", password):
            return False, "Master password must contain at least one special character."

        return True, ""

    @staticmethod
    def derive_backup_key(backup_password: str, salt: bytes, time_cost: int = 3, memory_cost: int = 262144,
                          parallelism: int = 4) -> bytes:
        """Derives a key for encrypting/decrypting backups."""
        return hash_secret_raw(
            secret=backup_password.encode(),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32,
            type=Type.ID
        )
