import os
import pyotp
from lib.vault import Vault

def test_vault_init(db_file):
    with Vault(db_file) as vault:
        assert os.path.exists(db_file)
        assert not vault.vault_exists()

def test_vault_create_and_unlock(vault):
    master_pw = "CorrectHorseBatteryStaple123!"
    twofa_secret = pyotp.random_base32()
    dek = vault.create_vault(master_pw, twofa_secret)
    assert dek is not None
    assert vault.vault_exists()

    # Unlock vault
    totp = pyotp.TOTP(twofa_secret)
    code = totp.now()
    unlocked_dek = vault.unlock_vault(master_pw, code)
    assert unlocked_dek == dek

def test_vault_unlock_failure(vault):
    master_pw = "CorrectHorseBatteryStaple123!"
    twofa_secret = pyotp.random_base32()
    vault.create_vault(master_pw, twofa_secret)

    # Wrong password
    assert vault.unlock_vault("wrong", "000000") is None

def test_vault_lockout(vault):
    master_pw = "CorrectHorseBatteryStaple123!"
    twofa_secret = pyotp.random_base32()
    vault.create_vault(master_pw, twofa_secret)

    assert vault.get_failed_attempts() == 0
    vault.record_failed_login(3, 60)
    assert vault.get_failed_attempts() == 1
    assert not vault.is_login_locked()

    vault.record_failed_login(3, 60)
    assert vault.get_failed_attempts() == 2
    
    vault.record_failed_login(3, 60)
    assert vault.get_failed_attempts() == 0  # Resets on lockout
    assert vault.is_login_locked()
    assert vault.login_lock_remaining() > 0

    vault.reset_failed_logins()
    assert not vault.is_login_locked()
    assert vault.get_failed_attempts() == 0

def test_vault_entries(vault):
    dek = b"a" * 32
    vault.add_vault_entry("Service1", "User1", "Pass1", "Secret1", dek)
    entries = vault.get_vault_entries()
    assert len(entries) == 1
    assert entries[0].id == 1

    # Update entry
    vault.update_vault_entry(1, "Service1", "User1", "NewPass", "Secret1", dek)
    entries = vault.get_vault_entries()
    assert len(entries) == 1

    # Delete entry
    vault.delete_vault_entry(1)
    assert len(vault.get_vault_entries()) == 0

def test_vault_metadata(vault):
    vault.meta_set_text("test_key", "test_value")
    assert vault.meta_get_text("test_key") == "test_value"
    
    vault.meta_set("binary_key", b"\x00\x01\x02")
    assert vault.meta_get("binary_key") == b"\x00\x01\x02"

def test_validate_master_password():
    # Valid
    valid, msg = Vault.validate_master_password("StrongPass123!")
    assert valid
    assert msg == ""

    # Too short
    valid, msg = Vault.validate_master_password("Short1!")
    assert not valid
    assert "at least 12 characters" in msg

    # No uppercase
    valid, msg = Vault.validate_master_password("strongpass123!")
    assert not valid
    assert "uppercase" in msg

    # No lowercase
    valid, msg = Vault.validate_master_password("STRONGPASS123!")
    assert not valid
    assert "lowercase" in msg

    # No number
    valid, msg = Vault.validate_master_password("StrongPass!!!")
    assert not valid
    assert "number" in msg

    # No special
    valid, msg = Vault.validate_master_password("StrongPass123")
    assert not valid
    assert "special character" in msg

def test_derive_backup_key():
    password = "backup_password"
    salt = os.urandom(16)
    key1 = Vault.derive_backup_key(password, salt)
    key2 = Vault.derive_backup_key(password, salt)
    
    assert len(key1) == 32
    assert key1 == key2
