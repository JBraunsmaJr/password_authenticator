import pytest
import os
from lib.crypto import (
    derive_key,
    encrypt_bytes,
    decrypt_bytes,
    encrypt_record,
    decrypt_record
)
from lib.models import VaultEntryData

def test_derive_key():
    password = "test_password"
    salt = b"test_salt_123456"
    key1 = derive_key(password, salt, time_cost=1, memory_cost=1024, parallelism=1)
    key2 = derive_key(password, salt, time_cost=1, memory_cost=1024, parallelism=1)
    
    assert len(key1) == 32
    assert key1 == key2
    
    # Different salt
    key3 = derive_key(password, b"different_salt!!", time_cost=1, memory_cost=1024, parallelism=1)
    assert key1 != key3

def test_encrypt_decrypt_bytes():
    key = os.urandom(32)
    plaintext = b"This is a secret message."
    
    nonce, ciphertext = encrypt_bytes(key, plaintext)
    assert len(nonce) == 12
    assert ciphertext != plaintext
    
    decrypted = decrypt_bytes(key, nonce, ciphertext)
    assert decrypted == plaintext

def test_encrypt_decrypt_record():
    dek = os.urandom(32)
    data = VaultEntryData(
        service="TestService",
        username="testuser",
        password="testpassword",
        secret="TESTSECRET"
    )
    
    nonce, ciphertext = encrypt_record(dek, data)
    decrypted_data = decrypt_record(dek, nonce, ciphertext)
    
    assert decrypted_data is not None
    assert decrypted_data.service == data.service
    assert decrypted_data.username == data.username
    assert decrypted_data.password == data.password
    assert decrypted_data.secret == data.secret

def test_encrypt_decrypt_record_dict():
    dek = os.urandom(32)
    data_dict = {
        "service": "TestService",
        "username": "testuser",
        "password": "testpassword",
        "secret": "TESTSECRET"
    }
    
    nonce, ciphertext = encrypt_record(dek, data_dict)
    decrypted_data = decrypt_record(dek, nonce, ciphertext)
    
    assert decrypted_data is not None
    assert decrypted_data.service == data_dict["service"]
    assert decrypted_data.username == data_dict["username"]

def test_decrypt_record_invalid_padding():
    dek = os.urandom(32)
    plaintext = b'{"service": "test"}'
    # Manual padding with wrong value
    pad_len = 64 - (len(plaintext) % 64)
    padded = plaintext + bytes([pad_len + 1] * pad_len)
    
    nonce, ciphertext = encrypt_bytes(dek, padded)
    
    # decrypt_record should handle padding error and return None (or raise if it bubbles up)
    with pytest.raises(ValueError, match="Invalid padding"):
        decrypt_record(dek, nonce, ciphertext)

def test_decrypt_record_wrong_key():
    dek = os.urandom(32)
    wrong_dek = os.urandom(32)
    data = VaultEntryData(service="test")
    
    nonce, ciphertext = encrypt_record(dek, data)
    
    # AESGCM decrypt will raise an exception with wrong key/nonce/ciphertext
    with pytest.raises(Exception):
        decrypt_record(wrong_dek, nonce, ciphertext)
