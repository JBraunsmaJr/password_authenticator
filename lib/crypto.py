import json
from typing import Optional, Union, Any

from lib.models import VaultEntryData
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def derive_key(
    master_password: str,
    salt: bytes,
    time_cost: int = 3,
    memory_cost: int = 65536,
    parallelism: int = 2
) -> bytes:
    return hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID
    )

def encrypt_bytes(key: bytes, plaintext_bytes: bytes) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return nonce, ciphertext


def decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def encrypt_record(dek: bytes, data: Union[VaultEntryData, dict[str, Any]]) -> tuple[bytes, bytes]:
    if isinstance(data, VaultEntryData):
        data_dict = data.model_dump()
    else:
        data_dict = data
    plaintext = json.dumps(data_dict).encode()
    # Add padding to hide length: pad to multiple of 64 bytes
    pad_len = 64 - (len(plaintext) % 64)
    plaintext += bytes([pad_len] * pad_len)
    return encrypt_bytes(dek, plaintext)

def decrypt_record(dek: bytes, nonce: bytes, ciphertext: bytes) -> Optional[VaultEntryData]:
    plaintext = decrypt_bytes(dek, nonce, ciphertext)
    # Remove padding
    if not plaintext:
        return None
    pad_len = plaintext[-1]
    if 0 < pad_len <= 64:
        # Verify padding: all pad_len bytes must be equal to pad_len
        if plaintext[-pad_len:] == bytes([pad_len] * pad_len):
            plaintext = plaintext[:-pad_len]
        else:
            raise ValueError("Invalid padding")
    
    try:
        data_dict = json.loads(plaintext.decode())
        return VaultEntryData.model_validate(data_dict)
    except Exception:
        return None
