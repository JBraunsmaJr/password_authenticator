from pydantic import BaseModel, ConfigDict
from typing import Optional

class VaultMeta(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    key: str
    value: bytes

class VaultEntry(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: Optional[int] = None
    nonce: bytes
    ciphertext: bytes

class VaultEntryData(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    service: str = ""
    username: str = ""
    password: str = ""
    secret: str = ""
