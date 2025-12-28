from dataclasses import dataclass
from typing import Optional

@dataclass
class UserPublicKey:
    email: str
    public_key: str
    algorithm: str

@dataclass
class NamespaceKey:
    wrapped_key: str
    key_id: str
