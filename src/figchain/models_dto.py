from dataclasses import dataclass
from typing import Optional

@dataclass
class UserPublicKey:
    email: str
    publicKey: str
    algorithm: str

@dataclass
class NamespaceKey:
    wrappedKey: str
    keyId: str
