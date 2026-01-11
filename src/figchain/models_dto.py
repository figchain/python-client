from dataclasses import dataclass


@dataclass
class UserPublicKey:
    email: str
    public_key: str
    algorithm: str


@dataclass
class NamespaceKey:
    wrapped_key: str
    key_id: str
