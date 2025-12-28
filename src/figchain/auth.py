import jwt
import abc
from datetime import datetime, timedelta

class TokenProvider(abc.ABC):
    @abc.abstractmethod
    def get_token(self) -> str:
        """Returns a valid authentication token."""
        pass

class SharedSecretTokenProvider(TokenProvider):
    def __init__(self, client_secret: str):
        self.client_secret = client_secret

    def get_token(self) -> str:
        return self.client_secret

class PrivateKeyTokenProvider(TokenProvider):
    def __init__(self, private_key: any, service_account_id: str, tenant_id: str = "default", namespace: str = None, key_id: str = None, token_ttl_minutes: int = 10):
        self.private_key = private_key
        self.service_account_id = service_account_id
        self.tenant_id = tenant_id
        self.namespace = namespace
        self.key_id = key_id
        self.token_ttl = timedelta(minutes=token_ttl_minutes)

    def get_token(self) -> str:
        now = datetime.utcnow()
        payload = {
            "iss": self.service_account_id,
            "sub": self.service_account_id,
            "iat": now,
            "nbf": now,
            "exp": now + self.token_ttl,
            "tenant_id": self.tenant_id
        }
        if self.namespace:
            payload["namespace"] = self.namespace

        headers = {}
        if self.key_id:
            headers["kid"] = self.key_id

        return jwt.encode(payload, self.private_key, algorithm="RS256", headers=headers)
