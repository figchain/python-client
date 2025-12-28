import logging
import urllib.parse
import requests
import uuid
from datetime import datetime
from typing import Optional, List
from .serialization import serialize, deserialize, serialize_ocf, deserialize_ocf
from .models import InitialFetchRequest, InitialFetchResponse, UpdateFetchRequest, UpdateFetchResponse
from .models_dto import NamespaceKey, UserPublicKey
from .auth import TokenProvider

logger = logging.getLogger(__name__)

class Transport:
    def __init__(self, base_url: str, token_provider: TokenProvider, environment_id: uuid.UUID):
        self.base_url = base_url.rstrip("/")
        self.token_provider = token_provider
        self.environment_id = environment_id
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/octet-stream"
        })

    def fetch_initial(self, namespace: str, as_of: Optional[datetime] = None) -> InitialFetchResponse:
        logger.debug(f"Fetching initial data for namespace {namespace}")
        req = InitialFetchRequest(
            namespace=namespace,
            environmentId=self.environment_id,
            asOfTimestamp=as_of
        )

        data = serialize_ocf(req, "InitialFetchRequest")

        url = f"{self.base_url}/data/initial"
        headers = {"Authorization": f"Bearer {self.token_provider.get_token()}"}
        resp = self.session.post(url, data=data, headers=headers, timeout=5)

        if resp.status_code == 401:
            raise PermissionError("Authentication failed: Check your credentials")
        if resp.status_code == 403:
            raise PermissionError("Authorization failed: Check environment ID and permissions")

        resp.raise_for_status()

        return deserialize_ocf(resp.content, "InitialFetchResponse", InitialFetchResponse)

    def fetch_updates(self, namespace: str, cursor: str) -> UpdateFetchResponse:
        logger.debug(f"Fetching updates for namespace {namespace} with cursor {cursor}")
        req = UpdateFetchRequest(
            namespace=namespace,
            environmentId=self.environment_id,
            cursor=cursor
        )

        data = serialize_ocf(req, "UpdateFetchRequest")

        url = f"{self.base_url}/data/updates"
        headers = {"Authorization": f"Bearer {self.token_provider.get_token()}"}
        resp = self.session.post(url, data=data, headers=headers, timeout=65)

        if resp.status_code == 401:
            raise PermissionError("Authentication failed: Check your credentials")
        if resp.status_code == 403:
            raise PermissionError("Authorization failed: Check environment ID and permissions")

        resp.raise_for_status()

        return deserialize_ocf(resp.content, "UpdateFetchResponse", UpdateFetchResponse)

    def get_namespace_key(self, namespace: str) -> List[NamespaceKey]:
        url = f"{self.base_url}/keys/namespace/{urllib.parse.quote(namespace)}"
        headers = {"Authorization": f"Bearer {self.token_provider.get_token()}"}
        resp = self.session.get(url, headers=headers, timeout=5)
        resp.raise_for_status()

        data = resp.json()
        # Expecting a list of keys
        return [NamespaceKey(wrapped_key=item['wrappedKey'], key_id=item['keyId']) for item in data]

    def upload_public_key(self, key: UserPublicKey) -> None:
        url = f"{self.base_url}/keys/public"
        data = {
            "email": key.email,
            "publicKey": key.public_key,
            "algorithm": key.algorithm
        }
        headers = {"Authorization": f"Bearer {self.token_provider.get_token()}"}
        resp = self.session.put(url, json=data, headers=headers, timeout=5)
        resp.raise_for_status()
