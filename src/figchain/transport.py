import logging
import requests
import uuid
from datetime import datetime
from typing import Optional
from .serialization import serialize, deserialize
from .models import InitialFetchRequest, InitialFetchResponse, UpdateFetchRequest, UpdateFetchResponse

logger = logging.getLogger(__name__)

class Transport:
    def __init__(self, base_url: str, client_secret: str, environment_id: uuid.UUID):
        self.base_url = base_url.rstrip("/")
        self.client_secret = client_secret
        self.environment_id = environment_id
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {client_secret}",
            "Content-Type": "application/octet-stream"
        })

    def fetch_initial(self, namespace: str, as_of: Optional[datetime] = None) -> InitialFetchResponse:
        logger.debug(f"Fetching initial data for namespace {namespace}")
        req = InitialFetchRequest(
            namespace=namespace,
            environmentId=self.environment_id,
            asOfTimestamp=as_of
        )
        
        data = serialize(req, "InitialFetchRequest")
        
        url = f"{self.base_url}/data/initial"
        resp = self.session.post(url, data=data, timeout=5)
        
        if resp.status_code == 401:
            raise PermissionError("Authentication failed: Check client secret")
        if resp.status_code == 403:
            raise PermissionError("Authorization failed: Check environment ID and permissions")
        
        resp.raise_for_status()
        
        return deserialize(resp.content, "InitialFetchResponse", InitialFetchResponse)

    def fetch_updates(self, namespace: str, cursor: str) -> UpdateFetchResponse:
        logger.debug(f"Fetching updates for namespace {namespace} with cursor {cursor}")
        req = UpdateFetchRequest(
            namespace=namespace,
            environmentId=self.environment_id,
            cursor=cursor
        )
        
        data = serialize(req, "UpdateFetchRequest")
        
        url = f"{self.base_url}/data/updates"
        resp = self.session.post(url, data=data, timeout=65)
        
        if resp.status_code == 401:
            raise PermissionError("Authentication failed: Check client secret")
        if resp.status_code == 403:
            raise PermissionError("Authorization failed: Check environment ID and permissions")

        resp.raise_for_status()
        
        return deserialize(resp.content, "UpdateFetchResponse", UpdateFetchResponse)
