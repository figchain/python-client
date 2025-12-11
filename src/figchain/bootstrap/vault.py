from typing import List
from .strategy import BootstrapStrategy, BootstrapResult
from ..vault.service import VaultService

class VaultStrategy(BootstrapStrategy):
    def __init__(self, vault_service: VaultService):
        self.vault_service = vault_service

    def bootstrap(self, namespaces: List[str]) -> BootstrapResult:
        payload = self.vault_service.load_backup()
        if not payload:
            return BootstrapResult([], {})

        families = payload.items
        cursors = {}

        # Populate cursors for requested namespaces if sync_token present
        if payload.sync_token:
            for ns in namespaces:
                cursors[ns] = payload.sync_token

            # Also for any namespace found in items
            for f in families:
                cursors[f.definition.namespace] = payload.sync_token

        return BootstrapResult(families, cursors)
