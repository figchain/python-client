import base64
import logging

from ..backup.service import BackupPayload, S3BackupService
from .strategy import BootstrapResult, BootstrapStrategy

logger = logging.getLogger(__name__)


def backup_schemas(payload: BackupPayload) -> dict[str, str]:
    """Schema JSON by URI from a v3 backup's publicData, so figs decode offline."""
    schemas: dict[str, str] = {}
    for uri, entry in ((payload.public_data or {}).get("schemas") or {}).items():
        try:
            content = entry["content"] if isinstance(entry, dict) else entry
            schemas[uri] = base64.b64decode(content).decode("utf-8")
        except Exception as e:
            logger.warning(f"Skipping unreadable backup schema {uri}: {e}")
    return schemas


class S3BackupStrategy(BootstrapStrategy):
    def __init__(self, s3_backup_service: S3BackupService):
        self.s3_backup_service = s3_backup_service

    def bootstrap(self, namespaces: list[str]) -> BootstrapResult:
        payload = self.s3_backup_service.load_backup()
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

        return BootstrapResult(families, cursors, backup_schemas(payload))
