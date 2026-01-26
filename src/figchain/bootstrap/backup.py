from typing import List
from .strategy import BootstrapStrategy, BootstrapResult
from ..backup.service import S3BackupService


class S3BackupStrategy(BootstrapStrategy):
    def __init__(self, s3_backup_service: S3BackupService):
        self.s3_backup_service = s3_backup_service

    def bootstrap(self, namespaces: List[str]) -> BootstrapResult:
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

        return BootstrapResult(families, cursors)
