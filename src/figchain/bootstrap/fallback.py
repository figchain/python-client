from typing import List
import logging
from .strategy import BootstrapStrategy, BootstrapResult

logger = logging.getLogger(__name__)


class FallbackStrategy(BootstrapStrategy):
    def __init__(
        self, server_strategy: BootstrapStrategy, s3_backup_strategy: BootstrapStrategy
    ):
        self.server_strategy = server_strategy
        self.s3_backup_strategy = s3_backup_strategy

    def bootstrap(self, namespaces: List[str]) -> BootstrapResult:
        try:
            return self.server_strategy.bootstrap(namespaces)
        except Exception as e:
            logger.warning(f"Server bootstrap failed: {e}. Falling back to S3 Backup.")
            try:
                return self.s3_backup_strategy.bootstrap(namespaces)
            except Exception as ve:
                raise e from ve
