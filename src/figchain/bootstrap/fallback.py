import logging

from .strategy import BootstrapResult, BootstrapStrategy

logger = logging.getLogger(__name__)


class FallbackStrategy(BootstrapStrategy):
    def __init__(
        self, server_strategy: BootstrapStrategy, s3_backup_strategy: BootstrapStrategy
    ):
        self.server_strategy = server_strategy
        self.s3_backup_strategy = s3_backup_strategy

    def bootstrap(self, namespaces: list[str]) -> BootstrapResult:
        try:
            return self.server_strategy.bootstrap(namespaces)
        except PermissionError:
            # A rejected credential is a configuration error, not an outage. Serving the
            # backup would hide it while every later update fails the same way.
            raise
        except Exception as e:
            logger.warning(f"Server bootstrap failed: {e}. Falling back to S3 Backup.")
            try:
                return self.s3_backup_strategy.bootstrap(namespaces)
            except Exception as ve:
                raise e from ve
