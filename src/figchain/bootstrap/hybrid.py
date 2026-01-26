from typing import List
import logging
from .strategy import BootstrapStrategy, BootstrapResult
from ..transport import Transport

logger = logging.getLogger(__name__)


class HybridStrategy(BootstrapStrategy):
    def __init__(
        self,
        s3_backup_strategy: BootstrapStrategy,
        server_strategy: BootstrapStrategy,
        transport: Transport,
    ):
        self.s3_backup_strategy = s3_backup_strategy
        self.server_strategy = server_strategy
        self.transport = transport

    def bootstrap(self, namespaces: List[str]) -> BootstrapResult:
        # 1. Load from S3 Backup
        try:
            s3_backup_result = self.s3_backup_strategy.bootstrap(namespaces)
        except Exception as e:
            logger.warning(
                f"S3 Backup bootstrap failed: {e}. Falling back to empty result."
            )
            s3_backup_result = BootstrapResult([], {})

        # 2. Identify missing namespaces
        missing_namespaces = [
            ns for ns in namespaces if ns not in s3_backup_result.cursors
        ]

        all_families = list(s3_backup_result.fig_families)
        final_cursors = dict(s3_backup_result.cursors)

        # 3. Fetch missing from Server
        if missing_namespaces:
            logger.info(
                f"Fetching missing namespaces from server: {missing_namespaces}"
            )
            try:
                server_result = self.server_strategy.bootstrap(missing_namespaces)
                all_families.extend(server_result.fig_families)
                final_cursors.update(server_result.cursors)
            except Exception as e:
                logger.error(f"Server bootstrap failed for missing namespaces: {e}")

        # 4. Catch up
        for ns in namespaces:
            cursor = final_cursors.get(ns)
            # Only catch up if it was in S3 Backup (so it might be stale)
            # And NOT if it was just fetched from server (assumed fresh)
            if ns not in missing_namespaces and cursor:
                try:
                    logger.debug(f"Catching up namespace {ns} from cursor {cursor}")
                    resp = self.transport.fetch_updates(ns, cursor)
                    if resp.figFamilies:
                        all_families.extend(resp.figFamilies)
                    if resp.cursor:
                        final_cursors[ns] = resp.cursor
                except Exception as e:
                    logger.warning(f"Failed to catch up for {ns}: {e}")

        return BootstrapResult(all_families, final_cursors)
