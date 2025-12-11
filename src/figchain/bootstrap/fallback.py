from typing import List
import logging
from .strategy import BootstrapStrategy, BootstrapResult

logger = logging.getLogger(__name__)

class FallbackStrategy(BootstrapStrategy):
    def __init__(self, server_strategy: BootstrapStrategy, vault_strategy: BootstrapStrategy):
        self.server_strategy = server_strategy
        self.vault_strategy = vault_strategy

    def bootstrap(self, namespaces: List[str]) -> BootstrapResult:
        try:
            return self.server_strategy.bootstrap(namespaces)
        except Exception as e:
            logger.warning(f"Server bootstrap failed: {e}. Falling back to Vault.")
            try:
                return self.vault_strategy.bootstrap(namespaces)
            except Exception as ve:
                raise e from ve
