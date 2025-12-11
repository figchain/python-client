from datetime import datetime
import threading
import logging
import uuid
from typing import Set, Optional, Dict, List, Type, Callable, TypeVar, Any

from .config import Config, BootstrapStrategy
from .models import Fig, FigFamily
from .transport import Transport
from .store import Store
from .evaluation import Evaluator, Context
from .serialization import deserialize
from .bootstrap.server import ServerStrategy
from .bootstrap.vault import VaultStrategy
from .bootstrap.hybrid import HybridStrategy
from .bootstrap.fallback import FallbackStrategy
from .vault.service import VaultService

T = TypeVar("T")

logger = logging.getLogger(__name__)

class FigChainClient:
    def __init__(self,
                 base_url: Optional[str] = None,
                 client_secret: Optional[str] = None,
                 environment_id: Optional[str] = None,
                 namespaces: Optional[Set[str]] = None,
                 as_of: Optional[datetime] = None,
                 poll_interval: Optional[int] = None,
                 config: Optional[Config] = None):

        # 1. Load Configuration
        if config is None:
            config = Config.load()

        # 2. Override with explicit args
        if base_url: config.base_url = base_url
        if client_secret: config.client_secret = client_secret
        if environment_id: config.environment_id = environment_id
        if namespaces: config.namespaces = namespaces
        if poll_interval is not None: config.poll_interval = poll_interval

        self.config = config
        self.namespaces = config.namespaces
        if not self.namespaces:
            logger.warning("No namespaces configured")

        as_of_dt = as_of
        if as_of_dt is None and config.as_of:
            as_of_dt = datetime.fromisoformat(config.as_of.replace('Z', '+00:00'))
        self.as_of = as_of_dt

        if not config.environment_id:
            raise ValueError("Environment ID is required")

        if not config.client_secret:
            raise ValueError("Client secret is required")

        # 3. Initialize Components
        self.transport = Transport(config.base_url, config.client_secret, uuid.UUID(config.environment_id))
        self.store = Store()
        self.evaluator = Evaluator()

        self.namespace_cursors: Dict[str, str] = {}
        self._shutdown_event = threading.Event()
        self._poller_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._listeners: Dict[str, List[tuple[Callable[[Any], None], Type[Any]]]] = {}

        # 4. Bootstrap Strategy
        server_strategy = ServerStrategy(self.transport, self.as_of)

        if config.vault_enabled:
            vault_service = VaultService(config)
            vault_strategy = VaultStrategy(vault_service)

            if config.bootstrap_strategy == BootstrapStrategy.VAULT:
                self.bootstrap_strategy = vault_strategy
            elif config.bootstrap_strategy == BootstrapStrategy.HYBRID:
                self.bootstrap_strategy = HybridStrategy(vault_strategy, server_strategy, self.transport)
            elif config.bootstrap_strategy == BootstrapStrategy.SERVER:
                # Explicitly server only, despite vault enabled generally
                self.bootstrap_strategy = server_strategy
            else: # SERVER_FIRST or Default
                self.bootstrap_strategy = FallbackStrategy(server_strategy, vault_strategy)
        else:
            self.bootstrap_strategy = server_strategy

        logger.info(f"Bootstrapping with strategy: {self.bootstrap_strategy.__class__.__name__}")

        # 5. Execute Bootstrap
        try:
            result = self.bootstrap_strategy.bootstrap(list(self.namespaces))
            self.store.put_all(result.fig_families)
            self.namespace_cursors = result.cursors
        except Exception as e:
            logger.error(f"Bootstrap failed: {e}")
            raise

        # 6. Start Poller
        self._start_poller()

    def _start_poller(self):
        self._poller_thread = threading.Thread(target=self._poll_loop, daemon=True, name="FigChainPoller")
        self._poller_thread.start()

    def _poll_loop(self):
        logger.info("Starting poll loop")
        while not self._shutdown_event.is_set():
            for ns in self.namespaces:
                if self._shutdown_event.is_set():
                    break

                cursor = self.namespace_cursors.get(ns, "")
                try:
                    # Long polling request
                    resp = self.transport.fetch_updates(ns, cursor)

                    if resp.figFamilies:
                        logger.debug(f"Received {len(resp.figFamilies)} updates for {ns}")
                        self.store.put_all(resp.figFamilies)
                        self._notify_listeners(resp.figFamilies)

                    # Update cursor even if no families (heartbeat/timeout)
                    if resp.cursor:
                        self.namespace_cursors[ns] = resp.cursor

                except Exception as e:
                    logger.warning(f"Poll failed for {ns}: {e}")
                    # On error, wait a bit before retrying to avoid hammering
                    self._shutdown_event.wait(5.0)

    def _notify_listeners(self, families: List[FigFamily]):
        with self._lock:
            for family in families:
                key = family.definition.key
                if key in self._listeners:
                    listeners = self._listeners[key]
                    for callback, result_type in listeners:
                        # Evaluate for listeners with empty context
                        context = {}
                        fig = self.evaluator.evaluate(family, context)
                        if fig:
                            try:
                                schema_name = result_type.__name__
                                val = deserialize(fig.payload, schema_name, result_type)
                                callback(val)
                            except Exception as e:
                                logger.error(f"Failed to notify listener for {key}: {e}")

    def register_listener(self, key: str, callback: Callable[[T], None], result_type: Type[T]):
        """
        Register a listener for updates to a specific Fig key.
        The callback will be invoked with the deserialized object when an update occurs.
        The type T is contravariant, allow callbacks that handle supertypes.

        WARNING: This feature should be used for SERVER-SCOPED configuration only (e.g. global flags).
        The update is evaluated with an empty context. If your rules depend on user-specific attributes
        (like request-scoped context), this listener may receive default values or fail to match rules.
        For request-scoped configuration, use get_fig() with the appropriate context when needed.
        """
        with self._lock:
            if key not in self._listeners:
                self._listeners[key] = []
            self._listeners[key].append((callback, result_type))

    def get_fig(self,
                key: str,
                result_type: Type[T],
                context: Context = {},
                namespace: Optional[str] = None,
                default_value: Optional[T] = None) -> Optional[T]:

        if namespace is None:
            if len(self.namespaces) == 1:
                namespace = list(self.namespaces)[0]
            else:
                # Check if key exists in any namespace
                found_ns = None
                # This is inefficient if we have many namespaces, but correctness first
                for ns in self.namespaces:
                    if self.store.get_fig_family(ns, key):
                        found_ns = ns
                        break

                if found_ns:
                    namespace = found_ns
                else:
                    return default_value

        family = self.store.get_fig_family(namespace, key)
        if not family:
            return default_value

        fig = self.evaluator.evaluate(family, context)
        if not fig:
            return default_value

        try:
            schema_name = result_type.__name__
            return deserialize(fig.payload, schema_name, result_type)
        except Exception as e:
            logger.error(f"Failed to deserialize fig {key}: {e}")
            return default_value

    def close(self):
        logger.info("Shutting down FigChain client")
        self._shutdown_event.set()
        if self._poller_thread and self._poller_thread.is_alive():
            self._poller_thread.join(timeout=5.0)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
