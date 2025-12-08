import threading
import time
import logging
import uuid
from typing import Set, Optional, Dict, List, Type, Callable, TypeVar, Any
from datetime import datetime

from .models import Fig, FigFamily
from .transport import Transport
from .store import Store
from .evaluation import Evaluator, Context
from .serialization import deserialize

T = TypeVar("T")

logger = logging.getLogger(__name__)

class FigChainClient:
    def __init__(self, 
                 base_url: str, 
                 client_secret: str, 
                 environment_id: str, 
                 namespaces: Set[str],
                 as_of: Optional[datetime] = None,
                 poll_interval: int = 30):
        
        self.transport = Transport(base_url, client_secret, uuid.UUID(environment_id))
        self.store = Store()
        self.evaluator = Evaluator()
        self.namespaces = namespaces
        self.as_of = as_of
        self.poll_interval = poll_interval
        
    
        self.namespace_cursors: Dict[str, str] = {}
        self._shutdown_event = threading.Event()
        self._poller_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        
        # key -> list of (callback, result_type)
        self._listeners: Dict[str, List[tuple[Callable[[Any], None], Type[Any]]]] = {}
        
        # Initial fetch
        self._initial_fetch()
        
        # Start poller
        self._start_poller()

    def _initial_fetch(self):
        for ns in self.namespaces:
            try:
                logger.info(f"Fetching initial data for namespace {ns}")
                resp = self.transport.fetch_initial(ns, self.as_of)
                if resp.figFamilies:
                    self.store.put_all(resp.figFamilies)
                self.namespace_cursors[ns] = resp.cursor
                logger.info(f"Initial fetch for {ns} complete. Cursor: {resp.cursor}")
            except Exception as e:
                logger.error(f"Failed initial fetch for {ns}: {e}")
                
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
                        # We evaluate with empty context for listeners as we don't know the context
                        # Or should we pass the FigFamily? Java implementation usually passes the typed object.
                        # Assuming default evaluation or raw payload?
                        # Let's use default evaluation (no rules or default rules).
                        # If rules depend on context, listeners might get 'None' or default if we don't have context.
                        # For now, let's try to evaluate with empty context.
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
                context: Context = None, 
                namespace: Optional[str] = None,
                default_value: Optional[T] = None) -> Optional[T]:
        
        if context is None:
            context = {}
            
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
