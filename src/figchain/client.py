import json
import logging
import threading
import urllib.parse
import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any, TypeVar

import requests

from .auth import PrivateKeyTokenProvider, SharedSecretTokenProvider, TokenProvider
from .backup.service import S3BackupService
from .bootstrap.backup import S3BackupStrategy
from .bootstrap.fallback import FallbackStrategy
from .bootstrap.hybrid import HybridStrategy
from .bootstrap.server import ServerStrategy
from .config import BootstrapStrategy, Config
from .encryption import crypto
from .encryption.service import EncryptionService
from .evaluation import Context, Evaluator
from .exceptions import SchemaNotFoundError
from .models import FigFamily
from .serialization import deserialize, register_schema
from .store import Store
from .transport import Transport

T = TypeVar("T")

logger = logging.getLogger(__name__)

# How long the server may hold an update request open. Kept under common
# proxy/load-balancer idle timeouts (often 60s).
LONG_POLL_WAIT_SECONDS = 30
# Consecutive in-transit failures (timeouts, dropped connections) in long-poll
# mode before a namespace falls back to plain polling.
LONG_POLL_FALLBACK_AFTER = 3


class FigChainClient:
    @classmethod
    def from_config(cls, path: str, **kwargs) -> "FigChainClient":
        """
        Creates a FigChainClient from a client-config.json file.
        """
        with open(path) as f:
            data = json.load(f)

        # Map fields from client-config.json to Config
        cfg = Config()

        # Define mapping of config attributes to their possible JSON key variants
        # Format: config_attr: [json_key_variants...]
        config_mappings = {
            "auth_private_key": ["authPrivateKey", "privateKey"],
            "encryption_private_key": ["encryptionPrivateKey"],
            "auth_credential_id": ["credentialId"],
            "tenant_id": ["tenantId"],
            "environment_id": ["environmentId"],
        }

        # Load config values from JSON using first matching key variant
        for attr, key_variants in config_mappings.items():
            for key in key_variants:
                if key in data:
                    setattr(cfg, attr, data[key])
                    break

        # Handle namespaces (special case - can be list or single value)
        if "namespaces" in data and isinstance(data["namespaces"], list):
            cfg.namespaces.update(data["namespaces"])
        if "namespace" in data:
            cfg.namespaces.add(data["namespace"])

        # Load base config from environment/defaults
        base_config = Config.load(**kwargs)

        # Merge cfg into base_config (only if not already set)
        merge_mappings = {
            "namespaces": "namespaces",
            "environment_id": "environment_id",
            "auth_private_key": "auth_private_key",
            "encryption_private_key": "encryption_private_key",
            "auth_credential_id": "auth_credential_id",
        }

        for base_attr, cfg_attr in merge_mappings.items():
            base_value = getattr(base_config, base_attr)
            cfg_value = getattr(cfg, cfg_attr)

            # Only merge if base is empty/falsy and cfg has a value
            if not base_value and cfg_value:
                setattr(base_config, base_attr, cfg_value)

        # Tenant ID special case (override if not default)
        if cfg.tenant_id != "default":
            base_config.tenant_id = cfg.tenant_id

        # S3 Backup Config - load from camelCase or snake_case variants
        s3_config_mappings = {
            "s3_backup_enabled": ["s3BackupEnabled", "s3_backup_enabled"],
            "s3_backup_bucket": ["s3BackupBucket", "s3_backup_bucket"],
            "s3_backup_prefix": ["s3BackupPrefix", "s3_backup_prefix"],
            "s3_backup_region": ["s3BackupRegion", "s3_backup_region"],
            "s3_backup_endpoint": ["s3BackupEndpoint", "s3_backup_endpoint"],
        }

        for attr_name, key_variants in s3_config_mappings.items():
            for key in key_variants:
                if key in data:
                    setattr(base_config, attr_name, data[key])
                    break

        # Bootstrap mode (special case with enum conversion)
        if "bootstrapMode" in data:
            try:
                base_config.bootstrap_strategy = BootstrapStrategy(
                    data["bootstrapMode"]
                )
            except ValueError:
                pass

        return cls(config=base_config)

    def __init__(
        self,
        base_url: str | None = None,
        client_secret: str | None = None,
        environment_id: str | None = None,
        namespaces: set[str] | None = None,
        as_of: datetime | None = None,
        poll_interval: int | None = None,
        config: Config | None = None,
    ):

        # Configuration
        if config is None:
            config = Config.load()

        if base_url:
            config.base_url = base_url

        if client_secret:
            config.client_secret = client_secret

        if environment_id:
            config.environment_id = environment_id

        if namespaces:
            config.namespaces = namespaces

        if poll_interval is not None:
            config.poll_interval = poll_interval

        self.config = config
        self.namespaces = config.namespaces
        if not self.namespaces:
            logger.warning("No namespaces configured")

        as_of_dt = as_of
        if as_of_dt is None and config.as_of:
            try:
                as_of_dt = datetime.fromisoformat(config.as_of.replace("Z", "+00:00"))
            except ValueError:
                pass
        self.as_of = as_of_dt

        if not config.environment_id:
            raise ValueError("Environment ID is required")

        # Components
        token_provider: TokenProvider
        auth_key_obj = None

        # Check for Auth Private Key
        auth_key_hex = config.auth_private_key

        if auth_key_hex:
            try:
                auth_key_obj = crypto.load_ed25519_private_key(auth_key_hex)
            except Exception as e:
                # If we rely on auth key, this is fatal unless client_secret is present
                if not config.client_secret:
                    raise ValueError(f"Failed to load Auth Private Key: {e}")

        if not config.client_secret and not auth_key_obj:
            raise ValueError("Client secret or Auth private key is required")

        if auth_key_obj:
            if config.namespaces and len(config.namespaces) > 1:
                raise ValueError(
                    "Private key authentication can only be used with a single namespace"
                )

            # Use environment_id as service_account_id for now if not provided
            service_account_id = (
                config.auth_client_id
                or config.auth_credential_id
                or config.environment_id
            )
            tenant_id = config.tenant_id
            namespace = next(iter(config.namespaces)) if config.namespaces else None

            # Extract key_id (credentialId) from config
            key_id = config.auth_credential_id

            token_provider = PrivateKeyTokenProvider(
                auth_key_obj,
                service_account_id,
                tenant_id=tenant_id,
                namespace=namespace,
                key_id=key_id,
            )
        else:
            token_provider = SharedSecretTokenProvider(config.client_secret)

        self.transport = Transport(
            config.base_url, token_provider, uuid.UUID(config.environment_id)
        )
        self.store = Store()
        self.evaluator = Evaluator()

        self.namespace_cursors: dict[str, str] = {}
        self.schemas: dict[str, str] = {}
        self._shutdown_event = threading.Event()
        self._poller_threads: list[threading.Thread] = []
        self._lock = threading.RLock()
        self._listeners: dict[str, list[tuple[Callable[[Any], None], type[Any]]]] = {}
        self.encryption_service: EncryptionService | None = None

        # Prepare S3 Backup Config for Encryption Service
        s3_backup_config = {
            "bucket": config.s3_backup_bucket,
            "prefix": config.s3_backup_prefix,
            "region": config.s3_backup_region,
            "endpoint": config.s3_backup_endpoint,
        }
        client_id_for_backup = config.auth_credential_id or config.auth_client_id

        # Encryption Key Loading
        enc_key_obj = None
        enc_key_hex = config.encryption_private_key

        if enc_key_hex:
            try:
                enc_key_obj = crypto.load_x25519_private_key(enc_key_hex)
            except Exception as e:
                logger.error(f"Failed to load Encryption Private Key: {e}")
                raise e

        if enc_key_obj:
            self.encryption_service = EncryptionService(
                self.transport,
                private_key=enc_key_obj,
                s3_backup_enabled=config.s3_backup_enabled,
                s3_backup_config=s3_backup_config,
                client_id=client_id_for_backup,
            )

        # Bootstrap Strategy
        server_strategy = ServerStrategy(self.transport, self.as_of)

        if config.s3_backup_enabled:
            s3_backup_service = S3BackupService(config)
            s3_backup_strategy = S3BackupStrategy(s3_backup_service)

            if config.bootstrap_strategy == BootstrapStrategy.S3_BACKUP_ONLY:
                self.bootstrap_strategy = s3_backup_strategy
            elif config.bootstrap_strategy == BootstrapStrategy.HYBRID:
                self.bootstrap_strategy = HybridStrategy(
                    s3_backup_strategy, server_strategy, self.transport
                )
            elif config.bootstrap_strategy == BootstrapStrategy.SERVER:
                # Explicitly server only, despite s3 backup enabled generally
                self.bootstrap_strategy = server_strategy
            else:
                # SERVER_FIRST or Default
                self.bootstrap_strategy = FallbackStrategy(
                    server_strategy, s3_backup_strategy
                )
        else:
            self.bootstrap_strategy = server_strategy

        logger.info(
            f"Bootstrapping with strategy: {self.bootstrap_strategy.__class__.__name__}"
        )

        # Execute Bootstrap
        try:
            result = self.bootstrap_strategy.bootstrap(list(self.namespaces))
            self.store.put_all(result.fig_families)
            self.namespace_cursors = result.cursors
            if result.schemas:
                for k, v in result.schemas.items():
                    self.schemas[k] = v
                    try:
                        register_schema(v)
                    except Exception as e:
                        logger.warning(f"Failed to register schema {k}: {e}")
        except Exception as e:
            logger.error(f"Bootstrap failed: {e}")
            raise

        # Start Poller
        self._start_poller()

    def _start_poller(self):
        # One poller per namespace so a long poll on a quiet namespace never
        # delays updates for another.
        self._poller_threads = [
            threading.Thread(
                target=self._poll_namespace,
                args=(ns,),
                daemon=True,
                name=f"FigChainPoller-{ns}",
            )
            for ns in self.namespaces
        ]
        for t in self._poller_threads:
            t.start()

    def _poll_namespace(self, ns: str):
        """Single update loop for both transports.

        Long polling and plain polling differ only in how long the server may
        hold the request (LONG_POLL_WAIT_SECONDS vs 0) and how long we pause
        before the next request (0 vs poll_interval).
        """
        long_poll = self.config.use_long_polling
        transit_failures = 0
        logger.info(f"Starting {'long-poll' if long_poll else 'poll'} loop for {ns}")

        while not self._shutdown_event.is_set():
            pause = self.config.poll_interval
            try:
                resp = self.transport.fetch_updates(
                    ns,
                    self.namespace_cursors.get(ns, ""),
                    wait_seconds=LONG_POLL_WAIT_SECONDS if long_poll else 0,
                )
            except (requests.Timeout, requests.ConnectionError) as e:
                logger.warning(f"Poll failed in transit for {ns}: {e}")
                if long_poll:
                    transit_failures += 1
                    if transit_failures >= LONG_POLL_FALLBACK_AFTER:
                        logger.warning(
                            f"Long polling for {ns} failed {transit_failures} times "
                            f"in transit; falling back to polling every "
                            f"{self.config.poll_interval}s"
                        )
                        long_poll = False
            except Exception as e:
                logger.warning(f"Poll failed for {ns}: {e}")
            else:
                transit_failures = 0
                self._apply_update(ns, resp)
                if long_poll:
                    pause = 0  # the server already waited; reconnect now

            if pause > 0:
                self._shutdown_event.wait(pause)

    def _apply_update(self, ns: str, resp):
        if resp.figFamilies:
            logger.debug(f"Received {len(resp.figFamilies)} updates for {ns}")
            # Update schemas and cursors first, then notify listeners
            with self._lock:
                if resp.cursor:
                    self.namespace_cursors[ns] = resp.cursor
                if resp.schemas:
                    for k, v in resp.schemas.items():
                        self.schemas[k] = v
                        try:
                            register_schema(v)
                        except Exception as e:
                            logger.warning(f"Failed to register schema {k}: {e}")

            self.store.put_all(resp.figFamilies)
            self._notify_listeners(resp.figFamilies)

        # Update cursor even if no families (heartbeat/timeout)
        elif resp.cursor:
            with self._lock:
                self.namespace_cursors[ns] = resp.cursor

    def _notify_listeners(self, families: list[FigFamily]):
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
                                payload = fig.payload
                                if fig.isEncrypted:
                                    if not self.encryption_service:
                                        logger.error(
                                            f"Listener received encrypted fig for key '{key}' but client is not configured for decryption"
                                        )
                                        continue
                                    payload = self.encryption_service.decrypt(
                                        fig, family.definition.namespace
                                    )

                                schema_name = result_type.__name__
                                try:
                                    val = deserialize(payload, schema_name, result_type)
                                except SchemaNotFoundError as e:
                                    # Attempt on-demand fetch
                                    schema_uri = family.definition.schemaUri
                                    logger.info(
                                        f"Schema {schema_name} not found locally, attempting on-demand fetch of {schema_uri}"
                                    )
                                    try:
                                        schema_content = self._fetch_schema_by_uri(
                                            schema_uri
                                        )
                                        with self._lock:
                                            self.schemas[schema_uri] = schema_content
                                            register_schema(schema_content)
                                        val = deserialize(
                                            payload, schema_name, result_type
                                        )
                                    except Exception as fetch_err:
                                        logger.error(
                                            f"Failed to fetch schema {schema_uri} on-demand: {fetch_err}"
                                        )
                                        raise e
                                callback(val)
                            except Exception as e:
                                logger.error(
                                    f"Failed to notify listener for {key}: {e}"
                                )

    def register_listener(
        self, key: str, callback: Callable[[T], None], result_type: type[T]
    ):
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

    def get_fig(
        self,
        key: str,
        result_type: type[T],
        context: Context | None = None,
        namespace: str | None = None,
        default_value: T | None = None,
    ) -> T | None:
        if context is None:
            context = {}

        if namespace is None:
            if len(self.namespaces) == 1:
                namespace = list(self.namespaces)[0]
            else:
                found_ns = None
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
            payload = fig.payload
            if fig.isEncrypted:
                if not self.encryption_service:
                    raise ValueError(
                        f"Received encrypted fig for key '{key}' but client is not configured for decryption"
                    )
                payload = self.encryption_service.decrypt(fig, namespace)

            schema_name = result_type.__name__
            if hasattr(result_type, "schema") and callable(result_type.schema):
                schema_name = result_type.schema()

            try:
                return deserialize(payload, schema_name, result_type)
            except SchemaNotFoundError:
                # Attempt on-demand fetch
                schema_uri = family.definition.schemaUri
                logger.info(
                    f"Schema {schema_name} not found locally, attempting on-demand fetch of {schema_uri}"
                )
                try:
                    schema_content = self._fetch_schema_by_uri(schema_uri)
                    with self._lock:
                        self.schemas[schema_uri] = schema_content
                        register_schema(schema_content)
                    return deserialize(payload, schema_name, result_type)
                except Exception as fetch_err:
                    logger.error(
                        f"Failed to fetch schema {schema_uri} on-demand: {fetch_err}"
                    )
                    return default_value
        except Exception as e:
            logger.error(f"Failed to deserialize fig {key}: {e}")
            return default_value

    def _fetch_schema_by_uri(self, schema_uri: str) -> str:
        parsed = urllib.parse.urlparse(schema_uri)
        if parsed.scheme == "tag":
            # Format: tag:figchain.io,2025:namespace:schemaName:version
            parts = parsed.path.split(":")
            if len(parts) >= 4:
                namespace = parts[1]
                name = parts[2]
                version = int(parts[3])
                return self.transport.fetch_schema(namespace, name, version)
            else:
                raise ValueError(f"Invalid path for tag schema URI: {parsed.path}")

        raise ValueError(f"Invalid or unsupported schema URI scheme: {parsed.scheme}")

    def close(self):
        logger.info("Shutting down FigChain client")
        self._shutdown_event.set()
        for t in self._poller_threads:
            if t.is_alive():
                t.join(timeout=5.0)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
