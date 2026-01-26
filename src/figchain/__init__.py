from .client import FigChainClient
from .evaluation import Context
from .exceptions import (
    FigChainError,
    ConfigurationError,
    AuthenticationError,
    SchemaError,
    SchemaNotFoundError,
    SchemaRegistrationError,
    DeserializationError,
    EncryptionError,
    TransportError,
    BootstrapError,
)

try:
    from .version import version as __version__
except ImportError:
    __version__ = "0.0.0"

__all__ = [
    "FigChainClient",
    "Context",
    "__version__",
    # Exceptions
    "FigChainError",
    "ConfigurationError",
    "AuthenticationError",
    "SchemaError",
    "SchemaNotFoundError",
    "SchemaRegistrationError",
    "DeserializationError",
    "EncryptionError",
    "TransportError",
    "BootstrapError",
]
