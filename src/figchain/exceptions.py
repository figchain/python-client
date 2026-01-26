"""
Custom exceptions for the FigChain client.
"""


class FigChainError(Exception):
    """Base exception for all FigChain errors."""
    pass


class ConfigurationError(FigChainError):
    """Raised when there's a configuration issue."""
    pass


class AuthenticationError(FigChainError):
    """Raised when authentication fails."""
    pass


class SchemaError(FigChainError):
    """Base exception for schema-related errors."""
    pass


class SchemaNotFoundError(SchemaError):
    """Raised when a schema cannot be found locally or remotely."""

    def __init__(self, schema_name: str, schema_uri: str = None):
        self.schema_name = schema_name
        self.schema_uri = schema_uri
        message = f"Schema '{schema_name}' not found"
        if schema_uri:
            message += f" (URI: {schema_uri})"
        super().__init__(message)


class SchemaRegistrationError(SchemaError):
    """Raised when schema registration fails."""
    pass


class DeserializationError(FigChainError):
    """Raised when deserialization fails."""

    def __init__(self, message: str, schema_name: str = None, cause: Exception = None):
        self.schema_name = schema_name
        self.cause = cause
        super().__init__(message)


class EncryptionError(FigChainError):
    """Raised when encryption/decryption fails."""
    pass


class TransportError(FigChainError):
    """Raised when network/transport operations fail."""
    pass


class BootstrapError(FigChainError):
    """Raised when bootstrap fails."""
    pass
