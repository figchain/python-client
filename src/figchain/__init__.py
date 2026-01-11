from .client import FigChainClient
from .evaluation import Context

try:
    from .version import version as __version__
except ImportError:
    __version__ = "0.0.0"

__all__ = [
    "FigChainClient",
    "Context",
    "__version__",
]
