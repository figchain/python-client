from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..models import FigFamily


@dataclass
class BootstrapResult:
    fig_families: list[FigFamily]
    cursors: dict[str, str]
    schemas: dict[str, str] = field(default_factory=dict)


class BootstrapStrategy(ABC):
    @abstractmethod
    def bootstrap(self, namespaces: list[str]) -> BootstrapResult:
        pass
