from abc import ABC, abstractmethod
from typing import List, Dict
from dataclasses import dataclass, field
from ..models import FigFamily


@dataclass
class BootstrapResult:
    fig_families: List[FigFamily]
    cursors: Dict[str, str]
    schemas: Dict[str, str] = field(default_factory=dict)


class BootstrapStrategy(ABC):
    @abstractmethod
    def bootstrap(self, namespaces: List[str]) -> BootstrapResult:
        pass
