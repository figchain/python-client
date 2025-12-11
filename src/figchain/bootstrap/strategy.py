from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from dataclasses import dataclass
from ..models import FigFamily

@dataclass
class BootstrapResult:
    fig_families: List[FigFamily]
    cursors: Dict[str, str]

class BootstrapStrategy(ABC):
    @abstractmethod
    def bootstrap(self, namespaces: List[str]) -> BootstrapResult:
        pass
