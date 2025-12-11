from typing import List, Optional
from .strategy import BootstrapStrategy, BootstrapResult
from ..transport import Transport
from datetime import datetime

class ServerStrategy(BootstrapStrategy):
    def __init__(self, transport: Transport, as_of: Optional[datetime] = None):
        self.transport = transport
        self.as_of = as_of

    def bootstrap(self, namespaces: List[str]) -> BootstrapResult:
        families = []
        cursors = {}
        for ns in namespaces:
            resp = self.transport.fetch_initial(ns, self.as_of)
            if resp.figFamilies:
                families.extend(resp.figFamilies)
            if resp.cursor:
                cursors[ns] = resp.cursor
        return BootstrapResult(families, cursors)
