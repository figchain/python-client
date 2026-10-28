from datetime import datetime

from ..transport import Transport
from .strategy import BootstrapResult, BootstrapStrategy


class ServerStrategy(BootstrapStrategy):
    def __init__(self, transport: Transport, as_of: datetime | None = None):
        self.transport = transport
        self.as_of = as_of

    def bootstrap(self, namespaces: list[str]) -> BootstrapResult:
        families = []
        cursors = {}
        schemas = {}
        for ns in namespaces:
            resp = self.transport.fetch_initial(ns, self.as_of)
            if resp.figFamilies:
                families.extend(resp.figFamilies)
            if resp.cursor:
                cursors[ns] = resp.cursor
            if resp.schemas:
                schemas.update(resp.schemas)
        return BootstrapResult(families, cursors, schemas)
