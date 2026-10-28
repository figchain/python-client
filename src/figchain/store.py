import threading

from .models import FigFamily


class Store:
    def __init__(self):
        self._data: dict[str, dict[str, FigFamily]] = {}  # namespace -> key -> family
        self._lock = threading.RLock()

    def put(self, family: FigFamily):
        with self._lock:
            namespace = family.definition.namespace
            key = family.definition.key
            if namespace not in self._data:
                self._data[namespace] = {}
            self._data[namespace][key] = family

    def get_fig_family(self, namespace: str, key: str) -> FigFamily | None:
        with self._lock:
            return self._data.get(namespace, {}).get(key)

    def put_all(self, families: list[FigFamily]):
        with self._lock:
            for f in families:
                self.put(f)

    def clear(self):
        with self._lock:
            self._data.clear()
