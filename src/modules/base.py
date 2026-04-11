from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseModule(ABC):
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    @abstractmethod
    def run(self, **kwargs) -> Dict[str, Any]:
        pass

    def health_check(self) -> Dict[str, Any]:
        return {"status": "unknown"}