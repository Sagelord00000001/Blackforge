from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel

from blackforge.capabilities.models import CapabilityMeta


class CapabilityResult(BaseModel):
    success: bool
    output: Any = None
    error: str | None = None
    metadata: dict = {}


class Capability(ABC):
    @abstractmethod
    def meta(self) -> CapabilityMeta:
        ...

    @abstractmethod
    def execute(self, target: str, params: dict | None = None) -> CapabilityResult:
        ...
