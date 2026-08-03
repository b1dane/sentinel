"""Base module contract."""

from __future__ import annotations

from abc import ABC, abstractmethod

from sentinel.bus import Bus


class Module(ABC):
    name: str = "base"
    description: str = ""

    @abstractmethod
    async def execute(self, bus: Bus) -> None:
        ...
