"""Orchestrator for Sentinel modules."""

from __future__ import annotations

import asyncio
import logging
from typing import Sequence

from sentinel.bus import Bus
from sentinel.core.registry import Registry

logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(self, bus: Bus) -> None:
        self.bus = bus
        self.registry = Registry()

    async def run(self, modules: Sequence[str] | None = None) -> None:
        selected = self.registry.all() if not modules else self.registry.select(modules)
        if not selected:
            logger.warning("No modules selected.")
            return
        tasks = [module.execute(self.bus) for module in selected]
        await asyncio.gather(*tasks, return_exceptions=True)
