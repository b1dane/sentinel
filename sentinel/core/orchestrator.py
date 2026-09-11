"""Orchestrator for Sentinel modules."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Sequence

from sentinel.bus import Bus
from sentinel.core.registry import Registry

logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(self, bus: Bus) -> None:
        self.bus = bus
        self.registry = Registry()

    async def run(self, modules: Sequence[str] | None = None) -> dict[str, Any]:
        selected = self.registry.all() if not modules else self.registry.select(modules)
        if not selected:
            logger.warning("No modules selected.")
            return {}
        tasks = [module.execute(self.bus) for module in selected]
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)

        # Map module name → exception (if any)
        errors: dict[str, str] = {}
        for module, outcome in zip(selected, outcomes):
            if isinstance(outcome, Exception):
                logger.exception("Module %s failed", module.name, exc_info=outcome)
                errors[module.name] = f"{type(outcome).__name__}: {outcome}"

        results = await self._build_results(selected)

        # Overlay hard failures that never emitted a completion event
        for name, message in errors.items():
            if name not in results or results[name].get("status") == "no_output":
                results[name] = {
                    "status": "error",
                    "error": message,
                }
        return results

    async def _build_results(self, modules: list) -> dict[str, Any]:
        results: dict[str, Any] = {}
        for module in modules:
            module_name = module.name
            completed_events = [
                e for e in await self.bus.replay()
                if e.source == module_name and e.topic.endswith(".completed")
            ]
            if not completed_events:
                results[module_name] = {
                    "status": "no_output",
                    "error": "Module did not emit a completion event.",
                }
                continue
            last = completed_events[-1]
            payload = dict(last.payload)
            payload["status"] = "ok"
            results[module_name] = payload
        return results
