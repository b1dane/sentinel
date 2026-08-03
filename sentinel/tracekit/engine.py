"""TraceKit — payload analysis toolkit."""

from __future__ import annotations

import logging
from typing import Any

from sentinel.bus import Bus, Event
from sentinel.core.module import Module

logger = logging.getLogger(__name__)


class TraceKit(Module):
    name = "tracekit"
    description = "Analyzes referral payloads, cookies, and vendor scripts."

    async def execute(self, bus: Bus) -> None:
        await bus.publish(Event(
            topic="tracekit.started",
            payload={"status": "running"},
            source=self.name,
        ))
        # TODO: replace with real browser/network inspection
        await bus.publish(Event(
            topic="tracekit.completed",
            payload={"status": "noop", "reason": "not_implemented"},
            source=self.name,
        ))
