"""PromptFence — injection detection engine."""

from __future__ import annotations

import logging
from typing import Any

from sentinel.bus import Bus, Event
from sentinel.core.module import Module

logger = logging.getLogger(__name__)


class PromptFence(Module):
    name = "promptfence"
    description = "Detects prompt injection and adversarial input attempts."

    async def execute(self, bus: Bus) -> None:
        await bus.publish(Event(
            topic="promptfence.started",
            payload={"status": "running"},
            source=self.name,
        ))
        # TODO: replace with real input-stream inspection
        await bus.publish(Event(
            topic="promptfence.completed",
            payload={"status": "noop", "reason": "not_implemented"},
            source=self.name,
        ))
