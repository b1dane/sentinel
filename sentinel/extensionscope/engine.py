"""ExtensionScope — browser extension auditor."""

from __future__ import annotations

import logging
from typing import Any

from sentinel.bus import Bus, Event
from sentinel.core.module import Module

logger = logging.getLogger(__name__)


class ExtensionScope(Module):
    name = "extensionscope"
    description = "Audits browser extension permissions and listener behavior."

    async def execute(self, bus: Bus) -> None:
        await bus.publish(Event(
            topic="extensionscope.started",
            payload={"status": "running"},
            source=self.name,
        ))
        # TODO: replace with real browser extension inspection
        await bus.publish(Event(
            topic="extensionscope.completed",
            payload={"status": "noop", "reason": "not_implemented"},
            source=self.name,
        ))
