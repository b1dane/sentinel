"""Local event bus for Sentinel modules."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Event:
    topic: str
    payload: dict[str, Any]
    source: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


Handler = Callable[[Event], Coroutine[Any, Any, None]]


class Bus:
    def __init__(self, max_history: int = 1000) -> None:
        self._subscribers: dict[str, list[Handler]] = defaultdict(list)
        self._history: deque[Event] = deque(maxlen=max_history)
        self._lock = asyncio.Lock()

    async def publish(self, event: Event) -> None:
        async with self._lock:
            self._history.append(event)
            logger.debug("event topic=%s source=%s", event.topic, event.source)
        for handler in list(self._subscribers.get(event.topic, [])):
            try:
                await handler(event)
            except Exception as exc:  # noqa: BLE001
                logger.error("handler error topic=%s: %s", event.topic, exc)

    def subscribe(self, topic: str, handler: Handler) -> None:
        self._subscribers[topic].append(handler)

    async def replay(self, since: str | None = None) -> list[Event]:
        async with self._lock:
            events = list(self._history)
        if since:
            events = [e for e in events if e.timestamp >= since]
        return events
