"""Tests for the local event bus."""

import asyncio
import pytest
from sentinel.bus import Bus, Event


@pytest.fixture
def bus():
    return Bus()


def test_event_creation():
    event = Event(topic="test", payload={"a": 1}, source="unit")
    assert event.topic == "test"
    assert event.source == "unit"
    assert event.payload == {"a": 1}
    assert event.timestamp.endswith("Z")


@pytest.mark.asyncio
async def test_publish_and_replay(bus):
    event = Event(topic="a", payload={"x": 1}, source="t1")
    await bus.publish(event)
    events = await bus.replay()
    assert len(events) == 1
    assert events[0].topic == "a"


@pytest.mark.asyncio
async def test_subscriber_called(bus):
    results = []

    async def handler(event: Event) -> None:
        results.append(event.topic)

    bus.subscribe("alpha", handler)
    await bus.publish(Event(topic="alpha", payload={}, source="pub"))
    assert results == ["alpha"]


@pytest.mark.asyncio
async def test_handler_error_does_not_broadcast(bus):
    calls = []

    async def bad_handler(event: Event) -> None:
        raise RuntimeError("boom")

    async def good_handler(event: Event) -> None:
        calls.append(1)

    bus.subscribe("topic", bad_handler)
    bus.subscribe("topic", good_handler)
    await bus.publish(Event(topic="topic", payload={}, source="pub"))
    assert len(calls) == 1
