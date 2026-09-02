"""Hunt event stream, consumed by the front-end investigation feed over SSE.

The interface's stance is to show the reasoning rather than a loading indicator:
this stream is therefore a deliverable, not debug trace. It carries only data
already minimized by the middleware.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class HuntEventType(StrEnum):
    HUNT_STARTED = "hunt_started"
    ITERATION_STARTED = "iteration_started"
    AGENT_REASONING = "agent_reasoning"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    TOOL_ERROR = "tool_error"
    FINDING_RECORDED = "finding_recorded"
    BUDGET_UPDATED = "budget_updated"
    BUDGET_ALERT = "budget_alert"
    BUDGET_PAUSED = "budget_paused"
    BUDGET_EXTENDED = "budget_extended"
    INTERRUPTED = "interrupted"
    CONCLUDED = "concluded"
    FAILED = "failed"


@dataclass(frozen=True)
class HuntEvent:
    hunt_id: str
    type: HuntEventType
    sequence: int
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "hunt_id": self.hunt_id,
            "type": self.type.value,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "payload": self.payload,
        }


class EventStream:
    """Broadcast to several subscribers, with history replay.

    An analyst who opens the feed mid-hunt must see the steps already gone by:
    history replay is part of the contract, not just the live stream.
    """

    def __init__(self, hunt_id: str) -> None:
        self.hunt_id = hunt_id
        self._history: list[HuntEvent] = []
        self._subscribers: list[asyncio.Queue[HuntEvent | None]] = []
        self._sequence = 0
        self._closed = False

    @property
    def history(self) -> list[HuntEvent]:
        return list(self._history)

    @property
    def closed(self) -> bool:
        return self._closed

    def publish(self, event_type: HuntEventType, **payload: Any) -> HuntEvent:
        self._sequence += 1
        event = HuntEvent(
            hunt_id=self.hunt_id,
            type=event_type,
            sequence=self._sequence,
            payload=payload,
        )
        self._history.append(event)
        for queue in self._subscribers:
            queue.put_nowait(event)
        return event

    def close(self) -> None:
        self._closed = True
        for queue in self._subscribers:
            queue.put_nowait(None)

    async def subscribe(self, *, replay: bool = True) -> Any:
        queue: asyncio.Queue[HuntEvent | None] = asyncio.Queue()
        self._subscribers.append(queue)
        try:
            if replay:
                for event in self._history:
                    yield event
            if self._closed:
                return
            while True:
                event = await queue.get()
                if event is None:
                    return
                yield event
        finally:
            if queue in self._subscribers:
                self._subscribers.remove(queue)
