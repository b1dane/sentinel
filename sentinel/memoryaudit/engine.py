"""MemoryAudit — Persistence and retention tracker."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.bus import Bus, Event
from sentinel.core.module import Module

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MemoryEntry:
    path: str
    size_bytes: int
    modified_ts: float
    ttl_seconds: float | None = None
    category: str | None = None
    session_id: str | None = None


@dataclass(frozen=True)
class RetentionAnomaly:
    entry: MemoryEntry
    reason: str


@dataclass
class MemoryAuditReport:
    entries: list[MemoryEntry] = field(default_factory=list)
    anomalies: list[RetentionAnomaly] = field(default_factory=list)


class MemoryAudit(Module):
    name = "memoryaudit"
    description = "Tracks assistant memory persistence and retention anomalies."

    async def execute(self, bus: Bus) -> None:
        await bus.publish(Event(
            topic="memoryaudit.started",
            payload={"status": "running"},
            source=self.name,
        ))
        report = self._scan_local_stores()
        await bus.publish(Event(
            topic="memoryaudit.completed",
            payload={
                "entries": [e.__dict__ for e in report.entries],
                "anomalies": [a.__dict__ for a in report.anomalies],
            },
            source=self.name,
        ))

    def _scan_local_stores(self) -> MemoryAuditReport:
        report = MemoryAuditReport()
        bases = [
            (Path.home() / ".hermes" / "memories", "memory"),
            (Path.home() / ".hermes" / "skills", "skill"),
            (Path.home() / ".config" / "gh", "config"),
        ]
        now = time.time()
        for base, category in bases:
            if not base.exists() or not base.is_dir():
                continue
            for root, _, files in os.walk(base):
                for name in files:
                    path = Path(root) / name
                    try:
                        stat = path.stat()
                        entry = MemoryEntry(
                            path=str(path),
                            size_bytes=stat.st_size,
                            modified_ts=stat.st_mtime,
                            category=category,
                        )
                        report.entries.append(entry)
                        age = now - stat.st_mtime
                        if age > 30 * 24 * 60 * 60:
                            report.anomalies.append(RetentionAnomaly(
                                entry=entry,
                                reason="stale_entry",
                            ))
                        if category == "memory" and age < 60 and stat.st_size > 1024 * 1024:
                            report.anomalies.append(RetentionAnomaly(
                                entry=entry,
                                reason="large_recent_write",
                            ))
                    except OSError:
                        continue
        self._detect_cross_session_carryover(report, now)
        return report

    def _detect_cross_session_carryover(self, report: MemoryAuditReport, now: float) -> None:
        user_memory_dir = Path.home() / ".hermes" / "memories"
        if not user_memory_dir.exists():
            return
        sessions: dict[str, list[float]] = {}
        for path in user_memory_dir.rglob("*"):
            if not path.is_file():
                continue
            try:
                content = path.read_text(errors="ignore")
                if "session_id" not in content:
                    continue
                stat = path.stat()
                sessions.setdefault(path.name, []).append(stat.st_mtime)
            except OSError:
                continue
        for session_name, mtimes in sessions.items():
            if len(mtimes) > 1:
                report.anomalies.append(RetentionAnomaly(
                    entry=MemoryEntry(
                        path=str(user_memory_dir / session_name),
                        size_bytes=0,
                        modified_ts=mtimes[-1],
                        category="memory",
                        session_id=session_name,
                    ),
                    reason="cross_session_carryover",
                ))
