"""MemoryAudit — Persistence and retention tracker."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.bus import Bus, Event
from sentinel.config import max_entries
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
    content_preview: str | None = None


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
        # Flat string codes for consistent CLI / JSON consumers
        anomaly_codes = [f"{a.reason}:{a.entry.path}" for a in report.anomalies]
        await bus.publish(Event(
            topic="memoryaudit.completed",
            payload={
                "entries": [e.__dict__ for e in report.entries],
                "anomalies": anomaly_codes,
                "anomaly_details": [
                    {
                        "entry": a.entry.__dict__,
                        "reason": a.reason,
                    }
                    for a in report.anomalies
                ],
            },
            source=self.name,
        ))

    def _scan_local_stores(self) -> MemoryAuditReport:
        report = MemoryAuditReport()
        bases = [
            (Path.home() / ".hermes" / "memories", "memory"),
            (Path.home() / ".config" / "gh", "config"),
        ]
        now = time.time()
        limit = max_entries()
        for base, category in bases:
            if not base.exists() or not base.is_dir():
                continue
            for root, _, files in os.walk(base):
                for name in files:
                    if len(report.entries) >= limit:
                        break
                    path = Path(root) / name
                    try:
                        stat = path.stat()
                        content_preview = self._safe_preview(path, max_bytes=128)
                        entry = MemoryEntry(
                            path=str(path),
                            size_bytes=stat.st_size,
                            modified_ts=stat.st_mtime,
                            category=category,
                            content_preview=content_preview,
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
                        if category == "memory" and content_preview and "session_id" in content_preview:
                            report.anomalies.append(RetentionAnomaly(
                                entry=entry,
                                reason="session_id_detected",
                            ))
                    except OSError:
                        continue
                if len(report.entries) >= limit:
                    break
            if len(report.entries) >= limit:
                break
        return report

    def _safe_preview(self, path: Path, max_bytes: int = 256) -> str | None:
        try:
            with path.open("r", errors="ignore") as f:
                return f.read(max_bytes)
        except OSError:
            return None
