"""ExtensionScope — Browser extension auditor."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.bus import Bus, Event
from sentinel.core.module import Module

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Extension:
    id: str
    name: str
    version: str
    permissions: list[str]
    host_permissions: list[str]
    content_scripts: int
    manifest_path: str
    risk_score: int = 0


@dataclass(frozen=True)
class ExtensionScopeReport:
    extensions: list[Extension] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)


class ExtensionScope(Module):
    name = "extensionscope"
    description = "Audits browser extension permissions and listener behavior."

    def __init__(self) -> None:
        self._bases = [
            Path.home() / ".config/google-chrome/Default/Extensions",
            Path.home() / ".config/chromium/Default/Extensions",
            Path.home() / ".config/microsoft-edge/Default/Extensions",
        ]

    async def execute(self, bus: Bus) -> None:
        await bus.publish(Event(
            topic="extensionscope.started",
            payload={"status": "running"},
            source=self.name,
        ))
        report = self._scan_extension_dirs()
        await bus.publish(Event(
            topic="extensionscope.completed",
            payload={
                "extensions": [e.__dict__ for e in report.extensions],
                "anomalies": report.anomalies,
            },
            source=self.name,
        ))

    def _scan_extension_dirs(self) -> ExtensionScopeReport:
        report = ExtensionScopeReport()
        for base in self._bases:
            if not base.exists() or not base.is_dir():
                continue
            for ext_id in base.iterdir():
                if not ext_id.is_dir():
                    continue
                for version_dir in ext_id.iterdir():
                    manifest = version_dir / "manifest.json"
                    if not manifest.exists():
                        continue
                    try:
                        data = json.loads(manifest.read_text())
                        permissions = data.get("permissions", [])
                        host_permissions = data.get("host_permissions", [])
                        content_scripts = len(data.get("content_scripts", []))
                        risk = self._score_risk(permissions, host_permissions, content_scripts)
                        ext = Extension(
                            id=ext_id.name,
                            name=data.get("name", "unknown"),
                            version=data.get("version", "unknown"),
                            permissions=list(permissions),
                            host_permissions=list(host_permissions),
                            content_scripts=content_scripts,
                            manifest_path=str(manifest),
                            risk_score=risk,
                        )
                        report.extensions.append(ext)
                        if risk >= 7:
                            report.anomalies.append(f"high_risk_extension:{ext_id.name}:{risk}")
                    except (json.JSONDecodeError, OSError) as exc:
                        logger.debug("manifest parse failed %s: %s", manifest, exc)
                        continue
        report.extensions.sort(key=lambda e: e.risk_score, reverse=True)
        return report

    def _score_risk(self, permissions: list[str], host_permissions: list[str], content_scripts: int) -> int:
        score = 0
        sensitive = {
            "activeTab", "tabs", "cookies", "storage", "history",
            "bookmarks", "downloads", "webRequest", "webRequestBlocking",
        }
        for perm in permissions:
            if perm in sensitive or perm.startswith("*"):
                score += 2
        for host in host_permissions:
            if "<all_urls>" in host or "*://*/*" in host:
                score += 3
        score += min(content_scripts, 3)
        return min(score, 10)
