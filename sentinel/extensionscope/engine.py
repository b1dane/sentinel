"""ExtensionScope — Browser extension auditor."""

from __future__ import annotations

import json
import logging
import os
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
    enabled: bool = True
    install_method: str = "normal"


@dataclass(frozen=True)
class ExtensionScopeReport:
    extensions: list[Extension] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)


class ExtensionScope(Module):
    name = "extensionscope"
    description = "Audits browser extension permissions and listener behavior."

    def __init__(self) -> None:
        home = Path.home()
        self._bases = [
            # Linux
            home / ".config/google-chrome/Default",
            home / ".config/chromium/Default",
            home / ".config/microsoft-edge/Default",
            # macOS
            home / "Library/Application Support/Google/Chrome/Default",
            home / "Library/Application Support/Chromium/Default",
            home / "Library/Application Support/Microsoft Edge/Default",
        ]
        self._extension_dirs = [
            "Extensions",
            "Extension State",
        ]

    async def execute(self, bus: Bus) -> None:
        await bus.publish(Event(
            topic="extensionscope.started",
            payload={"status": "running"},
            source=self.name,
        ))
        report = self._scan()
        await bus.publish(Event(
            topic="extensionscope.completed",
            payload={
                "extensions": [e.__dict__ for e in report.extensions],
                "anomalies": report.anomalies,
            },
            source=self.name,
        ))

    def _scan(self) -> ExtensionScopeReport:
        report = ExtensionScopeReport()
        for base in self._bases:
            if not base.exists() or not base.is_dir():
                continue
            self._scan_preferences(base, report)
            self._scan_extension_dirs(base, report)
        report.extensions.sort(key=lambda e: e.risk_score, reverse=True)
        return report

    def _scan_preferences(self, profile_dir: Path, report: ExtensionScopeReport) -> None:
        for name in ("Preferences", "Secure Preferences"):
            path = profile_dir / name
            if not path.exists():
                continue
            try:
                data = json.loads(path.read_text())
                settings = data.get("settings", {})
                extensions = settings.get("extensions", {})
                settings_list = extensions.get("settings", {})
                for ext_id, ext_data in settings_list.items():
                    if not isinstance(ext_data, dict):
                        continue
                    manifest_path = self._find_manifest(profile_dir, ext_id, ext_data.get("manifest", {}).get("version", ""))
                    if manifest_path is None:
                        report.anomalies.append(f"missing_manifest:{ext_id}")
                        continue
                    try:
                        manifest = json.loads(manifest_path.read_text())
                        permissions = manifest.get("permissions", [])
                        host_permissions = manifest.get("host_permissions", [])
                        content_scripts = len(manifest.get("content_scripts", []))
                        risk = self._score_risk(permissions, host_permissions, content_scripts)
                        report.extensions.append(Extension(
                            id=ext_id,
                            name=ext_data.get("manifest", {}).get("name", manifest.get("name", "unknown")),
                            version=ext_data.get("manifest", {}).get("version", manifest.get("version", "unknown")),
                            permissions=list(permissions),
                            host_permissions=list(host_permissions),
                            content_scripts=content_scripts,
                            manifest_path=str(manifest_path),
                            risk_score=risk,
                            enabled=not ext_data.get("disabled", False),
                            install_method=ext_data.get("install_type", "normal"),
                        ))
                    except (json.JSONDecodeError, OSError) as exc:
                        report.anomalies.append(f"manifest_read_failed:{ext_id}:{exc}")
            except (json.JSONDecodeError, OSError) as exc:
                logger.debug("preferences read failed %s: %s", path, exc)

    def _scan_extension_dirs(self, profile_dir: Path, report: ExtensionScopeReport) -> None:
        extensions_dir = profile_dir / "Extensions"
        if not extensions_dir.exists():
            return
        known_ids = {e.id for e in report.extensions}
        for ext_id in extensions_dir.iterdir():
            if not ext_id.is_dir():
                continue
            for version_dir in ext_id.iterdir():
                manifest = version_dir / "manifest.json"
                if not manifest.exists():
                    continue
                if ext_id.name not in known_ids:
                    report.anomalies.append(f"orphaned_extension_dir:{ext_id.name}")

    def _find_manifest(self, profile_dir: Path, ext_id: str, version: str) -> Path | None:
        candidates = [
            profile_dir / "Extensions" / ext_id / version / "manifest.json",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return None

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
