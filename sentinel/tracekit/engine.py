"""TraceKit — Payload analysis toolkit."""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from sentinel.bus import Bus, Event
from sentinel.core.module import Module

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Cookie:
    domain: str
    name: str
    path: str
    secure: bool
    http_only: bool
    same_site: str | None
    samesite: str | None


@dataclass(frozen=True)
class URLTrace:
    url: str
    domain: str
    params: dict[str, list[str]]
    referrer: str | None = None
    utm_params: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class VendorScript:
    url: str
    domain: str
    inline: bool = False


@dataclass(frozen=True)
class TraceReport:
    cookies: list[Cookie] = field(default_factory=list)
    urls: list[URLTrace] = field(default_factory=list)
    vendor_scripts: list[VendorScript] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class TraceKit(Module):
    name = "tracekit"
    description = "Analyzes referral payloads, cookies, and vendor scripts."

    async def execute(self, bus: Bus) -> None:
        await bus.publish(Event(
            topic="tracekit.started",
            payload={"status": "running"},
            source=self.name,
        ))
        report = self._scan()
        await bus.publish(Event(
            topic="tracekit.completed",
            payload={
                "cookies": [c.__dict__ for c in report.cookies],
                "urls": [u.__dict__ for u in report.urls],
                "vendor_scripts": [v.__dict__ for v in report.vendor_scripts],
                "errors": report.errors,
            },
            source=self.name,
        ))

    def _scan(self) -> TraceReport:
        report = TraceReport()
        self._scan_browser_dirs(report)
        self._scan_sample_urls(report)
        return report

    def _scan_browser_dirs(self, report: TraceReport) -> None:
        bases = [
            Path.home() / ".config/google-chrome/Default",
            Path.home() / ".config/chromium/Default",
            Path.home() / ".config/microsoft-edge/Default",
        ]
        for base in bases:
            if not base.exists():
                continue
            cookies_db = base / "Cookies"
            if cookies_db.exists():
                report.urls.append(URLTrace(
                    url=f"file://{cookies_db}",
                    domain=base.name,
                    params={},
                ))
            history_db = base / "History"
            if history_db.exists():
                report.urls.append(URLTrace(
                    url=f"file://{history_db}",
                    domain=base.name,
                    params={},
                ))
            for manifest in base.glob("Extensions/*/manifest.json"):
                try:
                    data = json.loads(manifest.read_text())
                    for content in data.get("content_scripts", []):
                        for js in content.get("js", []):
                            report.vendor_scripts.append(VendorScript(
                                url=js,
                                domain=manifest.parent.parent.name,
                                inline=not js.startswith("http"),
                            ))
                except (json.JSONDecodeError, OSError):
                    continue

    def _scan_sample_urls(self, report: TraceReport) -> None:
        samples = [
            "https://example.com/page?utm_source=google&utm_medium=cpc&id=123",
            "https://tracker.example.com/pixel?ref=https://site.com&user=abc",
            "https://cdn.example.com/lib.js",
            "https://example.com/page",
        ]
        for raw in samples:
            parsed = urlparse(raw)
            params = {k: v for k, v in parse_qs(parsed.query).items()}
            utm = {k: v[0] for k, v in params.items() if k.startswith("utm_")}
            report.urls.append(URLTrace(
                url=raw,
                domain=parsed.netloc,
                params=params,
                utm_params=utm,
            ))
            if re.search(r"cdn|tracker|pixel", parsed.netloc):
                report.vendor_scripts.append(VendorScript(
                    url=raw,
                    domain=parsed.netloc,
                    inline=False,
                ))
