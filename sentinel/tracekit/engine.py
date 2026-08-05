"""TraceKit — Payload analysis toolkit."""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from collections import defaultdict
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
class LineageNode:
    id: str
    label: str
    kind: str


@dataclass(frozen=True)
class LineageEdge:
    source: str
    target: str
    label: str


@dataclass(frozen=True)
class DataFlowMap:
    domain: str
    request_count: int
    param_names: list[str]
    cookies_set: list[str]
    scripts_loaded: list[str]
    redirects: int


@dataclass
class TraceReport:
    cookies: list[Cookie] = field(default_factory=list)
    urls: list[URLTrace] = field(default_factory=list)
    vendor_scripts: list[VendorScript] = field(default_factory=list)
    lineage_nodes: list[LineageNode] = field(default_factory=list)
    lineage_edges: list[LineageEdge] = field(default_factory=list)
    data_flow_maps: list[DataFlowMap] = field(default_factory=list)
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
                "lineage_nodes": [n.__dict__ for n in report.lineage_nodes],
                "lineage_edges": [e.__dict__ for e in report.lineage_edges],
                "data_flow_maps": [m.__dict__ for m in report.data_flow_maps],
                "errors": report.errors,
            },
            source=self.name,
        ))

    def _scan(self) -> TraceReport:
        report = TraceReport()
        self._scan_browser_dirs(report)
        self._scan_sample_urls(report)
        self._build_lineage(report)
        self._build_data_flow_maps(report)
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
                self._read_cookies(cookies_db, base.name, report)
            history_db = base / "History"
            if history_db.exists():
                self._read_history(history_db, base.name, report)
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

    def _read_cookies(self, db_path: Path, profile: str, report: TraceReport) -> None:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT host_key, name, path, is_secure, is_httponly, samesite FROM cookies LIMIT 200")
            for row in cur.fetchall():
                report.cookies.append(Cookie(
                    domain=row["host_key"],
                    name=row["name"],
                    path=row["path"],
                    secure=bool(row["is_secure"]),
                    http_only=bool(row["is_httponly"]),
                    same_site=str(row["samesite"]) if row["samesite"] is not None else None,
                    samesite=None,
                ))
            conn.close()
        except (sqlite3.Error, OSError) as exc:
            report.errors.append(f"cookie_read_failed:{profile}:{exc}")

    def _read_history(self, db_path: Path, profile: str, report: TraceReport) -> None:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT 50")
            for row in cur.fetchall():
                url = row["url"]
                parsed = urlparse(url)
                params = {k: v for k, v in parse_qs(parsed.query).items()}
                utm = {k: v[0] for k, v in params.items() if k.startswith("utm_")}
                report.urls.append(URLTrace(
                    url=url,
                    domain=parsed.netloc,
                    params=params,
                    utm_params=utm,
                ))
            conn.close()
        except (sqlite3.Error, OSError) as exc:
            report.errors.append(f"history_read_failed:{profile}:{exc}")

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

    def _build_lineage(self, report: TraceReport) -> None:
        nodes: dict[str, LineageNode] = {}
        edges: list[LineageEdge] = []

        def ensure_node(ident: str, label: str, kind: str) -> None:
            if ident not in nodes:
                nodes[ident] = LineageNode(id=ident, label=label, kind=kind)

        for url in report.urls:
            domain = url.domain
            ensure_node(f"domain:{domain}", domain, "domain")
            ensure_node(f"url:{url.url}", url.url, "url")
            edges.append(LineageEdge(source=f"domain:{domain}", target=f"url:{url.url}", label="hosts"))
            for param in url.params:
                ensure_node(f"param:{param}", param, "param")
                edges.append(LineageEdge(source=f"url:{url.url}", target=f"param:{param}", label="query"))
        for script in report.vendor_scripts:
            ensure_node(f"script:{script.url}", script.url, "script")
            ensure_node(f"domain:{script.domain}", script.domain, "domain")
            edges.append(LineageEdge(source=f"domain:{script.domain}", target=f"script:{script.url}", label="serves"))

        report.lineage_nodes = list(nodes.values())
        report.lineage_edges = edges

    def _build_data_flow_maps(self, report: TraceReport) -> None:
        domain_stats: dict[str, dict[str, Any]] = defaultdict(lambda: {
            "request_count": 0,
            "param_names": set(),
            "cookies_set": set(),
            "scripts_loaded": set(),
            "redirects": 0,
        })
        for url in report.urls:
            stats = domain_stats[url.domain]
            stats["request_count"] += 1
            stats["param_names"].update(url.params.keys())
            if url.referrer:
                stats["redirects"] += 1
        for cookie in report.cookies:
            domain_stats[cookie.domain]["cookies_set"].add(cookie.name)
        for script in report.vendor_scripts:
            domain_stats[script.domain]["scripts_loaded"].add(script.url)
        for domain, stats in domain_stats.items():
            report.data_flow_maps.append(DataFlowMap(
                domain=domain,
                request_count=stats["request_count"],
                param_names=sorted(stats["param_names"]),
                cookies_set=sorted(stats["cookies_set"]),
                scripts_loaded=sorted(stats["scripts_loaded"]),
                redirects=stats["redirects"],
            ))
        report.data_flow_maps.sort(key=lambda m: m.request_count, reverse=True)
