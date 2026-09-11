"""StackCheck — Cross-layer integrity scanner."""

from __future__ import annotations

import hashlib
import logging
import platform
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.bus import Bus, Event
from sentinel.core.module import Module

logger = logging.getLogger(__name__)

# pid  name  args...  uid  (uid is the last integer; args must be non-empty)
_UNIX_PS_RE = re.compile(
    r"^\s*(\d+)\s+(\S+)\s+(.+?)\s+(\d+)\s*$",
)


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str
    cmdline: str
    uid: int | None = None


@dataclass(frozen=True)
class FileHash:
    path: str
    sha256: str


@dataclass
class StackCheckReport:
    hostname: str = ""
    platform: str = ""
    processes: list[ProcessInfo] = field(default_factory=list)
    file_hashes: list[FileHash] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)


class StackCheck(Module):
    name = "stackcheck"
    description = "Cross-layer integrity scanner for shell, browser, and assistant processes."

    async def execute(self, bus: Bus) -> None:
        await bus.publish(Event(
            topic="stackcheck.started",
            payload={"status": "running"},
            source=self.name,
        ))
        report = self._scan_stack()
        await bus.publish(Event(
            topic="stackcheck.completed",
            payload={
                "hostname": report.hostname,
                "platform": report.platform,
                "processes": [p.__dict__ for p in report.processes],
                "file_hashes": [h.__dict__ for h in report.file_hashes],
                "anomalies": report.anomalies,
            },
            source=self.name,
        ))

    def _scan_stack(self) -> StackCheckReport:
        report = StackCheckReport(
            hostname=platform.node(),
            platform=platform.platform(),
        )
        self._scan_processes(report)
        self._scan_critical_files(report)
        self._detect_anomalies(report)
        return report

    def _scan_processes(self, report: StackCheckReport) -> None:
        try:
            if platform.system() == "Windows":
                cmd = ["tasklist", "/fo", "csv", "/nh"]
                output = subprocess.check_output(cmd, text=True, timeout=10)
                self._parse_windows_processes(output, report)
            else:
                cmd = ["ps", "-eo", "pid=,comm=,args=,uid="]
                output = subprocess.check_output(cmd, text=True, timeout=10)
                self._parse_unix_processes(output, report)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.error("process scan failed: %s", exc)
            report.anomalies.append(f"process_scan_failed:{exc}")

    def _parse_unix_processes(self, output: str, report: StackCheckReport) -> None:
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            match = _UNIX_PS_RE.match(line)
            if not match:
                continue
            try:
                pid = int(match.group(1))
                name = match.group(2)
                cmdline = match.group(3).strip()
                uid = int(match.group(4))
                if not cmdline:
                    continue
                report.processes.append(ProcessInfo(pid=pid, name=name, cmdline=cmdline, uid=uid))
            except (ValueError, IndexError):
                continue

    def _parse_windows_processes(self, output: str, report: StackCheckReport) -> None:
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) < 2:
                continue
            try:
                name = parts[0]
                pid = int(parts[1])
                cmdline = parts[2] if len(parts) > 2 else ""
                report.processes.append(ProcessInfo(pid=pid, name=name, cmdline=cmdline))
            except (ValueError, IndexError):
                continue

    def _scan_critical_files(self, report: StackCheckReport) -> None:
        candidates = [
            Path.home() / ".bashrc",
            Path.home() / ".zshrc",
            Path.home() / ".config" / "gh" / "hosts.yml",
            Path("/etc/passwd"),
            Path("/etc/shadow"),
        ]
        for path in candidates:
            if not path.exists() or not path.is_file():
                continue
            try:
                data = path.read_bytes()
                sha = hashlib.sha256(data).hexdigest()
                report.file_hashes.append(FileHash(path=str(path), sha256=sha))
            except OSError as exc:
                report.anomalies.append(f"hash_failed:{path}:{exc}")

    def _detect_anomalies(self, report: StackCheckReport) -> None:
        now = time.time()
        for proc in report.processes:
            if proc.uid == 0 and proc.name not in {"init", "systemd", "kernel_task", "launchd_sim"}:
                report.anomalies.append(f"root_process:{proc.pid}:{proc.name}")
        for fh in report.file_hashes:
            path = Path(fh.path)
            try:
                mtime = path.stat().st_mtime
                if now - mtime < 3600:
                    report.anomalies.append(f"recent_modification:{fh.path}")
            except OSError:
                continue
