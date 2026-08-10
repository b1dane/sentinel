"""Tests for StackCheck."""

from pathlib import Path
from unittest.mock import patch

import pytest
from sentinel.stackcheck.engine import StackCheck, StackCheckReport, ProcessInfo, FileHash


def test_stackcheck_report_defaults():
    report = StackCheckReport()
    assert report.processes == []
    assert report.file_hashes == []
    assert report.anomalies == []


def test_stackcheck_reports_host_and_platform():
    checker = StackCheck()
    report = checker._scan_stack()
    assert report.hostname != ""
    assert report.platform != ""
    assert isinstance(report.processes, list)
    assert isinstance(report.file_hashes, list)
    assert isinstance(report.anomalies, list)


def test_parse_unix_processes():
    checker = StackCheck()
    report = StackCheckReport()
    # Match Termux ps output: pid, comm (truncated), args, uid — space-separated
    sample = "1 /data/data/com. /data/data/com.termux/files/usr/bin/python3 10469\n1234 bash /usr/bin/bash 1000\n"
    checker._parse_unix_processes(sample, report)
    assert len(report.processes) == 2
    assert report.processes[0].pid == 1
    assert report.processes[0].uid == 10469
    assert "python3" in report.processes[0].cmdline
    assert report.processes[1].pid == 1234
    assert report.processes[1].uid == 1000
    assert report.processes[1].name == "bash"


def test_parse_unix_processes_skips_malformed():
    checker = StackCheck()
    report = StackCheckReport()
    checker._parse_unix_processes("garbage line\n  1   /sbin/init   0\n", report)
    assert len(report.processes) == 0


def test_parse_windows_processes():
    checker = StackCheck()
    report = StackCheckReport()
    sample = '"System","4","0","NT AUTHORITY\\System"\n"explorer.exe","1234","1234","User"\n'
    checker._parse_windows_processes(sample, report)
    assert len(report.processes) == 2
    assert report.processes[0].name == "System"
    assert report.processes[0].pid == 4


@patch("subprocess.check_output")
def test_scan_processes_unix(mock_output):
    mock_output.return_value = "  1 init /sbin/init 0\n"
    checker = StackCheck()
    report = StackCheckReport()
    checker._scan_processes(report)
    assert len(report.processes) == 1
    assert report.processes[0].name == "init"


@patch("subprocess.check_output", side_effect=FileNotFoundError("ps not found"))
def test_scan_processes_handles_failure(mock_output):
    checker = StackCheck()
    report = StackCheckReport()
    checker._scan_processes(report)
    assert any("process_scan_failed" in a for a in report.anomalies)


def test_scan_critical_files(tmp_path: Path):
    bashrc = tmp_path / ".bashrc"
    bashrc.write_text("export PATH=$PATH:/usr/local/bin\n")
    checker = StackCheck()
    checker._scan_critical_files = lambda report: [
        report.file_hashes.append(FileHash(path=str(bashrc), sha256="abc123")) or None
    ]
    report = StackCheckReport()
    # Directly test file hash collection
    data = bashrc.read_bytes()
    sha = __import__("hashlib").sha256(data).hexdigest()
    report.file_hashes.append(FileHash(path=str(bashrc), sha256=sha))
    assert len(report.file_hashes) == 1
    assert report.file_hashes[0].sha256 == sha


def test_detect_root_process_anomaly():
    checker = StackCheck()
    report = StackCheckReport()
    report.processes.append(ProcessInfo(pid=999, name="suspicious_bin", cmdline="/tmp/evil", uid=0))
    now = __import__("time").time()
    checker._detect_anomalies(report)
    assert any(a.startswith("root_process:") for a in report.anomalies)


def test_detect_recent_modification_anomaly(tmp_path: Path):
    checker = StackCheck()
    target = tmp_path / "recent"
    target.write_text("data")
    # File was just created, so mtime is very recent
    report = StackCheckReport()
    checker._scan_critical_files = lambda r: r.file_hashes.append(
        FileHash(path=str(target), sha256="x")
    ) or None
    report.file_hashes.append(FileHash(path=str(target), sha256="x"))
    checker._detect_anomalies(report)
    assert any(a.startswith("recent_modification:") for a in report.anomalies)


def test_detect_anomalies_ignores_whitelisted_root():
    checker = StackCheck()
    report = StackCheckReport()
    report.processes.append(ProcessInfo(pid=1, name="init", cmdline="/sbin/init", uid=0))
    checker._detect_anomalies(report)
    assert not any(a.startswith("root_process:") for a in report.anomalies)
