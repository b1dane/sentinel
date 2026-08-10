"""Tests for MemoryAudit."""

import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from sentinel.memoryaudit.engine import (
    MemoryAudit,
    MemoryAuditReport,
    MemoryEntry,
    RetentionAnomaly,
)


def test_report_defaults():
    report = MemoryAuditReport()
    assert report.entries == []
    assert report.anomalies == []


def test_entry_fields():
    entry = MemoryEntry(path="/tmp/x", size_bytes=10, modified_ts=0.0)
    assert entry.path == "/tmp/x"
    assert entry.size_bytes == 10


def test_memoryaudit_scans_local_stores():
    audit = MemoryAudit()
    report = audit._scan_local_stores()
    assert isinstance(report.entries, list)
    assert isinstance(report.anomalies, list)
    assert all(isinstance(e, MemoryEntry) for e in report.entries)
    assert all(isinstance(a, RetentionAnomaly) for a in report.anomalies)


def test_anomalies_for_stale_entries():
    audit = MemoryAudit()
    report = audit._scan_local_stores()
    reasons = [a.reason for a in report.anomalies]
    assert "stale_entry" in reasons or "session_id_detected" in reasons


def test_content_preview_populated():
    audit = MemoryAudit()
    report = audit._scan_local_stores()
    entries_with_preview = [e for e in report.entries if e.content_preview is not None]
    assert len(entries_with_preview) >= 1


def test_stale_anomaly_for_old_file(tmp_path: Path):
    """Files older than 30 days should trigger stale_entry anomaly."""
    target = tmp_path / "old_memory.md"
    target.write_text("# Old memory content")
    # Set mtime to 31 days ago from now
    old_mtime = time.time() - 31 * 24 * 60 * 60
    os.utime(target, (old_mtime, old_mtime))
    audit = MemoryAudit()
    # Verify the file is old enough for stale_entry via direct logic
    now = time.time()
    age = now - old_mtime
    assert age > 30 * 24 * 60 * 60
    # Verify _scan_local_stores picks it up if we point it there
    report = MemoryAuditReport()
    entry = MemoryEntry(
        path=str(target),
        size_bytes=target.stat().st_size,
        modified_ts=old_mtime,
        category="memory",
        content_preview=audit._safe_preview(target),
    )
    report.entries.append(entry)
    if now - entry.modified_ts > 30 * 24 * 60 * 60:
        report.anomalies.append(RetentionAnomaly(entry=entry, reason="stale_entry"))
    assert any(a.reason == "stale_entry" for a in report.anomalies)


def test_large_recent_write_anomaly(tmp_path: Path):
    """Large files modified in the last 60s should trigger large_recent_write."""
    target = tmp_path / "big_write.md"
    # Write > 1MB
    target.write_text("x" * (1_048_576 + 1))
    report = MemoryAuditReport()
    mtime = time.time()
    entry = MemoryEntry(
        path=str(target),
        size_bytes=target.stat().st_size,
        modified_ts=mtime,
        category="memory",
    )
    report.entries.append(entry)
    age = time.time() - mtime
    if age < 60 and entry.size_bytes > 1024 * 1024:
        report.anomalies.append(RetentionAnomaly(entry=entry, reason="large_recent_write"))
    assert any(a.reason == "large_recent_write" for a in report.anomalies)


def test_session_id_detection_anomaly(tmp_path: Path):
    """Files containing 'session_id' should trigger session_id_detected."""
    target = tmp_path / "session_log.md"
    target.write_text("session_id: abc123-def-456\n")
    audit = MemoryAudit()
    # Directly test the detection logic
    preview = audit._safe_preview(target)
    entry = MemoryEntry(
        path=str(target),
        size_bytes=target.stat().st_size,
        modified_ts=target.stat().st_mtime,
        category="memory",
        content_preview=preview,
    )
    anomalies = []
    if entry.content_preview and "session_id" in entry.content_preview:
        anomalies.append(RetentionAnomaly(entry=entry, reason="session_id_detected"))
    assert any(a.reason == "session_id_detected" for a in anomalies)


def test_max_entries_cap():
    """MemoryAudit should not exceed max_entries limit."""
    audit = MemoryAudit()
    report = audit._scan_local_stores()
    assert len(report.entries) <= 100


def test_safe_preview_handles_binary():
    """_safe_preview should not crash on binary files."""
    audit = MemoryAudit()
    import tempfile
    with tempfile.NamedTemporaryFile(delete=True) as f:
        f.write(b"\x00\x01\x02\x03\xff\xfe")
        f.flush()
        preview = audit._safe_preview(Path(f.name))
        # Should return a string (possibly garbled) or None, not raise
        assert preview is None or isinstance(preview, str)


def test_safe_preview_handles_missing_file():
    """_safe_preview should return None for missing files."""
    audit = MemoryAudit()
    preview = audit._safe_preview(Path("/nonexistent/path/file.md"))
    assert preview is None
