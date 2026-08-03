"""Tests for MemoryAudit."""

from pathlib import Path

import pytest
from sentinel.memoryaudit.engine import MemoryAudit, MemoryAuditReport, MemoryEntry, RetentionAnomaly


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
