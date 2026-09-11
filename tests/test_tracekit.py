"""Tests for TraceKit."""

import sqlite3
from pathlib import Path

from sentinel.tracekit.engine import TraceKit, TraceReport, DataFlowMap


def test_trace_report_defaults():
    report = TraceReport()
    assert report.cookies == []
    assert report.urls == []
    assert report.vendor_scripts == []
    assert report.lineage_nodes == []
    assert report.lineage_edges == []
    assert report.data_flow_maps == []
    assert report.errors == []


def test_tracekit_sample_urls():
    kit = TraceKit()
    report = kit._scan(include_samples=True)
    url_domains = [u.domain for u in report.urls]
    assert "example.com" in url_domains
    assert any("google" in u.params.get("utm_source", [""])[0] for u in report.urls)


def test_tracekit_samples_off_by_default():
    kit = TraceKit()
    report = kit._scan(include_samples=False)
    # Sample domains should not appear unless real browser data happens to match
    sample_only = {"tracker.example.com", "cdn.example.com"}
    found = {u.domain for u in report.urls} & sample_only
    assert not found


def test_tracekit_vendor_script_detection():
    kit = TraceKit()
    report = kit._scan(include_samples=True)
    domains = [s.domain for s in report.vendor_scripts]
    assert "example.com" in domains or "cdn.example.com" in domains


def test_tracekit_lineage_graph():
    kit = TraceKit()
    report = kit._scan(include_samples=True)
    node_ids = [n.id for n in report.lineage_nodes]
    edge_count = len(report.lineage_edges)
    assert edge_count >= 1
    assert any("domain:" in nid for nid in node_ids)
    assert any("url:" in nid for nid in node_ids)


def test_tracekit_data_flow_maps():
    kit = TraceKit()
    report = kit._scan(include_samples=True)
    assert len(report.data_flow_maps) >= 1
    top = report.data_flow_maps[0]
    assert isinstance(top, DataFlowMap)
    assert top.request_count >= 1
    assert isinstance(top.param_names, list)
    assert isinstance(top.cookies_set, list)
    assert isinstance(top.scripts_loaded, list)


def test_read_cookies_from_sqlite(tmp_path: Path):
    db = tmp_path / "Cookies"
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE cookies (
            host_key TEXT, name TEXT, path TEXT, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER
        )
    """)
    cur.execute("INSERT INTO cookies VALUES ('example.com', 'sid', '/', 1, 0, 1)")
    conn.commit()
    conn.close()
    kit = TraceKit()
    report = TraceReport()
    kit._read_cookies(db, "test", report)
    assert len(report.cookies) == 1
    assert report.cookies[0].domain == "example.com"
    assert report.cookies[0].secure is True
    assert report.cookies[0].same_site == "1"


def test_read_history_from_sqlite(tmp_path: Path):
    db = tmp_path / "History"
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE urls (
            url TEXT, title TEXT, last_visit_time INTEGER
        )
    """)
    cur.execute("INSERT INTO urls VALUES ('https://example.com?a=1', 'Example', 0)")
    conn.commit()
    conn.close()
    kit = TraceKit()
    report = TraceReport()
    kit._read_history(db, "test", report)
    assert len(report.urls) == 1
    assert report.urls[0].domain == "example.com"
    assert report.urls[0].params.get("a") == ["1"]
