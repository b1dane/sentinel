"""Tests for TraceKit."""

import pytest
from sentinel.tracekit.engine import TraceKit, TraceReport


def test_trace_report_defaults():
    report = TraceReport()
    assert report.cookies == []
    assert report.urls == []
    assert report.vendor_scripts == []
    assert report.errors == []


def test_tracekit_sample_urls():
    kit = TraceKit()
    report = kit._scan()
    url_domains = [u.domain for u in report.urls]
    assert "example.com" in url_domains
    assert any("google" in u.params.get("utm_source", [""])[0] for u in report.urls)


def test_tracekit_vendor_script_detection():
    kit = TraceKit()
    report = kit._scan()
    domains = [s.domain for s in report.vendor_scripts]
    assert "example.com" in domains or "cdn.example.com" in domains
