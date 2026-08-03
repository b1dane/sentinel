"""Tests for ExtensionScope."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from sentinel.extensionscope.engine import ExtensionScope, ExtensionScopeReport, Extension


def test_report_defaults():
    report = ExtensionScopeReport()
    assert report.extensions == []
    assert report.anomalies == []


def test_risk_score_for_broad_host_permission():
    scope = ExtensionScope()
    score = scope._score_risk(["tabs"], ["<all_urls>"], 1)
    assert score >= 3


def test_risk_score_for_sensitive_permission():
    scope = ExtensionScope()
    score = scope._score_risk(["cookies", "activeTab"], [], 0)
    assert score >= 2


def test_scan_parses_manifest(tmp_path: Path):
    scope = ExtensionScope()
    base = tmp_path / "extensions"
    ext_id = base / "abc"
    version_dir = ext_id / "1.0"
    version_dir.mkdir(parents=True)
    manifest = version_dir / "manifest.json"
    manifest.write_text(json.dumps({
        "name": "Test",
        "version": "1.0",
        "permissions": ["tabs", "cookies"],
        "host_permissions": ["https://*/*"],
        "content_scripts": [{"js": ["a.js"]}],
    }))
    scope._bases = [base]
    report = scope._scan_extension_dirs()
    assert len(report.extensions) == 1
    assert report.extensions[0].name == "Test"
    assert report.extensions[0].risk_score >= 3
