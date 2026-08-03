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


def test_scan_preferences(tmp_path: Path):
    profile = tmp_path / "profile"
    profile.mkdir()
    ext_dir = profile / "Extensions" / "abc" / "1.0"
    ext_dir.mkdir(parents=True)
    manifest = ext_dir / "manifest.json"
    manifest.write_text(json.dumps({
        "name": "Test",
        "version": "1.0",
        "permissions": ["tabs", "cookies"],
        "host_permissions": ["https://*/*"],
        "content_scripts": [{"js": ["a.js"]}],
    }))
    prefs = {
        "settings": {
            "extensions": {
                "settings": {
                    "abc": {
                        "manifest": {"name": "Test", "version": "1.0"},
                        "install_type": "normal",
                        "disabled": False,
                    }
                }
            }
        }
    }
    (profile / "Preferences").write_text(json.dumps(prefs))
    scope = ExtensionScope()
    scope._bases = [profile]
    report = scope._scan()
    assert len(report.extensions) == 1
    assert report.extensions[0].name == "Test"
    assert report.extensions[0].risk_score >= 3


def test_orphaned_extension_dir(tmp_path: Path):
    profile = tmp_path / "profile"
    profile.mkdir()
    orphan = profile / "Extensions" / "orphan" / "1.0"
    orphan.mkdir(parents=True)
    (orphan / "manifest.json").write_text("{}")
    scope = ExtensionScope()
    scope._bases = [profile]
    report = scope._scan()
    assert any(a.startswith("orphaned_extension_dir:orphan") for a in report.anomalies)
