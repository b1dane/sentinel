"""Tests for ExtensionScope."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from sentinel.extensionscope.engine import (
    Extension,
    ExtensionScope,
    ExtensionScopeReport,
)


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


def test_risk_score_capped_at_10():
    scope = ExtensionScope()
    score = scope._score_risk(["tabs", "cookies", "storage", "history", "bookmarks", "downloads"], ["*://*/*"], 10)
    assert score <= 10


def test_risk_score_zero_for_benign_extension():
    scope = ExtensionScope()
    score = scope._score_risk([], [], 0)
    assert score == 0


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


def test_scan_preferences_with_disabled_extension(tmp_path: Path):
    profile = tmp_path / "profile"
    profile.mkdir()
    ext_dir = profile / "Extensions" / "abc" / "1.0"
    ext_dir.mkdir(parents=True)
    manifest = ext_dir / "manifest.json"
    manifest.write_text(json.dumps({
        "name": "Disabled Test",
        "version": "1.0",
        "permissions": ["tabs"],
        "host_permissions": [],
        "content_scripts": [],
    }))
    prefs = {
        "settings": {
            "extensions": {
                "settings": {
                    "abc": {
                        "manifest": {"name": "Disabled Test", "version": "1.0"},
                        "install_type": "normal",
                        "disabled": True,
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
    assert report.extensions[0].enabled is False


def test_scan_preferences_no_preferences_file(tmp_path: Path):
    profile = tmp_path / "profile"
    profile.mkdir()
    scope = ExtensionScope()
    scope._bases = [profile]
    report = scope._scan()
    assert len(report.extensions) == 0


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


def test_orphaned_dir_not_flagged_when_in_prefs(tmp_path: Path):
    """Extension in both Preferences and Extensions dir should not be orphaned."""
    profile = tmp_path / "profile"
    profile.mkdir()
    ext_dir = profile / "Extensions" / "abc" / "1.0"
    ext_dir.mkdir(parents=True)
    (ext_dir / "manifest.json").write_text(json.dumps({"name": "Known", "version": "1.0"}))
    prefs = {
        "settings": {
            "extensions": {
                "settings": {
                    "abc": {
                        "manifest": {"name": "Known", "version": "1.0"},
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
    assert not any(a.startswith("orphaned_extension_dir:abc") for a in report.anomalies)


def test_missing_manifest_anomaly(tmp_path: Path):
    """Extension in Preferences but with missing manifest file should be flagged."""
    profile = tmp_path / "profile"
    profile.mkdir()
    prefs = {
        "settings": {
            "extensions": {
                "settings": {
                    "abc": {
                        "manifest": {"name": "Ghost", "version": "1.0"},
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
    assert any(a.startswith("missing_manifest:abc") for a in report.anomalies)


def test_extensions_sorted_by_risk_score():
    scope = ExtensionScope()
    # Verify _score_risk produces distinct scores for ordering
    low = scope._score_risk([], [], 0)
    mid = scope._score_risk(["tabs"], [], 0)
    high = scope._score_risk(["cookies", "tabs"], ["<all_urls>"], 3)
    assert low < mid < high
