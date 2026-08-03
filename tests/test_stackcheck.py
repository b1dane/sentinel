"""Tests for StackCheck."""

from pathlib import Path

import pytest
from sentinel.stackcheck.engine import StackCheck, StackCheckReport


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
