"""Tests for PromptFence."""

import pytest
from sentinel.promptfence.engine import PromptFence, PromptFenceReport


def test_report_mutable_fields():
    report = PromptFenceReport()
    report.inputs_scanned = 1
    report.anomalies.append("x")
    assert report.inputs_scanned == 1
    assert report.anomalies == ["x"]


@pytest.mark.asyncio
async def test_promptfence_detects_injection():
    bus = object()
    fence = PromptFence()
    # exercise module contract without needing real bus
    report = fence._scan_default_inputs()
    assert report.inputs_scanned == 8
    assert len(report.matches) >= 5
