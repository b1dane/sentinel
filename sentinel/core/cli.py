"""Sentinel CLI entry point."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Sequence

import click

from sentinel.bus import Bus
from sentinel.core.orchestrator import Orchestrator


@click.group()
@click.option("--verbose", is_flag=True, help="Enable debug logging.")
def main(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@main.command()
@click.option("--module", multiple=True, help="Limit run to specific module(s).")
@click.option("--json", "output_json", is_flag=True, help="Emit machine-readable JSON.")
def run(module: tuple[str, ...], output_json: bool) -> None:
    bus = Bus()
    orchestrator = Orchestrator(bus=bus)
    modules = list(module) if module else None
    results = asyncio.run(orchestrator.run(modules))
    _print_results(results, output_json)


def _print_results(results: dict[str, Any], output_json: bool) -> None:
    if output_json:
        click.echo(json.dumps(results, indent=2))
        return
    for module_name, payload in results.items():
        click.echo(f"[{module_name}]")
        if payload.get("status") == "error":
            click.echo(f"  error: {payload.get('error')}")
            continue
        anomalies = payload.get("anomalies", [])
        if anomalies:
            click.echo(f"  anomalies: {len(anomalies)}")
            for anomaly in anomalies[:10]:
                click.echo(f"    - {anomaly}")
        else:
            click.echo("  anomalies: none")
        if "hostname" in payload:
            click.echo(f"  host: {payload['hostname']} ({payload.get('platform', '')})")
        if "processes" in payload:
            click.echo(f"  processes: {len(payload['processes'])}")
        if "file_hashes" in payload:
            click.echo(f"  file_hashes: {len(payload['file_hashes'])}")
        if "entries" in payload:
            click.echo(f"  memory_entries: {len(payload['entries'])}")
        if "extensions" in payload:
            click.echo(f"  extensions: {len(payload['extensions'])}")
        if "urls" in payload:
            click.echo(f"  urls: {len(payload['urls'])}")
        if "vendor_scripts" in payload:
            click.echo(f"  vendor_scripts: {len(payload['vendor_scripts'])}")
        if "inputs_scanned" in payload:
            click.echo(f"  inputs_scanned: {payload['inputs_scanned']}")
            matches = payload.get("matches", [])
            click.echo(f"  injection_matches: {len(matches)}")
        click.echo()


@main.command()
def status() -> None:
    click.echo("Sentinel local bus is available. No persistent daemon in v0.1.")


if __name__ == "__main__":
    main()
