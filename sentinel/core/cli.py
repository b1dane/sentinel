"""Sentinel CLI entry point."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sentinel.bus import Bus
from sentinel.core.orchestrator import Orchestrator
from sentinel.core.registry import Registry

console = Console()


@click.group()
@click.option("--verbose", is_flag=True, help="Enable debug logging.")
def main(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@main.command()
@click.option("--module", multiple=True, help="Limit run to specific module(s).")
@click.option("--json", "output_json", is_flag=True, help="Emit machine-readable JSON.")
@click.option(
    "--include-samples",
    is_flag=True,
    default=False,
    help="Include built-in sample data in module scans (off by default).",
)
def run(module: tuple[str, ...], output_json: bool, include_samples: bool) -> None:
    bus = Bus(include_samples=include_samples)
    orchestrator = Orchestrator(bus=bus)
    modules = list(module) if module else None
    results = asyncio.run(orchestrator.run(modules))
    _print_results(results, output_json)


@main.command("modules")
def list_modules() -> None:
    """List available modules and their descriptions."""
    registry = Registry()
    table = Table(title="Sentinel modules", show_header=True, header_style="bold cyan")
    table.add_column("Name", style="green")
    table.add_column("Description")
    for mod in registry.all():
        table.add_row(mod.name, mod.description or "—")
    console.print(table)


@main.command()
def status() -> None:
    console.print(
        Panel(
            "Sentinel local bus is available.\nNo persistent daemon in v0.1.",
            title="Status",
            border_style="blue",
        )
    )


def _print_results(results: dict[str, Any], output_json: bool) -> None:
    if output_json:
        click.echo(json.dumps(results, indent=2))
        return

    if not results:
        console.print("[yellow]No modules ran.[/yellow]")
        return

    for module_name, payload in results.items():
        status = payload.get("status", "unknown")
        if status == "error":
            console.print(
                Panel(
                    Text(str(payload.get("error", "unknown error")), style="red"),
                    title=f"[{module_name}] error",
                    border_style="red",
                )
            )
            continue

        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("key", style="dim")
        table.add_column("value")

        anomalies = payload.get("anomalies", [])
        if anomalies:
            table.add_row("anomalies", str(len(anomalies)))
            for anomaly in anomalies[:10]:
                table.add_row("", f"• {anomaly}")
            if len(anomalies) > 10:
                table.add_row("", f"… and {len(anomalies) - 10} more")
        else:
            table.add_row("anomalies", "none")

        if "hostname" in payload:
            table.add_row("host", f"{payload['hostname']} ({payload.get('platform', '')})")
        if "processes" in payload:
            table.add_row("processes", str(len(payload["processes"])))
        if "file_hashes" in payload:
            table.add_row("file_hashes", str(len(payload["file_hashes"])))
        if "entries" in payload:
            table.add_row("memory_entries", str(len(payload["entries"])))
        if "extensions" in payload:
            table.add_row("extensions", str(len(payload["extensions"])))
        if "urls" in payload:
            table.add_row("urls", str(len(payload["urls"])))
        if "vendor_scripts" in payload:
            table.add_row("vendor_scripts", str(len(payload["vendor_scripts"])))
        if "inputs_scanned" in payload:
            table.add_row("inputs_scanned", str(payload["inputs_scanned"]))
            matches = payload.get("matches", [])
            table.add_row("injection_matches", str(len(matches)))

        border = "green" if status == "ok" else "yellow"
        console.print(Panel(table, title=f"[{module_name}] {status}", border_style=border))


if __name__ == "__main__":
    main()
