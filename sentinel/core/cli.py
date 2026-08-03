"""Sentinel CLI entry point."""

from __future__ import annotations

import asyncio
import logging

import click

from sentinel.bus import Bus
from sentinel.core.orchestrator import Orchestrator


@click.group()
@click.option("--verbose", is_flag=True, help="Enable debug logging.")
def main(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@main.command()
@click.option("--module", multiple=True, help="Limit run to specific module.")
def run(module: tuple[str, ...]) -> None:
    bus = Bus()
    orchestrator = Orchestrator(bus=bus)
    modules = list(module) if module else None
    asyncio.run(orchestrator.run(modules))


@main.command()
def status() -> None:
    bus = Bus()
    click.echo("Sentinel local bus is available. No persistent daemon in v0.1.")


if __name__ == "__main__":
    main()
