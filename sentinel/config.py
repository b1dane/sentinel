"""Runtime configuration from environment variables."""

from __future__ import annotations

import os
from pathlib import Path


def watch_paths() -> list[Path]:
    """Paths PromptFence watches for recent text inputs."""
    raw = os.environ.get("SENTINEL_WATCH_PATHS", "").strip()
    if raw:
        paths = [Path(p).expanduser() for p in raw.split(":") if p.strip()]
    else:
        paths = [Path.home() / ".hermes" / "memories"]
    if os.environ.get("SENTINEL_WATCH_TMP", "").strip() in {"1", "true", "yes"}:
        paths.append(Path("/tmp"))
    return paths


def max_entries() -> int:
    """Upper bound on MemoryAudit file indexing."""
    raw = os.environ.get("SENTINEL_MAX_ENTRIES", "100").strip()
    try:
        value = int(raw)
        return max(1, value)
    except ValueError:
        return 100
