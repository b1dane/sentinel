Sentinel — Local integrity agent
================================

Local-first diagnostic agent for browser, assistant, and system behavior analysis.
Field Integrity Systems. By Byron Dane Simmons.

## Features

| Module | Purpose |
|--------|---------|
| **tracekit** | Cookies, history, vendor scripts, data-flow maps (Chrome/Chromium/Edge/Firefox) |
| **promptfence** | Prompt-injection / adversarial input detection |
| **memoryaudit** | Assistant memory persistence and retention anomalies |
| **extensionscope** | Browser extension permissions and risk scoring |
| **stackcheck** | Process inventory, critical file hashes, integrity anomalies |

All scanning is local. No data leaves the machine.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\\Scripts\\activate
pip install -e ".[dev]"
```

## Usage

```bash
# Run all modules
sentinel run

# Run a subset
sentinel run --module tracekit --module stackcheck

# Machine-readable output
sentinel run --json

# Include built-in sample data (off by default)
sentinel run --include-samples

# List available modules
sentinel modules

# Status
sentinel status

# Verbose logging
sentinel --verbose run
```

## Configuration (environment)

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_WATCH_PATHS` | `~/.hermes/memories` | Colon-separated paths for PromptFence file watching |
| `SENTINEL_WATCH_TMP` | unset / false | Set to `1` to also watch `/tmp` |
| `SENTINEL_MAX_ENTRIES` | `100` | Max files MemoryAudit will index |

## Status

**Alpha (v0.1).** Core architecture and module engines are implemented.
Sample data is optional (`--include-samples`). Browser path coverage includes
Linux and macOS Chrome/Chromium/Edge plus basic Firefox cookie/history support.

## Development

```bash
make test    # pytest
make lint    # ruff + mypy
make format  # ruff format
```
