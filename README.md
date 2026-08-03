Sentinel — Local integrity agent
===============================

Local-first diagnostic agent for browser, assistant, and system behavior analysis.
Field Integrity Systems. By Byron Dane Simmons.

## Setup

```bash
cd 02_Projects/Sentinel
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Run

```bash
sentinel run
sentinel run --module tracekit
```

## Status

Alpha. Architecture scaffolded. Module implementations are no-ops pending real inspection logic.
