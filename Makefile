.PHONY: test lint format build clean install dev-install

test:
	pytest -q

lint:
	ruff check sentinel tests
	mypy sentinel

format:
	ruff format sentinel tests

build:
	python -m build

clean:
	rm -rf dist build *.egg-info .pytest_cache .mypy_cache .ruff_cache

install:
	pip install -e .

dev-install:
	pip install -e ".[dev]"
