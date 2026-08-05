FROM python:3.11-slim AS base

LABEL maintainer="Byron Dane Simmons <byron.dane@gmail.com>"
LABEL description="Sentinel — local integrity agent for browser, assistant, and system behavior analysis."

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY sentinel/ ./sentinel/
COPY tests/ ./tests/

RUN pip install --no-cache-dir -e .

ENTRYPOINT ["sentinel"]
CMD ["run"]
