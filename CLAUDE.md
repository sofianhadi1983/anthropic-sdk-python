# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Official Anthropic Python SDK — a typed, httpx-based client library generated from an OpenAPI spec by [Stainless](https://stainlessapi.com). Supports sync/async clients, streaming, tool use, and platform integrations (AWS Bedrock, Google Vertex AI, Anthropic Foundry).

## Common Commands

```bash
# Setup
./scripts/bootstrap          # Install uv, Python, and all dependencies
uv sync --all-extras         # Alternative: just sync deps if uv is installed

# Testing (auto-starts Prism mock server on port 4010)
./scripts/test               # Full suite: runs Pydantic v1 + v2, Python 3.9 + 3.14
./scripts/test -k test_name  # Run a single test by name
UV_PYTHON=">=3.9.0" ./scripts/test  # Pin to one Python version (skips matrix)
./scripts/test --inline-snapshot=fix -n0  # Update inline snapshots (must disable xdist)
ANTHROPIC_LIVE=1 ./scripts/test --inline-snapshot=fix  # Refresh HTTP snapshots against real API

# Linting (runs ruff, pyright, mypy)
./scripts/lint               # Check all
./scripts/lint --fix         # Auto-fix ruff issues

# Formatting
./scripts/format             # ruff format + ruff check --fix
```

## Architecture

### Generated vs Hand-Written Code

Most of the SDK is **auto-generated from the OpenAPI spec** (tracked in `.stats.yml`). Generated files have the header comment: `File generated from our OpenAPI spec by Stainless.`

**Generated** (will be overwritten by the generator):
- `src/anthropic/_client.py` — `Anthropic` and `AsyncAnthropic` client classes
- `src/anthropic/_base_client.py` — core HTTP machinery
- `src/anthropic/resources/` — API resource methods (messages, completions, models, beta)
- `src/anthropic/types/` — Pydantic request/response models (120+ files)
- Most files under `src/anthropic/` at the top level

**Never overwritten by the generator** (safe to edit freely):
- `src/anthropic/lib/` — hand-written helper libraries (streaming, tools, bedrock, vertex, foundry)
- `examples/` — example scripts

### Client Structure

Dual sync/async clients built on httpx:
- `Anthropic(SyncAPIClient)` / `AsyncAnthropic(AsyncAPIClient)`
- Resources accessed as properties: `client.messages`, `client.completions`, `client.models`, `client.beta`
- Streaming via `Stream[T]` / `AsyncStream[T]` with SSE
- Responses wrapped in `APIResponse[T]` / `AsyncAPIResponse[T]`

### Key Libraries (`src/anthropic/lib/`)

- `streaming/` — `MessageStream` / `AsyncMessageStream` for high-level streaming with event callbacks
- `tools/` — `@beta_tool` / `@beta_async_tool` decorators, auto-generates JSON schema from type hints and docstrings; `BetaToolRunner` for agentic tool-use loops
- `bedrock/` — AWS Bedrock client with IAM auth
- `vertex/` — Google Vertex AI client with OAuth2 auth
- `foundry.py` — Anthropic Foundry workspace integration

### Testing

- Tests run against a **Prism mock server** (OpenAPI spec-driven) on `localhost:4010`
- Uses `pytest` with `pytest-asyncio` (auto mode) and `pytest-xdist` (parallel by default)
- Tests run against **both Pydantic v1 and v2** (v1 skipped on Python 3.14+)
- Snapshot testing via `inline-snapshot` — incompatible with xdist, use `-n0` when updating
- HTTP response snapshots refreshed with `ANTHROPIC_LIVE=1`
- Override test target: `TEST_API_BASE_URL=https://... ./scripts/test`

### Type Checking

Pyright in **strict mode** (`pythonVersion: "3.9"`) and mypy with strict settings. Both are run by `./scripts/lint`.

### Code Style

- Line length: 120 characters
- Formatter/linter: ruff (replaces black + isort)
- Imports: length-sorted, combined-as-imports, `typing_extensions` treated as stdlib
- Print statements (`T201`, `T203`) are flagged but not auto-fixed
