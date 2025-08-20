# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

rpki-client-web is a Python web service that wraps [rpki-client](https://www.rpki-client.org/) and exposes its results via HTTP API and Prometheus metrics. It runs rpki-client periodically to validate RPKI objects and tracks various statistics about repository fetching, warnings, and errors.

## Development Commands

### Testing
```bash
# Run all tests
uv run pytest tests/ -v

# Run specific test file
uv run pytest tests/test_outputparser.py -v

# Run single test
uv run pytest tests/test_outputparser.py::test_parse_failed_fetch -v
```

### Code Quality
```bash
# Lint and fix code
uv run ruff check --fix rpkiclientweb/

# Format code
uv run ruff format rpkiclientweb/
```

### Running the Application
```bash
# Run with config file
python -m rpkiclientweb -v -c config.yml

# Docker development
docker run -p 8888:8888 --detach --name rpki-client-web -v ./config:/config ghcr.io/ties/rpki-client-web:dev
```

## Architecture Overview

### Core Components

1. **RpkiClient** (`rpki_client.py`) - Main orchestrator that runs rpki-client and processes output
2. **OutputParser** (`outputparser.py`) - Parses rpki-client stderr output for warnings and fetch status
3. **Models** (`models.py`) - Data classes for warnings, fetch status, and other structured data
4. **Parsing** (`parsing.py`) - Low-level regex-based parsing of rpki-client log lines
5. **Metrics** (`metrics.py`) - Prometheus metrics definitions
6. **Web** (`web.py`) - HTTP API endpoints for results, config, and metrics

### Data Flow

1. **Execution**: `RpkiClient` runs rpki-client subprocess periodically
2. **Parsing**: `OutputParser` processes stderr using regex patterns in `parsing.py`
3. **Metrics**: Parsed data updates Prometheus metrics with normalized URIs
4. **API**: Web endpoints serve results, metrics, and validated objects

### Key Design Patterns

- **URI Normalization**: Raw URIs are preserved in data structures. Normalization happens only when creating Prometheus metric labels using `parse_proto_host_from_url()` to reduce cardinality
- **Dataclass Equality**: Models use `@dataclass(frozen=True)` for immutable, hashable objects that work correctly with `in` operations on sets/lists
- **Generator-based Parsing**: Parsing functions yield results rather than returning lists for memory efficiency
- **Metric Lifecycle**: Tracks repositories over time, removing metrics for unreferenced repos after 24h

### Testing Strategy

- **Input-driven Tests**: Most tests use real rpki-client output files from `tests/inputs/`
- **Parsing Validation**: Tests verify specific warnings/errors are correctly extracted
- **Metric Behavior**: Tests validate metric creation, updates, and cleanup
- **Raw URI Preservation**: Tests expect raw URIs in parsed objects, normalization happens at metric level

### Critical Files

- `rpkiclientweb/parsing.py` - Contains regex patterns matching rpki-client log formats
- `rpkiclientweb/models.py` - Data structures with careful attention to `__eq__` and `__hash__` behavior
- `rpkiclientweb/rpki_client.py` - Metric label creation with URI normalization
- `tests/inputs/` - Real-world rpki-client output for comprehensive testing

## Pre-Commit Validation

Before committing changes, always run these validation commands to ensure code quality:

```bash
# Lint and fix code
uv run ruff check --fix rpkiclientweb/

# Format code
uv run ruff format rpkiclientweb/

# Run tests
uv run pytest tests/ -v
```

These steps ensure that all code follows the project's formatting standards, passes linting checks, and doesn't break existing functionality.

## Important Notes

- When modifying URI handling, remember normalization happens at metric creation time, not parse time
- The `normalize_object_uri()` function handles `.rsync/` prefixes and `#hash` fragments for ManifestObjectWarning
- Tests may break if dataclass equality behavior changes - prefer factory functions over computed properties
- The project uses uv for dependency management and hatchling for builds
