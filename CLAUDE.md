# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Dependency Track MCP Server - A Model Context Protocol (MCP) server enabling AI assistants to interact with OWASP Dependency Track for software composition analysis. Python 3.10+, uses FastMCP framework.

## Commands

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest                    # All tests
pytest -m unit           # Unit tests only
pytest -m integration    # Integration tests only
pytest tests/test_client.py  # Single test file
pytest -k "test_name"    # Run tests matching pattern

# Linting and formatting
ruff check .             # Check code style
ruff check . --fix       # Auto-fix issues
ruff format .            # Format code

# Run the server
dependency-track-mcp                   # Uses entry point
python -m dependency_track_mcp.main    # Direct module execution
```

## Architecture

### Layered Design
```
Client (with Bearer token)
    ↓
Main Server (main.py) - validates JWT via JWKS
    ↓
FastMCP Server (server.py) - registers tools
    ↓
Tool Handlers (tools/*.py) - call client methods
    ↓
DependencyTrackClient (client.py) [singleton] - async HTTP
    ↓
Dependency Track API
```

### Key Modules

- **main.py**: Main entry point with OAuth 2.1 authentication, FastAPI, JWT validation via JWKS
- **server.py**: FastMCP server initialization, registers tools
- **client.py**: Async HTTP client with singleton pattern, retry logic, rate limit handling
- **config.py**: Pydantic settings from environment variables (MCP_ and DEPENDENCY_TRACK_ prefixes), validates security requirements
- **oauth.py**: JWT validation, scope-based authorization middleware, JWKS caching
- **scopes.py**: Defines 9 MCP scopes for fine-grained access control
- **models.py**: Pydantic models for API types (Project, Component, Vulnerability, Finding, etc.)
- **exceptions.py**: Custom exception hierarchy mapping to HTTP status codes

### Tools Organization (tools/)

8 tool modules, each with a `register_*_tools(mcp)` function called from server.py:
- projects, components, vulnerabilities, findings, metrics, policies, bom, search

Tool pattern: async handlers decorated with `@mcp.tool()`, call client methods, return structured results.

### Security Model (Critical)

- **OAuth 2.1 is mandatory** - cannot be disabled, enforced at startup
- **HTTPS-only** - HTTP rejected unless `MCP_DEV_ALLOW_HTTP=true`
- **Scope-based authorization** - 9 scopes defined in scopes.py
- **Invalid config = server won't start** - fail-fast on security misconfiguration

### Configuration

MCP settings use `MCP_` prefix and backend settings use `DEPENDENCY_TRACK_`. Required:
- `DEPENDENCY_TRACK_URL` - Backend URL (must be HTTPS)
- `DEPENDENCY_TRACK_API_KEY` - API key for backend
- `MCP_OAUTH_ISSUER` - OAuth issuer URL

See `.env.example` for complete list.

## Testing

- Uses pytest with pytest-asyncio (async mode auto-enabled)
- HTTP mocking via respx
- Fixtures in `tests/conftest.py`
- Test files follow `test_*.py` pattern

## Code Style

- Line length: 100
- Ruff rules: E, F, I, N, W, UP
- Type hints throughout
- Async-first for all I/O operations
