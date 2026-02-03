"""Pytest configuration and shared fixtures."""

import os
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastmcp import FastMCP

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.config import Settings


@pytest.fixture(autouse=True)
def setup_env():
    """Set up environment variables for testing."""
    os.environ["DEPENDENCY_TRACK_URL"] = "https://localhost:8080"  # Changed to HTTPS
    os.environ["DEPENDENCY_TRACK_API_KEY"] = "test-api-key"
    os.environ["MCP_OAUTH_ISSUER"] = "https://auth.example.com"  # Added OAuth issuer
    # Note: Not setting VERIFY_SSL here to preserve default=True behavior for tests
    yield
    # Clean up
    for key in [
        "DEPENDENCY_TRACK_URL",
        "DEPENDENCY_TRACK_API_KEY",
        "MCP_OAUTH_ISSUER",
        "DEPENDENCY_TRACK_VERIFY_SSL",
    ]:
        if key in os.environ:
            del os.environ[key]


@pytest.fixture
def mock_env_vars(monkeypatch):
    """Set environment variables for settings tests."""
    monkeypatch.setenv("DEPENDENCY_TRACK_URL", "https://test.example.com")
    monkeypatch.setenv("DEPENDENCY_TRACK_API_KEY", "test-api-key")
    monkeypatch.setenv("MCP_OAUTH_ISSUER", "https://auth.example.com")  # Added OAuth issuer
    yield


@pytest.fixture
def settings():
    """Create settings for tests."""
    return Settings(
        url="https://test.example.com",
        api_key="test-api-key",
        oauth_issuer="https://auth.example.com",  # Added OAuth issuer
    )


@pytest.fixture
def mcp():
    """Create a real FastMCP instance for testing."""
    return FastMCP(
        name="dependency-track-test",
        instructions="Test MCP server for dependency-track"
    )


@pytest.fixture
def mock_client():
    """Create a mock DependencyTrackClient."""
    client = DependencyTrackClient(
        Settings(
            url="https://test.example.com",
            api_key="test-api-key",
            oauth_issuer="https://auth.example.com",  # Added OAuth issuer
        )
    )
    client._client = AsyncMock(spec=httpx.AsyncClient)
    client._client.is_closed = False
    return client


@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    response = MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.is_success = True
    response.headers = {"X-Total-Count": "1"}
    response.json.return_value = {"test": "data"}
    return response
