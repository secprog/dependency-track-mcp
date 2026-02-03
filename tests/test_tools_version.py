"""Tests for version tools."""

import pytest
from unittest.mock import AsyncMock, patch

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.exceptions import DependencyTrackError
from tests.utils import find_tool


@pytest.fixture
def register_tools():
    """Fixture that registers all tools."""
    from dependency_track_mcp.server import mcp
    return mcp


class TestGetVersionTool:
    """Tests for get_version tool."""

    @pytest.mark.asyncio
    async def test_get_version_success(self, register_tools):
        """Test getting version information."""
        mock_data = {
            "application": "Dependency-Track",
            "version": "4.10.0",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_version")
            assert tool is not None
            result = await tool.fn()
            
            assert "version" in result
            assert result["version"]["application"] == "Dependency-Track"
            mock_client.get.assert_called_once_with("/../version")

    @pytest.mark.asyncio
    async def test_get_version_error(self, register_tools):
        """Test get_version error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Connection failed"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_version")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result
            assert "Connection failed" in result["error"]
