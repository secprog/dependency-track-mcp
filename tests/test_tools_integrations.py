"""Tests for integration tools."""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.exceptions import DependencyTrackError
from tests.utils import find_tool


@pytest.fixture
def register_tools():
    """Fixture that registers all tools."""
    from dependency_track_mcp.server import mcp

    return mcp


class TestListOsvEcosystemsTool:
    """Tests for list_osv_ecosystems tool."""

    @pytest.mark.asyncio
    async def test_list_osv_ecosystems_success(self, register_tools):
        """Test listing active OSV ecosystems."""
        mock_ecosystems = [
            {"name": "PyPI", "enabled": True},
            {"name": "npm", "enabled": True},
            {"name": "Maven", "enabled": True},
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_ecosystems)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_osv_ecosystems")
            assert tool is not None
            result = await tool.fn()

            assert "ecosystems" in result
            assert result["ecosystems"] == mock_ecosystems
            mock_client.get.assert_called_once_with("/integration/osv/ecosystem")

    @pytest.mark.asyncio
    async def test_list_osv_ecosystems_empty(self, register_tools):
        """Test listing OSV ecosystems when none are active."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=[])
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_osv_ecosystems")
            assert tool is not None
            result = await tool.fn()

            assert "ecosystems" in result
            assert result["ecosystems"] == []

    @pytest.mark.asyncio
    async def test_list_osv_ecosystems_error(self, register_tools):
        """Test list_osv_ecosystems error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("OSV integration not available")
            error.details = {"status": 503}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_osv_ecosystems")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result
            assert "OSV integration not available" in str(result["error"])


class TestListInactiveOsvEcosystemsTool:
    """Tests for list_inactive_osv_ecosystems tool."""

    @pytest.mark.asyncio
    async def test_list_inactive_osv_ecosystems_success(self, register_tools):
        """Test listing inactive OSV ecosystems."""
        mock_ecosystems = [
            {"name": "Packagist", "enabled": False},
            {"name": "Go", "enabled": False},
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_ecosystems)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_inactive_osv_ecosystems")
            assert tool is not None
            result = await tool.fn()

            assert "ecosystems" in result
            assert result["ecosystems"] == mock_ecosystems
            mock_client.get.assert_called_once_with("/integration/osv/ecosystem/inactive")

    @pytest.mark.asyncio
    async def test_list_inactive_osv_ecosystems_empty(self, register_tools):
        """Test listing inactive OSV ecosystems when all are active."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=[])
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_inactive_osv_ecosystems")
            assert tool is not None
            result = await tool.fn()

            assert "ecosystems" in result
            assert result["ecosystems"] == []

    @pytest.mark.asyncio
    async def test_list_inactive_osv_ecosystems_error(self, register_tools):
        """Test list_inactive_osv_ecosystems error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Access denied")
            error.details = {"status": 403}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_inactive_osv_ecosystems")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result
            assert "Access denied" in str(result["error"])
