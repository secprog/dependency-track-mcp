"""Tests for badge tools."""

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


class TestGetVulnerabilityBadgeByUuidTool:
    """Tests for get_vulnerability_badge_by_uuid tool."""

    @pytest.mark.asyncio
    async def test_get_vulnerability_badge_by_uuid_success(self, register_tools):
        """Test getting vulnerability badge by UUID."""
        mock_badge = '<svg>...</svg>'
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_badge)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_vulnerability_badge_by_uuid")
            assert tool is not None
            result = await tool.fn(project_uuid="test-uuid")
            
            assert "badge" in result
            assert result["badge"] == mock_badge
            mock_client.get.assert_called_once_with("/badge/vulns/project/test-uuid")

    @pytest.mark.asyncio
    async def test_get_vulnerability_badge_by_uuid_error(self, register_tools):
        """Test get_vulnerability_badge_by_uuid error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Project not found"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_vulnerability_badge_by_uuid")
            assert tool is not None
            result = await tool.fn(project_uuid="bad-uuid")

            assert "error" in result


class TestGetVulnerabilityBadgeByNameTool:
    """Tests for get_vulnerability_badge_by_name tool."""

    @pytest.mark.asyncio
    async def test_get_vulnerability_badge_by_name_success(self, register_tools):
        """Test getting vulnerability badge by name and version."""
        mock_badge = '<svg>...</svg>'
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_badge)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_vulnerability_badge_by_name")
            assert tool is not None
            result = await tool.fn(project_name="my-project", project_version="1.0.0")
            
            assert "badge" in result
            assert result["badge"] == mock_badge
            mock_client.get.assert_called_once_with("/badge/vulns/project/my-project/1.0.0")

    @pytest.mark.asyncio
    async def test_get_vulnerability_badge_by_name_error(self, register_tools):
        """Test get_vulnerability_badge_by_name error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Project not found"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_vulnerability_badge_by_name")
            assert tool is not None
            result = await tool.fn(project_name="bad-project", project_version="1.0.0")

            assert "error" in result


class TestGetViolationsBadgeByUuidTool:
    """Tests for get_violations_badge_by_uuid tool."""

    @pytest.mark.asyncio
    async def test_get_violations_badge_by_uuid_success(self, register_tools):
        """Test getting violations badge by UUID."""
        mock_badge = '<svg>...</svg>'
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_badge)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_violations_badge_by_uuid")
            assert tool is not None
            result = await tool.fn(project_uuid="test-uuid")
            
            assert "badge" in result
            assert result["badge"] == mock_badge
            mock_client.get.assert_called_once_with("/badge/violations/project/test-uuid")

    @pytest.mark.asyncio
    async def test_get_violations_badge_by_uuid_error(self, register_tools):
        """Test get_violations_badge_by_uuid error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Project not found"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_violations_badge_by_uuid")
            assert tool is not None
            result = await tool.fn(project_uuid="bad-uuid")

            assert "error" in result


class TestGetViolationsBadgeByNameTool:
    """Tests for get_violations_badge_by_name tool."""

    @pytest.mark.asyncio
    async def test_get_violations_badge_by_name_success(self, register_tools):
        """Test getting violations badge by name and version."""
        mock_badge = '<svg>...</svg>'
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_badge)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_violations_badge_by_name")
            assert tool is not None
            result = await tool.fn(project_name="my-project", project_version="1.0.0")
            
            assert "badge" in result
            assert result["badge"] == mock_badge
            mock_client.get.assert_called_once_with("/badge/violations/project/my-project/1.0.0")

    @pytest.mark.asyncio
    async def test_get_violations_badge_by_name_error(self, register_tools):
        """Test get_violations_badge_by_name error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Project not found"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_violations_badge_by_name")
            assert tool is not None
            result = await tool.fn(project_name="bad-project", project_version="1.0.0")

            assert "error" in result
