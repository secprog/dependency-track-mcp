"""Tests for permission management tools."""

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


class TestListPermissionsTool:
    """Tests for list_permissions tool."""

    @pytest.mark.asyncio
    async def test_list_permissions_success(self, register_tools):
        """Test listing all available permissions."""
        mock_permissions = [
            {"name": "BOM_UPLOAD"},
            {"name": "VULNERABILITY_ANALYSIS"},
            {"name": "PROJECT_CREATION_UPLOAD"},
        ]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_permissions)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_permissions")
            assert tool is not None
            result = await tool.fn()
            
            assert "permissions" in result
            assert result["permissions"] == mock_permissions
            assert len(result["permissions"]) == 3
            mock_client.get.assert_called_once_with("/permission")

    @pytest.mark.asyncio
    async def test_list_permissions_empty(self, register_tools):
        """Test list_permissions with empty result."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=[])
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_permissions")
            assert tool is not None
            result = await tool.fn()
            
            assert result["permissions"] == []

    @pytest.mark.asyncio
    async def test_list_permissions_error(self, register_tools):
        """Test list_permissions error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Access denied")
            error.details = {"status": 403}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_permissions")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result
            assert "details" in result


class TestAddPermissionToTeamTool:
    """Tests for add_permission_to_team tool."""

    @pytest.mark.asyncio
    async def test_add_permission_to_team_success(self, register_tools):
        """Test adding a permission to a team."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "add_permission_to_team")
            assert tool is not None
            result = await tool.fn(permission="BOM_UPLOAD", team_uuid="team-uuid")
            
            assert "message" in result
            assert "successfully" in result["message"].lower()
            mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_permission_to_team_endpoint(self, register_tools):
        """Test add_permission_to_team calls correct endpoint."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "add_permission_to_team")
            assert tool is not None
            await tool.fn(permission="VULNERABILITY_ANALYSIS", team_uuid="team-123")
            
            call_args = mock_client.post.call_args
            assert "team-123" in call_args[0][0]
            assert "VULNERABILITY_ANALYSIS" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_add_permission_to_team_error(self, register_tools):
        """Test add_permission_to_team error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Team not found")
            error.details = {"status": 404}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_permission_to_team")
            assert tool is not None
            result = await tool.fn(permission="BOM_UPLOAD", team_uuid="bad-uuid")

            assert "error" in result
            assert "details" in result


class TestRemovePermissionFromTeamTool:
    """Tests for remove_permission_from_team tool."""

    @pytest.mark.asyncio
    async def test_remove_permission_from_team_success(self, register_tools):
        """Test removing a permission from a team."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "remove_permission_from_team")
            assert tool is not None
            result = await tool.fn(permission="BOM_UPLOAD", team_uuid="team-uuid")
            
            assert "message" in result
            assert "successfully" in result["message"].lower()
            mock_client.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_permission_from_team_endpoint(self, register_tools):
        """Test remove_permission_from_team calls correct endpoint."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "remove_permission_from_team")
            assert tool is not None
            await tool.fn(permission="PROJECT_CREATION_UPLOAD", team_uuid="team-456")
            
            call_args = mock_client.delete.call_args
            assert "team-456" in call_args[0][0]
            assert "PROJECT_CREATION_UPLOAD" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_remove_permission_from_team_error(self, register_tools):
        """Test remove_permission_from_team error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Permission not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_permission_from_team")
            assert tool is not None
            result = await tool.fn(permission="BOM_UPLOAD", team_uuid="team-uuid")

            assert "error" in result
            assert "details" in result


class TestAddPermissionToUserTool:
    """Tests for add_permission_to_user tool."""

    @pytest.mark.asyncio
    async def test_add_permission_to_user_success(self, register_tools):
        """Test adding a permission to a user."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "add_permission_to_user")
            assert tool is not None
            result = await tool.fn(permission="BOM_UPLOAD", username="testuser")
            
            assert "message" in result
            assert "successfully" in result["message"].lower()
            mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_permission_to_user_endpoint(self, register_tools):
        """Test add_permission_to_user calls correct endpoint."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "add_permission_to_user")
            assert tool is not None
            await tool.fn(permission="VULNERABILITY_ANALYSIS", username="john.doe")
            
            call_args = mock_client.post.call_args
            assert "john.doe" in call_args[0][0]
            assert "VULNERABILITY_ANALYSIS" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_add_permission_to_user_error(self, register_tools):
        """Test add_permission_to_user error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("User not found")
            error.details = {"status": 404}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_permission_to_user")
            assert tool is not None
            result = await tool.fn(permission="BOM_UPLOAD", username="baduser")

            assert "error" in result
            assert "details" in result


class TestRemovePermissionFromUserTool:
    """Tests for remove_permission_from_user tool."""

    @pytest.mark.asyncio
    async def test_remove_permission_from_user_success(self, register_tools):
        """Test removing a permission from a user."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "remove_permission_from_user")
            assert tool is not None
            result = await tool.fn(permission="BOM_UPLOAD", username="testuser")
            
            assert "message" in result
            assert "successfully" in result["message"].lower()
            mock_client.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_permission_from_user_endpoint(self, register_tools):
        """Test remove_permission_from_user calls correct endpoint."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "remove_permission_from_user")
            assert tool is not None
            await tool.fn(permission="PROJECT_CREATION_UPLOAD", username="jane.doe")
            
            call_args = mock_client.delete.call_args
            assert "jane.doe" in call_args[0][0]
            assert "PROJECT_CREATION_UPLOAD" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_remove_permission_from_user_error(self, register_tools):
        """Test remove_permission_from_user error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Permission not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_permission_from_user")
            assert tool is not None
            result = await tool.fn(permission="BOM_UPLOAD", username="testuser")

            assert "error" in result
            assert "details" in result
