"""Tests for ACL tools."""

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


class TestGetTeamAclProjectsTool:
    """Tests for get_team_acl_projects tool."""

    @pytest.mark.asyncio
    async def test_get_team_acl_projects_success(self, register_tools):
        """Test getting projects assigned to a team via ACL."""
        mock_projects = [
            {"uuid": "proj-1", "name": "Project 1"},
            {"uuid": "proj-2", "name": "Project 2"},
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_projects, {"X-Total-Count": "2"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_team_acl_projects")
            assert tool is not None
            result = await tool.fn(team_uuid="team-uuid")

            assert "projects" in result
            assert result["projects"] == mock_projects
            assert result["total"] == 2
            assert result["page"] == 1
            assert result["page_size"] == 100
            mock_client.get_with_headers.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_team_acl_projects_with_pagination(self, register_tools):
        """Test get_team_acl_projects with pagination parameters."""
        mock_projects = [{"uuid": "proj-3", "name": "Project 3"}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_projects, {"X-Total-Count": "150"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_team_acl_projects")
            assert tool is not None
            result = await tool.fn(team_uuid="team-uuid", page=2, page_size=50)

            assert result["page"] == 2
            assert result["page_size"] == 50
            assert result["total"] == 150
            call_args = mock_client.get_with_headers.call_args
            assert call_args[1]["params"] == {"pageNumber": 2, "pageSize": 50}

    @pytest.mark.asyncio
    async def test_get_team_acl_projects_error(self, register_tools):
        """Test get_team_acl_projects error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Team not found")
            error.details = {"status": 404}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_team_acl_projects")
            assert tool is not None
            result = await tool.fn(team_uuid="bad-uuid")

            assert "error" in result
            assert "details" in result

    @pytest.mark.asyncio
    async def test_get_team_acl_projects_empty_results(self, register_tools):
        """Test get_team_acl_projects with empty results."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(return_value=([], {"X-Total-Count": "0"}))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_team_acl_projects")
            assert tool is not None
            result = await tool.fn(team_uuid="team-uuid")

            assert result["projects"] == []
            assert result["total"] == 0


class TestAddAclMappingTool:
    """Tests for add_acl_mapping tool."""

    @pytest.mark.asyncio
    async def test_add_acl_mapping_success(self, register_tools):
        """Test adding an ACL mapping."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_acl_mapping")
            assert tool is not None
            result = await tool.fn(team_uuid="team-uuid", project_uuid="proj-uuid")

            assert "message" in result
            assert "successfully" in result["message"].lower()
            mock_client.put.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_acl_mapping_payload(self, register_tools):
        """Test add_acl_mapping sends correct payload."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_acl_mapping")
            assert tool is not None
            await tool.fn(team_uuid="team-123", project_uuid="proj-456")

            call_args = mock_client.put.call_args
            assert call_args[0][0] == "/acl/mapping"
            assert call_args[1]["data"]["team"] == "team-123"
            assert call_args[1]["data"]["project"] == "proj-456"

    @pytest.mark.asyncio
    async def test_add_acl_mapping_error(self, register_tools):
        """Test add_acl_mapping error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Invalid mapping")
            error.details = {"status": 400}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_acl_mapping")
            assert tool is not None
            result = await tool.fn(team_uuid="team-uuid", project_uuid="proj-uuid")

            assert "error" in result
            assert "details" in result


class TestRemoveAclMappingTool:
    """Tests for remove_acl_mapping tool."""

    @pytest.mark.asyncio
    async def test_remove_acl_mapping_success(self, register_tools):
        """Test removing an ACL mapping."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_acl_mapping")
            assert tool is not None
            result = await tool.fn(team_uuid="team-uuid", project_uuid="proj-uuid")

            assert "message" in result
            assert "removed" in result["message"].lower()
            mock_client.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_acl_mapping_endpoint(self, register_tools):
        """Test remove_acl_mapping calls correct endpoint."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_acl_mapping")
            assert tool is not None
            await tool.fn(team_uuid="team-123", project_uuid="proj-456")

            call_args = mock_client.delete.call_args
            assert "team-123" in call_args[0][0]
            assert "proj-456" in call_args[0][0]
            assert "/acl/mapping" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_remove_acl_mapping_error(self, register_tools):
        """Test remove_acl_mapping error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Mapping not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_acl_mapping")
            assert tool is not None
            result = await tool.fn(team_uuid="team-uuid", project_uuid="proj-uuid")

            assert "error" in result
            assert "details" in result
