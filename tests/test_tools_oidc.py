"""Tests for OIDC integration tools."""

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


class TestOidcAvailableTool:
    """Tests for oidc_available tool."""

    @pytest.mark.asyncio
    async def test_oidc_available_true(self, register_tools):
        """Test checking OIDC availability when enabled."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=True)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "oidc_available")
            assert tool is not None
            result = await tool.fn()

            assert "available" in result
            assert result["available"] is True
            mock_client.get.assert_called_once_with("/oidc/available")

    @pytest.mark.asyncio
    async def test_oidc_available_false(self, register_tools):
        """Test checking OIDC availability when disabled."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=False)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "oidc_available")
            assert tool is not None
            result = await tool.fn()

            assert "available" in result
            assert result["available"] is False

    @pytest.mark.asyncio
    async def test_oidc_available_error(self, register_tools):
        """Test oidc_available error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Server error")
            error.details = {"status": 500}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "oidc_available")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result
            assert "Server error" in str(result["error"])


class TestListOidcGroupsTool:
    """Tests for list_oidc_groups tool."""

    @pytest.mark.asyncio
    async def test_list_oidc_groups_success(self, register_tools):
        """Test listing OIDC groups."""
        mock_groups = [
            {"uuid": "group-1", "name": "developers"},
            {"uuid": "group-2", "name": "admins"},
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_groups, {"X-Total-Count": "2"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_oidc_groups")
            assert tool is not None
            result = await tool.fn()

            assert "groups" in result
            assert result["groups"] == mock_groups
            assert result["total"] == 2
            assert result["page"] == 1
            assert result["page_size"] == 100

    @pytest.mark.asyncio
    async def test_list_oidc_groups_with_pagination(self, register_tools):
        """Test list_oidc_groups with pagination."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(return_value=([], {"X-Total-Count": "30"}))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_oidc_groups")
            assert tool is not None
            result = await tool.fn(page=2, page_size=15)

            assert result["page"] == 2
            assert result["page_size"] == 15

    @pytest.mark.asyncio
    async def test_list_oidc_groups_error(self, register_tools):
        """Test list_oidc_groups error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("OIDC not configured")
            error.details = {"status": 400}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_oidc_groups")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result
            assert "OIDC not configured" in str(result["error"])


class TestCreateOidcGroupTool:
    """Tests for create_oidc_group tool."""

    @pytest.mark.asyncio
    async def test_create_oidc_group_success(self, register_tools):
        """Test creating an OIDC group."""
        mock_group = {"uuid": "new-group", "name": "developers"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_group)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_oidc_group")
            assert tool is not None
            result = await tool.fn(name="developers")

            assert "group" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()
            assert result["group"] == mock_group

    @pytest.mark.asyncio
    async def test_create_oidc_group_payload(self, register_tools):
        """Test create_oidc_group sends correct payload."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_oidc_group")
            assert tool is not None
            await tool.fn(name="test-group")

            call_args = mock_client.put.call_args
            payload = call_args[1]["data"]
            assert payload["name"] == "test-group"

    @pytest.mark.asyncio
    async def test_create_oidc_group_error(self, register_tools):
        """Test create_oidc_group error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Group already exists")
            error.details = {"status": 409}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_oidc_group")
            assert tool is not None
            result = await tool.fn(name="existing-group")

            assert "error" in result
            assert "Group already exists" in str(result["error"])


class TestUpdateOidcGroupTool:
    """Tests for update_oidc_group tool."""

    @pytest.mark.asyncio
    async def test_update_oidc_group_success(self, register_tools):
        """Test updating an OIDC group."""
        mock_group = {"uuid": "group-1", "name": "new-name"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_group)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_oidc_group")
            assert tool is not None
            result = await tool.fn(uuid="group-1", name="new-name")

            assert "group" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_update_oidc_group_payload(self, register_tools):
        """Test update_oidc_group sends correct payload."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value={})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_oidc_group")
            assert tool is not None
            await tool.fn(uuid="group-1", name="updated-name")

            call_args = mock_client.post.call_args
            payload = call_args[1]["data"]
            assert payload["uuid"] == "group-1"
            assert payload["name"] == "updated-name"

    @pytest.mark.asyncio
    async def test_update_oidc_group_error(self, register_tools):
        """Test update_oidc_group error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Group not found")
            error.details = {"status": 404}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_oidc_group")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid", name="new-name")

            assert "error" in result
            assert "Group not found" in str(result["error"])


class TestDeleteOidcGroupTool:
    """Tests for delete_oidc_group tool."""

    @pytest.mark.asyncio
    async def test_delete_oidc_group_success(self, register_tools):
        """Test deleting an OIDC group."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_oidc_group")
            assert tool is not None
            result = await tool.fn(uuid="group-123")

            assert "message" in result
            assert "deleted" in result["message"].lower()
            assert "group-123" in result["message"]
            mock_client.delete.assert_called_once_with("/oidc/group/group-123")

    @pytest.mark.asyncio
    async def test_delete_oidc_group_error(self, register_tools):
        """Test delete_oidc_group error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Group not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_oidc_group")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid")

            assert "error" in result
            assert "Group not found" in str(result["error"])


class TestGetOidcGroupTeamsTool:
    """Tests for get_oidc_group_teams tool."""

    @pytest.mark.asyncio
    async def test_get_oidc_group_teams_success(self, register_tools):
        """Test getting teams for an OIDC group."""
        mock_teams = [
            {"uuid": "team-1", "name": "Developers"},
            {"uuid": "team-2", "name": "Security"},
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_teams)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_oidc_group_teams")
            assert tool is not None
            result = await tool.fn(group_uuid="group-1")

            assert "teams" in result
            assert result["teams"] == mock_teams
            mock_client.get.assert_called_once_with("/oidc/group/group-1/team")

    @pytest.mark.asyncio
    async def test_get_oidc_group_teams_empty(self, register_tools):
        """Test getting teams when none are mapped."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=[])
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_oidc_group_teams")
            assert tool is not None
            result = await tool.fn(group_uuid="group-2")

            assert "teams" in result
            assert result["teams"] == []

    @pytest.mark.asyncio
    async def test_get_oidc_group_teams_error(self, register_tools):
        """Test get_oidc_group_teams error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Group not found")
            error.details = {"status": 404}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_oidc_group_teams")
            assert tool is not None
            result = await tool.fn(group_uuid="bad-uuid")

            assert "error" in result
            assert "Group not found" in str(result["error"])


class TestAddOidcMappingTool:
    """Tests for add_oidc_mapping tool."""

    @pytest.mark.asyncio
    async def test_add_oidc_mapping_success(self, register_tools):
        """Test adding an OIDC mapping."""
        mock_mapping = {
            "uuid": "mapping-1",
            "group": {"uuid": "group-1"},
            "team": {"uuid": "team-1"},
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_mapping)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_oidc_mapping")
            assert tool is not None
            result = await tool.fn(group_uuid="group-1", team_uuid="team-1")

            assert "mapping" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_add_oidc_mapping_payload(self, register_tools):
        """Test add_oidc_mapping sends correct payload."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_oidc_mapping")
            assert tool is not None
            await tool.fn(group_uuid="group-1", team_uuid="team-1")

            call_args = mock_client.put.call_args
            payload = call_args[1]["data"]
            assert payload["group"] == "group-1"
            assert payload["team"] == "team-1"

    @pytest.mark.asyncio
    async def test_add_oidc_mapping_error(self, register_tools):
        """Test add_oidc_mapping error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Group or team not found")
            error.details = {"status": 404}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_oidc_mapping")
            assert tool is not None
            result = await tool.fn(group_uuid="bad-group", team_uuid="bad-team")

            assert "error" in result
            assert "Group or team not found" in str(result["error"])


class TestRemoveOidcMappingTool:
    """Tests for remove_oidc_mapping tool."""

    @pytest.mark.asyncio
    async def test_remove_oidc_mapping_success(self, register_tools):
        """Test removing an OIDC mapping by UUID."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_oidc_mapping")
            assert tool is not None
            result = await tool.fn(mapping_uuid="mapping-123")

            assert "message" in result
            assert "removed" in result["message"].lower()
            assert "mapping-123" in result["message"]
            mock_client.delete.assert_called_once_with("/oidc/mapping/mapping-123")

    @pytest.mark.asyncio
    async def test_remove_oidc_mapping_error(self, register_tools):
        """Test remove_oidc_mapping error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Mapping not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_oidc_mapping")
            assert tool is not None
            result = await tool.fn(mapping_uuid="bad-uuid")

            assert "error" in result
            assert "Mapping not found" in str(result["error"])


class TestRemoveOidcGroupTeamMappingTool:
    """Tests for remove_oidc_group_team_mapping tool."""

    @pytest.mark.asyncio
    async def test_remove_oidc_group_team_mapping_success(self, register_tools):
        """Test removing an OIDC mapping by group and team UUID."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_oidc_group_team_mapping")
            assert tool is not None
            result = await tool.fn(group_uuid="group-1", team_uuid="team-1")

            assert "message" in result
            assert "removed" in result["message"].lower()
            mock_client.delete.assert_called_once_with("/oidc/group/group-1/team/team-1/mapping")

    @pytest.mark.asyncio
    async def test_remove_oidc_group_team_mapping_error(self, register_tools):
        """Test remove_oidc_group_team_mapping error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Mapping not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_oidc_group_team_mapping")
            assert tool is not None
            result = await tool.fn(group_uuid="bad-group", team_uuid="bad-team")

            assert "error" in result
            assert "Mapping not found" in str(result["error"])
