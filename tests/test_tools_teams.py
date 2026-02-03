"""Tests for team management tools."""

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


class TestListTeamsTool:
    """Tests for list_teams tool."""

    @pytest.mark.asyncio
    async def test_list_teams_success(self, register_tools):
        """Test listing all teams."""
        mock_teams = [
            {"uuid": "team-1", "name": "Backend Team"},
            {"uuid": "team-2", "name": "Security Team"},
        ]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_teams, {"X-Total-Count": "2"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_teams")
            assert tool is not None
            result = await tool.fn()
            
            assert "teams" in result
            assert result["teams"] == mock_teams
            assert result["total"] == 2

    @pytest.mark.asyncio
    async def test_list_teams_with_pagination(self, register_tools):
        """Test list_teams with pagination."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=([], {"X-Total-Count": "100"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_teams")
            assert tool is not None
            result = await tool.fn(page=2, page_size=50)
            
            assert result["page"] == 2
            assert result["page_size"] == 50

    @pytest.mark.asyncio
    async def test_list_teams_error(self, register_tools):
        """Test list_teams error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Access denied")
            error.details = {"status": 403}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_teams")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestListVisibleTeamsTool:
    """Tests for list_visible_teams tool."""

    @pytest.mark.asyncio
    async def test_list_visible_teams_success(self, register_tools):
        """Test listing visible teams."""
        mock_teams = [{"uuid": "team-1", "name": "Visible Team"}]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_teams, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_visible_teams")
            assert tool is not None
            result = await tool.fn()
            
            assert "teams" in result
            call_args = mock_client.get_with_headers.call_args
            assert "/team/visible" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_list_visible_teams_error(self, register_tools):
        """Test list_visible_teams error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Not found")
            error.details = {"status": 404}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_visible_teams")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestGetTeamTool:
    """Tests for get_team tool."""

    @pytest.mark.asyncio
    async def test_get_team_success(self, register_tools):
        """Test getting a specific team."""
        mock_team = {"uuid": "team-1", "name": "Backend Team", "members": []}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_team)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_team")
            assert tool is not None
            result = await tool.fn(uuid="team-1")
            
            assert "team" in result
            assert result["team"] == mock_team
            mock_client.get.assert_called_once_with("/team/team-1")

    @pytest.mark.asyncio
    async def test_get_team_error(self, register_tools):
        """Test get_team error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Team not found")
            error.details = {"status": 404}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_team")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid")

            assert "error" in result


class TestGetCurrentTeamTool:
    """Tests for get_current_team tool."""

    @pytest.mark.asyncio
    async def test_get_current_team_success(self, register_tools):
        """Test getting current team."""
        mock_team = {"uuid": "team-self", "name": "Current Team"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_team)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_current_team")
            assert tool is not None
            result = await tool.fn()
            
            assert "team" in result
            mock_client.get.assert_called_once_with("/team/self")

    @pytest.mark.asyncio
    async def test_get_current_team_error(self, register_tools):
        """Test get_current_team error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Unauthorized")
            error.details = {"status": 401}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_current_team")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestCreateTeamTool:
    """Tests for create_team tool."""

    @pytest.mark.asyncio
    async def test_create_team_success(self, register_tools):
        """Test creating a team."""
        mock_team = {"uuid": "new-team", "name": "New Team"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_team)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_team")
            assert tool is not None
            result = await tool.fn(name="New Team")
            
            assert "team" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_create_team_payload(self, register_tools):
        """Test create_team sends correct payload."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={"uuid": "team-1"})
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_team")
            assert tool is not None
            await tool.fn(name="Security Team")
            
            call_args = mock_client.put.call_args
            assert call_args[1]["data"]["name"] == "Security Team"

    @pytest.mark.asyncio
    async def test_create_team_error(self, register_tools):
        """Test create_team error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Duplicate team name")
            error.details = {"status": 400}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_team")
            assert tool is not None
            result = await tool.fn(name="Existing Team")

            assert "error" in result


class TestUpdateTeamTool:
    """Tests for update_team tool."""

    @pytest.mark.asyncio
    async def test_update_team_success(self, register_tools):
        """Test updating a team."""
        existing = {"uuid": "team-1", "name": "Old Name"}
        updated = {"uuid": "team-1", "name": "New Name"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing)
            mock_client.post = AsyncMock(return_value=updated)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "update_team")
            assert tool is not None
            result = await tool.fn(uuid="team-1", name="New Name")
            
            assert "team" in result
            assert "message" in result

    @pytest.mark.asyncio
    async def test_update_team_error(self, register_tools):
        """Test update_team error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Team not found")
            error.details = {"status": 404}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_team")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid", name="New Name")

            assert "error" in result


class TestDeleteTeamTool:
    """Tests for delete_team tool."""

    @pytest.mark.asyncio
    async def test_delete_team_success(self, register_tools):
        """Test deleting a team."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "delete_team")
            assert tool is not None
            result = await tool.fn(uuid="team-1")
            
            assert "message" in result
            assert "deleted" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_delete_team_error(self, register_tools):
        """Test delete_team error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Team not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_team")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid")

            assert "error" in result


class TestGenerateApiKeyTool:
    """Tests for generate_api_key tool."""

    @pytest.mark.asyncio
    async def test_generate_api_key_success(self, register_tools):
        """Test generating an API key."""
        mock_key = "generated-api-key-value"
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_key)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "generate_api_key")
            assert tool is not None
            result = await tool.fn(team_uuid="team-1")
            
            assert "apiKey" in result
            assert result["apiKey"] == mock_key
            assert "message" in result
            call_args = mock_client.put.call_args
            assert "team-1" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_generate_api_key_error(self, register_tools):
        """Test generate_api_key error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Team not found")
            error.details = {"status": 404}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "generate_api_key")
            assert tool is not None
            result = await tool.fn(team_uuid="bad-uuid")

            assert "error" in result


class TestRegenerateApiKeyTool:
    """Tests for regenerate_api_key tool."""

    @pytest.mark.asyncio
    async def test_regenerate_api_key_success(self, register_tools):
        """Test regenerating an API key."""
        new_key = "new-api-key-value"
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=new_key)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "regenerate_api_key")
            assert tool is not None
            result = await tool.fn(key="old-key-id")
            
            assert "apiKey" in result
            assert result["apiKey"] == new_key
            assert "regenerated" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_regenerate_api_key_error(self, register_tools):
        """Test regenerate_api_key error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Key not found")
            error.details = {"status": 404}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "regenerate_api_key")
            assert tool is not None
            result = await tool.fn(key="bad-key")

            assert "error" in result


class TestDeleteApiKeyTool:
    """Tests for delete_api_key tool."""

    @pytest.mark.asyncio
    async def test_delete_api_key_success(self, register_tools):
        """Test deleting an API key."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "delete_api_key")
            assert tool is not None
            result = await tool.fn(key="key-to-delete")
            
            assert "message" in result
            assert "deleted" in result["message"].lower()
            call_args = mock_client.delete.call_args
            assert "key-to-delete" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_delete_api_key_error(self, register_tools):
        """Test delete_api_key error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Key not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_api_key")
            assert tool is not None
            result = await tool.fn(key="bad-key")

            assert "error" in result


class TestUpdateApiKeyCommentTool:
    """Tests for update_api_key_comment tool."""

    @pytest.mark.asyncio
    async def test_update_api_key_comment_success(self, register_tools):
        """Test updating API key comment."""
        mock_key = {"uuid": "key-1", "comment": "Updated comment"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_key)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "update_api_key_comment")
            assert tool is not None
            result = await tool.fn(key="key-id", comment="My API Key")
            
            assert "apiKey" in result
            assert "message" in result

    @pytest.mark.asyncio
    async def test_update_api_key_comment_payload(self, register_tools):
        """Test update_api_key_comment sends correct payload."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value={})
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "update_api_key_comment")
            assert tool is not None
            await tool.fn(key="key-id", comment="Test comment")
            
            call_args = mock_client.post.call_args
            assert call_args[1]["data"]["comment"] == "Test comment"

    @pytest.mark.asyncio
    async def test_update_api_key_comment_error(self, register_tools):
        """Test update_api_key_comment error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Key not found")
            error.details = {"status": 404}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_api_key_comment")
            assert tool is not None
            result = await tool.fn(key="bad-key", comment="comment")

            assert "error" in result
