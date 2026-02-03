"""Tests for user management tools."""

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


class TestListManagedUsersTool:
    """Tests for list_managed_users tool."""

    @pytest.mark.asyncio
    async def test_list_managed_users_success(self, register_tools):
        """Test listing all managed users."""
        mock_users = [
            {"username": "admin", "email": "admin@example.com"},
            {"username": "user1", "email": "user1@example.com"},
        ]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_users, {"X-Total-Count": "2"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_managed_users")
            assert tool is not None
            result = await tool.fn()
            
            assert "users" in result
            assert result["users"] == mock_users
            assert result["total"] == 2
            call_args = mock_client.get_with_headers.call_args
            assert "/user/managed" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_list_managed_users_with_pagination(self, register_tools):
        """Test list_managed_users with pagination."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=([], {"X-Total-Count": "50"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_managed_users")
            assert tool is not None
            result = await tool.fn(page=2, page_size=25)
            
            assert result["page"] == 2
            assert result["page_size"] == 25

    @pytest.mark.asyncio
    async def test_list_managed_users_error(self, register_tools):
        """Test list_managed_users error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Access denied")
            error.details = {"status": 403}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_managed_users")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestListLdapUsersTool:
    """Tests for list_ldap_users tool."""

    @pytest.mark.asyncio
    async def test_list_ldap_users_success(self, register_tools):
        """Test listing LDAP users."""
        mock_users = [{"username": "ldap-user@domain.com"}]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_users, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_ldap_users")
            assert tool is not None
            result = await tool.fn()
            
            assert "users" in result
            call_args = mock_client.get_with_headers.call_args
            assert "/user/ldap" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_list_ldap_users_error(self, register_tools):
        """Test list_ldap_users error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("LDAP not configured")
            error.details = {"status": 400}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_ldap_users")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestListOidcUsersTool:
    """Tests for list_oidc_users tool."""

    @pytest.mark.asyncio
    async def test_list_oidc_users_success(self, register_tools):
        """Test listing OIDC users."""
        mock_users = [{"username": "user-123@provider.com"}]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_users, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_oidc_users")
            assert tool is not None
            result = await tool.fn()
            
            assert "users" in result
            call_args = mock_client.get_with_headers.call_args
            assert "/user/oidc" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_list_oidc_users_error(self, register_tools):
        """Test list_oidc_users error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("OIDC not configured")
            error.details = {"status": 400}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_oidc_users")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestGetCurrentUserTool:
    """Tests for get_current_user tool."""

    @pytest.mark.asyncio
    async def test_get_current_user_success(self, register_tools):
        """Test getting current user information."""
        mock_user = {"username": "current-user", "email": "user@example.com"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_user)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_current_user")
            assert tool is not None
            result = await tool.fn()
            
            assert "user" in result
            assert result["user"] == mock_user
            mock_client.get.assert_called_once_with("/user/self")

    @pytest.mark.asyncio
    async def test_get_current_user_error(self, register_tools):
        """Test get_current_user error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Unauthorized")
            error.details = {"status": 401}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_current_user")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestCreateManagedUserTool:
    """Tests for create_managed_user tool."""

    @pytest.mark.asyncio
    async def test_create_managed_user_success(self, register_tools):
        """Test creating a managed user."""
        mock_user = {"username": "newuser", "email": "newuser@example.com"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_user)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_managed_user")
            assert tool is not None
            result = await tool.fn(username="newuser", password="secure-password")
            
            assert "user" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_create_managed_user_with_all_options(self, register_tools):
        """Test create_managed_user with all optional parameters."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={"username": "user"})
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_managed_user")
            assert tool is not None
            await tool.fn(
                username="user",
                password="pass",
                fullname="Full Name",
                email="user@example.com",
                force_password_change=True,
                non_expiry_password=False,
                suspended=False,
            )
            
            call_args = mock_client.put.call_args
            payload = call_args[1]["data"]
            assert payload["username"] == "user"
            assert payload["newPassword"] == "pass"
            assert payload["fullname"] == "Full Name"
            assert payload["email"] == "user@example.com"
            assert payload["forcePasswordChange"] is True

    @pytest.mark.asyncio
    async def test_create_managed_user_error(self, register_tools):
        """Test create_managed_user error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Duplicate username")
            error.details = {"status": 400}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_managed_user")
            assert tool is not None
            result = await tool.fn(username="existing", password="pass")

            assert "error" in result


class TestUpdateManagedUserTool:
    """Tests for update_managed_user tool."""

    @pytest.mark.asyncio
    async def test_update_managed_user_success(self, register_tools):
        """Test updating a managed user."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value={"username": "user"})
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "update_managed_user")
            assert tool is not None
            result = await tool.fn(username="user", email="newemail@example.com")
            
            assert "user" in result
            assert "message" in result

    @pytest.mark.asyncio
    async def test_update_managed_user_partial(self, register_tools):
        """Test update_managed_user with partial updates."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value={})
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "update_managed_user")
            assert tool is not None
            await tool.fn(username="user", fullname="New Full Name")
            
            call_args = mock_client.post.call_args
            payload = call_args[1]["data"]
            assert payload["username"] == "user"
            assert payload["fullname"] == "New Full Name"
            assert "email" not in payload

    @pytest.mark.asyncio
    async def test_update_managed_user_error(self, register_tools):
        """Test update_managed_user error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("User not found")
            error.details = {"status": 404}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_managed_user")
            assert tool is not None
            result = await tool.fn(username="baduser", email="new@example.com")

            assert "error" in result


class TestDeleteManagedUserTool:
    """Tests for delete_managed_user tool."""

    @pytest.mark.asyncio
    async def test_delete_managed_user_success(self, register_tools):
        """Test deleting a managed user."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "delete_managed_user")
            assert tool is not None
            result = await tool.fn(username="user-to-delete")
            
            assert "message" in result
            assert "deleted" in result["message"].lower()
            call_args = mock_client.delete.call_args
            assert call_args[1]["params"]["username"] == "user-to-delete"

    @pytest.mark.asyncio
    async def test_delete_managed_user_error(self, register_tools):
        """Test delete_managed_user error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("User not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_managed_user")
            assert tool is not None
            result = await tool.fn(username="baduser")

            assert "error" in result


class TestCreateLdapUserTool:
    """Tests for create_ldap_user tool."""

    @pytest.mark.asyncio
    async def test_create_ldap_user_success(self, register_tools):
        """Test creating an LDAP user reference."""
        mock_user = {"username": "ldap-user@domain.com"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_user)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_ldap_user")
            assert tool is not None
            result = await tool.fn(username="ldap-user@domain.com")
            
            assert "user" in result
            assert "successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_create_ldap_user_error(self, register_tools):
        """Test create_ldap_user error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("User not found in LDAP")
            error.details = {"status": 404}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_ldap_user")
            assert tool is not None
            result = await tool.fn(username="nonexistent@domain.com")

            assert "error" in result


class TestDeleteLdapUserTool:
    """Tests for delete_ldap_user tool."""

    @pytest.mark.asyncio
    async def test_delete_ldap_user_success(self, register_tools):
        """Test deleting an LDAP user reference."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "delete_ldap_user")
            assert tool is not None
            result = await tool.fn(username="ldap-user@domain.com")
            
            assert "message" in result
            assert "deleted" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_delete_ldap_user_error(self, register_tools):
        """Test delete_ldap_user error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("User not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_ldap_user")
            assert tool is not None
            result = await tool.fn(username="baduser@domain.com")

            assert "error" in result


class TestCreateOidcUserTool:
    """Tests for create_oidc_user tool."""

    @pytest.mark.asyncio
    async def test_create_oidc_user_success(self, register_tools):
        """Test creating an OIDC user reference."""
        mock_user = {"username": "oidc-subject-id"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_user)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_oidc_user")
            assert tool is not None
            result = await tool.fn(username="oidc-subject-id")
            
            assert "user" in result
            assert "successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_create_oidc_user_error(self, register_tools):
        """Test create_oidc_user error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("OIDC not configured")
            error.details = {"status": 400}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_oidc_user")
            assert tool is not None
            result = await tool.fn(username="oidc-id")

            assert "error" in result


class TestDeleteOidcUserTool:
    """Tests for delete_oidc_user tool."""

    @pytest.mark.asyncio
    async def test_delete_oidc_user_success(self, register_tools):
        """Test deleting an OIDC user reference."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "delete_oidc_user")
            assert tool is not None
            result = await tool.fn(username="oidc-id")
            
            assert "message" in result
            assert "deleted" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_delete_oidc_user_error(self, register_tools):
        """Test delete_oidc_user error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("User not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_oidc_user")
            assert tool is not None
            result = await tool.fn(username="badid")

            assert "error" in result


class TestAddUserToTeamTool:
    """Tests for add_user_to_team tool."""

    @pytest.mark.asyncio
    async def test_add_user_to_team_success(self, register_tools):
        """Test adding a user to a team."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "add_user_to_team")
            assert tool is not None
            result = await tool.fn(username="user1", team_uuid="team-1")
            
            assert "message" in result
            assert "successfully" in result["message"].lower()
            call_args = mock_client.post.call_args
            assert "user1" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_add_user_to_team_error(self, register_tools):
        """Test add_user_to_team error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("User not found")
            error.details = {"status": 404}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_user_to_team")
            assert tool is not None
            result = await tool.fn(username="baduser", team_uuid="team-1")

            assert "error" in result


class TestRemoveUserFromTeamTool:
    """Tests for remove_user_from_team tool."""

    @pytest.mark.asyncio
    async def test_remove_user_from_team_success(self, register_tools):
        """Test removing a user from a team."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "remove_user_from_team")
            assert tool is not None
            result = await tool.fn(username="user1", team_uuid="team-1")
            
            assert "message" in result
            assert "removed" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_remove_user_from_team_error(self, register_tools):
        """Test remove_user_from_team error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("User not in team")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_user_from_team")
            assert tool is not None
            result = await tool.fn(username="user1", team_uuid="team-1")

            assert "error" in result
