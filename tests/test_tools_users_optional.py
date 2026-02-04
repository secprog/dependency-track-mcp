"""
Tests for users tool optional field coverage.
Targets missing lines in update_managed_user optional field handling.
"""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.tools.users import register_user_tools
from tests.utils import find_tool


@pytest.fixture
def register_tools(mcp):
    """Register user tools."""
    register_user_tools(mcp)
    return mcp


class TestUsersOptionalFields:
    """Tests for users optional field handling."""

    @pytest.mark.asyncio
    async def test_update_managed_user_with_fullname(self, register_tools):
        """Test updating user with fullname field."""
        updated_data = {
            "username": "testuser",
            "fullname": "New Full Name",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_managed_user")
            assert tool is not None
            result = await tool.fn(username="testuser", fullname="New Full Name")

            assert "user" in result
            assert result["user"]["fullname"] == "New Full Name"
            # Verify that fullname was included in the post call
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["fullname"] == "New Full Name"

    @pytest.mark.asyncio
    async def test_update_managed_user_with_email(self, register_tools):
        """Test updating user with email field."""
        updated_data = {
            "username": "testuser",
            "email": "newemail@example.com",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_managed_user")
            assert tool is not None
            result = await tool.fn(username="testuser", email="newemail@example.com")

            assert "user" in result
            assert result["user"]["email"] == "newemail@example.com"
            # Verify that email was included in the post call
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["email"] == "newemail@example.com"

    @pytest.mark.asyncio
    async def test_update_managed_user_with_password(self, register_tools):
        """Test updating user with password field."""
        updated_data = {
            "username": "testuser",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_managed_user")
            assert tool is not None
            result = await tool.fn(username="testuser", new_password="newpass123")

            assert "user" in result
            # Verify that both newPassword and confirmPassword were included
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["newPassword"] == "newpass123"
            assert posted_data["confirmPassword"] == "newpass123"

    @pytest.mark.asyncio
    async def test_update_managed_user_with_force_password_change(self, register_tools):
        """Test updating user with force_password_change field."""
        updated_data = {
            "username": "testuser",
            "forcePasswordChange": True,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_managed_user")
            assert tool is not None
            result = await tool.fn(username="testuser", force_password_change=True)

            assert "user" in result
            # Verify that forcePasswordChange was included
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["forcePasswordChange"] is True

    @pytest.mark.asyncio
    async def test_update_managed_user_with_non_expiry_password(self, register_tools):
        """Test updating user with non_expiry_password field."""
        updated_data = {
            "username": "testuser",
            "nonExpiryPassword": True,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_managed_user")
            assert tool is not None
            result = await tool.fn(username="testuser", non_expiry_password=True)

            assert "user" in result
            # Verify that nonExpiryPassword was included
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["nonExpiryPassword"] is True

    @pytest.mark.asyncio
    async def test_update_managed_user_with_suspended(self, register_tools):
        """Test updating user with suspended field."""
        updated_data = {
            "username": "testuser",
            "suspended": True,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_managed_user")
            assert tool is not None
            result = await tool.fn(username="testuser", suspended=True)

            assert "user" in result
            # Verify that suspended was included
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["suspended"] is True

    @pytest.mark.asyncio
    async def test_update_managed_user_all_optional_fields(self, register_tools):
        """Test updating user with all optional fields."""
        updated_data = {
            "username": "testuser",
            "fullname": "New Full Name",
            "email": "newemail@example.com",
            "forcePasswordChange": True,
            "nonExpiryPassword": False,
            "suspended": False,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_managed_user")
            assert tool is not None
            result = await tool.fn(
                username="testuser",
                fullname="New Full Name",
                email="newemail@example.com",
                new_password="newpass123",
                force_password_change=True,
                non_expiry_password=False,
                suspended=False,
            )

            assert "user" in result
            # Verify that all fields were included
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["fullname"] == "New Full Name"
            assert posted_data["email"] == "newemail@example.com"
            assert posted_data["newPassword"] == "newpass123"
            assert posted_data["confirmPassword"] == "newpass123"
            assert posted_data["forcePasswordChange"] is True
            assert posted_data["nonExpiryPassword"] is False
            assert posted_data["suspended"] is False

    @pytest.mark.asyncio
    async def test_update_managed_user_partial_optional_fields(self, register_tools):
        """Test updating user with some optional fields (not all)."""
        updated_data = {
            "username": "testuser",
            "fullname": "New Full Name",
            "suspended": True,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_managed_user")
            assert tool is not None
            result = await tool.fn(
                username="testuser",
                fullname="New Full Name",
                suspended=True,
            )

            assert "user" in result
            # Verify that only specified fields were included
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["fullname"] == "New Full Name"
            assert posted_data["suspended"] is True
            # Other fields should not be in the payload
            assert "email" not in posted_data or posted_data.get("email") is None
            assert "newPassword" not in posted_data or posted_data.get("newPassword") is None
