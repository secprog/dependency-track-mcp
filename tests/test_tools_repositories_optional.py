"""
Tests for repositories tool optional field coverage.
Targets missing lines in update_repository optional field handling.
"""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.tools.repositories import register_repository_tools
from tests.utils import find_tool


@pytest.fixture
def register_tools(mcp):
    """Register repository tools."""
    register_repository_tools(mcp)
    return mcp


class TestRepositoriesOptionalFields:
    """Tests for repositories optional field handling."""

    @pytest.mark.asyncio
    async def test_update_repository_with_url(self, register_tools):
        """Test updating repository with url field."""
        updated_data = {
            "uuid": "repo-1",
            "identifier": "maven-central",
            "url": "https://repo.maven.apache.org/maven2/",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_repository")
            assert tool is not None
            result = await tool.fn(uuid="repo-1", url="https://repo.maven.apache.org/maven2/")

            assert "repository" in result
            # Verify that url was included in the post call
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["url"] == "https://repo.maven.apache.org/maven2/"

    @pytest.mark.asyncio
    async def test_update_repository_with_enabled(self, register_tools):
        """Test updating repository with enabled field."""
        updated_data = {
            "uuid": "repo-1",
            "enabled": True,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_repository")
            assert tool is not None
            result = await tool.fn(uuid="repo-1", enabled=True)

            assert "repository" in result
            # Verify that enabled was included in the post call
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["enabled"] is True

    @pytest.mark.asyncio
    async def test_update_repository_with_internal(self, register_tools):
        """Test updating repository with internal field."""
        updated_data = {
            "uuid": "repo-1",
            "internal": False,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_repository")
            assert tool is not None
            result = await tool.fn(uuid="repo-1", internal=False)

            assert "repository" in result
            # Verify that internal was included in the post call
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["internal"] is False

    @pytest.mark.asyncio
    async def test_update_repository_with_username(self, register_tools):
        """Test updating repository with username field."""
        updated_data = {
            "uuid": "repo-1",
            "username": "admin",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_repository")
            assert tool is not None
            result = await tool.fn(uuid="repo-1", username="admin")

            assert "repository" in result
            # Verify that username was included in the post call
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["username"] == "admin"

    @pytest.mark.asyncio
    async def test_update_repository_with_password(self, register_tools):
        """Test updating repository with password field."""
        updated_data = {
            "uuid": "repo-1",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_repository")
            assert tool is not None
            result = await tool.fn(uuid="repo-1", password="secret123")

            assert "repository" in result
            # Verify that password was included in the post call
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["password"] == "secret123"

    @pytest.mark.asyncio
    async def test_update_repository_all_optional_fields(self, register_tools):
        """Test updating repository with all optional fields."""
        updated_data = {
            "uuid": "repo-1",
            "identifier": "custom-repo",
            "url": "https://custom.repo.org/",
            "resolutionOrder": 5,
            "enabled": True,
            "internal": False,
            "username": "admin",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_repository")
            assert tool is not None
            result = await tool.fn(
                uuid="repo-1",
                identifier="custom-repo",
                url="https://custom.repo.org/",
                resolution_order=5,
                enabled=True,
                internal=False,
                username="admin",
                password="secret123",
            )

            assert "repository" in result
            # Verify that all fields were included
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["identifier"] == "custom-repo"
            assert posted_data["url"] == "https://custom.repo.org/"
            assert posted_data["resolutionOrder"] == 5
            assert posted_data["enabled"] is True
            assert posted_data["internal"] is False
            assert posted_data["username"] == "admin"
            assert posted_data["password"] == "secret123"

    @pytest.mark.asyncio
    async def test_update_repository_error(self, register_tools):
        """Test update_repository error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Repository not found")
            error.details = {"status": 404}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_repository")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid", url="https://example.com")

            assert "error" in result
            assert result["error"] == "Repository not found"
