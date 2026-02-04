"""Tests for repository management tools."""

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


class TestListRepositoriesTool:
    """Tests for list_repositories tool."""

    @pytest.mark.asyncio
    async def test_list_repositories_success(self, register_tools):
        """Test listing all repositories."""
        mock_repos = [
            {"uuid": "repo-1", "type": "NPM", "identifier": "npmjs"},
            {"uuid": "repo-2", "type": "MAVEN", "identifier": "maven-central"},
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_repos, {"X-Total-Count": "2"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_repositories")
            assert tool is not None
            result = await tool.fn()

            assert "repositories" in result
            assert result["repositories"] == mock_repos
            assert result["total"] == 2
            assert result["page"] == 1

    @pytest.mark.asyncio
    async def test_list_repositories_with_pagination(self, register_tools):
        """Test list_repositories with pagination."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(return_value=([], {"X-Total-Count": "50"}))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_repositories")
            assert tool is not None
            result = await tool.fn(page=3, page_size=20)

            assert result["page"] == 3
            assert result["page_size"] == 20
            call_args = mock_client.get_with_headers.call_args
            assert call_args[1]["params"]["pageNumber"] == 3
            assert call_args[1]["params"]["pageSize"] == 20

    @pytest.mark.asyncio
    async def test_list_repositories_error(self, register_tools):
        """Test list_repositories error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Service unavailable")
            error.details = {"status": 503}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_repositories")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result
            assert "details" in result


class TestListRepositoriesByTypeTool:
    """Tests for list_repositories_by_type tool."""

    @pytest.mark.asyncio
    async def test_list_repositories_by_type_success(self, register_tools):
        """Test listing repositories by type."""
        mock_repos = [{"uuid": "repo-1", "type": "NPM", "identifier": "npmjs"}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_repos, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_repositories_by_type")
            assert tool is not None
            result = await tool.fn(repo_type="NPM")

            assert "repositories" in result
            assert result["repositories"] == mock_repos
            call_args = mock_client.get_with_headers.call_args
            assert "/repository/NPM" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_list_repositories_by_type_with_pagination(self, register_tools):
        """Test list_repositories_by_type with pagination."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(return_value=([], {"X-Total-Count": "30"}))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_repositories_by_type")
            assert tool is not None
            result = await tool.fn(repo_type="MAVEN", page=2, page_size=15)

            assert result["page"] == 2
            assert result["page_size"] == 15
            call_args = mock_client.get_with_headers.call_args
            assert call_args[1]["params"]["pageNumber"] == 2

    @pytest.mark.asyncio
    async def test_list_repositories_by_type_error(self, register_tools):
        """Test list_repositories_by_type error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Type not found")
            error.details = {"status": 404}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_repositories_by_type")
            assert tool is not None
            result = await tool.fn(repo_type="INVALID")

            assert "error" in result


class TestCreateRepositoryTool:
    """Tests for create_repository tool."""

    @pytest.mark.asyncio
    async def test_create_repository_success(self, register_tools):
        """Test creating a repository."""
        mock_repo = {
            "uuid": "new-repo",
            "type": "NPM",
            "identifier": "custom-npm",
            "url": "https://registry.npmjs.org",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_repo)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_repository")
            assert tool is not None
            result = await tool.fn(
                repo_type="NPM",
                identifier="custom-npm",
                url="https://registry.npmjs.org",
            )

            assert "repository" in result
            assert "message" in result

    @pytest.mark.asyncio
    async def test_create_repository_with_auth(self, register_tools):
        """Test create_repository with authentication credentials."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={"uuid": "new-repo"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_repository")
            assert tool is not None
            await tool.fn(
                repo_type="MAVEN",
                identifier="custom-maven",
                url="https://my-registry.com",
                username="user",
                password="pass",
            )

            call_args = mock_client.put.call_args
            assert call_args[1]["data"]["username"] == "user"
            assert call_args[1]["data"]["password"] == "pass"

    @pytest.mark.asyncio
    async def test_create_repository_with_all_options(self, register_tools):
        """Test create_repository with all optional parameters."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={"uuid": "new-repo"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_repository")
            assert tool is not None
            await tool.fn(
                repo_type="PYPI",
                identifier="custom-pypi",
                url="https://my-pypi.com",
                resolution_order=1,
                enabled=True,
                internal=True,
                username="user",
                password="pass",
            )

            call_args = mock_client.put.call_args
            payload = call_args[1]["data"]
            assert payload["enabled"] is True
            assert payload["internal"] is True
            assert payload["resolutionOrder"] == 1

    @pytest.mark.asyncio
    async def test_create_repository_error(self, register_tools):
        """Test create_repository error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Invalid URL")
            error.details = {"status": 400}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_repository")
            assert tool is not None
            result = await tool.fn(
                repo_type="NPM",
                identifier="bad",
                url="invalid://url",
            )

            assert "error" in result


class TestUpdateRepositoryTool:
    """Tests for update_repository tool."""

    @pytest.mark.asyncio
    async def test_update_repository_success(self, register_tools):
        """Test updating a repository."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value={"uuid": "repo-1"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_repository")
            assert tool is not None
            result = await tool.fn(
                uuid="repo-1",
                enabled=False,
            )

            assert "repository" in result
            assert "message" in result

    @pytest.mark.asyncio
    async def test_update_repository_partial(self, register_tools):
        """Test update_repository with partial updates."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value={"uuid": "repo-1"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_repository")
            assert tool is not None
            await tool.fn(uuid="repo-1", url="https://new-url.com")

            call_args = mock_client.post.call_args
            assert call_args[1]["data"]["uuid"] == "repo-1"
            assert call_args[1]["data"]["url"] == "https://new-url.com"
            assert "identifier" not in call_args[1]["data"]

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
            result = await tool.fn(uuid="bad-uuid", enabled=False)

            assert "error" in result


class TestDeleteRepositoryTool:
    """Tests for delete_repository tool."""

    @pytest.mark.asyncio
    async def test_delete_repository_success(self, register_tools):
        """Test deleting a repository."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_repository")
            assert tool is not None
            result = await tool.fn(uuid="repo-1")

            assert "message" in result
            assert "deleted" in result["message"].lower()
            mock_client.delete.assert_called_once_with("/repository/repo-1")

    @pytest.mark.asyncio
    async def test_delete_repository_error(self, register_tools):
        """Test delete_repository error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Repository not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_repository")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid")

            assert "error" in result


class TestResolveLatestVersionTool:
    """Tests for resolve_latest_version tool."""

    @pytest.mark.asyncio
    async def test_resolve_latest_version_success(self, register_tools):
        """Test resolving latest version."""
        mock_version = {"version": "1.2.3", "published": "2024-01-15"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_version)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "resolve_latest_version")
            assert tool is not None
            result = await tool.fn(purl="pkg:npm/lodash")

            assert "latestVersion" in result
            assert result["latestVersion"] == mock_version
            call_args = mock_client.get.call_args
            assert call_args[1]["params"]["purl"] == "pkg:npm/lodash"

    @pytest.mark.asyncio
    async def test_resolve_latest_version_error(self, register_tools):
        """Test resolve_latest_version error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Component not found")
            error.details = {"status": 404}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "resolve_latest_version")
            assert tool is not None
            result = await tool.fn(purl="pkg:npm/unknown")

            assert "error" in result
