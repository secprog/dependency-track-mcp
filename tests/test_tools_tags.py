"""Tests for tag management tools."""

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


class TestListTagsTool:
    """Tests for list_tags tool."""

    @pytest.mark.asyncio
    async def test_list_tags_success(self, register_tools):
        """Test listing all tags."""
        mock_tags = [
            {"uuid": "tag-1", "name": "production"},
            {"uuid": "tag-2", "name": "critical"},
        ]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_tags, {"X-Total-Count": "2"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_tags")
            assert tool is not None
            result = await tool.fn()
            
            assert "tags" in result
            assert result["tags"] == mock_tags
            assert result["total"] == 2

    @pytest.mark.asyncio
    async def test_list_tags_with_pagination(self, register_tools):
        """Test list_tags with pagination."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=([], {"X-Total-Count": "50"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_tags")
            assert tool is not None
            result = await tool.fn(page=2, page_size=25)
            
            assert result["page"] == 2
            assert result["page_size"] == 25

    @pytest.mark.asyncio
    async def test_list_tags_error(self, register_tools):
        """Test list_tags error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Access denied")
            error.details = {"status": 403}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_tags")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result
            assert "details" in result


class TestCreateTagsTool:
    """Tests for create_tags tool."""

    @pytest.mark.asyncio
    async def test_create_tags_success(self, register_tools):
        """Test creating tags."""
        mock_tags = [
            {"uuid": "tag-1", "name": "new-tag"},
            {"uuid": "tag-2", "name": "another-tag"},
        ]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_tags)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_tags")
            assert tool is not None
            result = await tool.fn(names=["new-tag", "another-tag"])
            
            assert "tags" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_create_tags_payload(self, register_tools):
        """Test create_tags sends correct payload."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=[])
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_tags")
            assert tool is not None
            await tool.fn(names=["tag1", "tag2", "tag3"])
            
            call_args = mock_client.put.call_args
            payload = call_args[1]["data"]
            assert len(payload) == 3
            assert all("name" in tag for tag in payload)

    @pytest.mark.asyncio
    async def test_create_tags_single(self, register_tools):
        """Test create_tags with single tag."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=[{"uuid": "tag-1", "name": "single"}])
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_tags")
            assert tool is not None
            result = await tool.fn(names=["single"])
            
            assert "Created 1 tag" in result["message"]

    @pytest.mark.asyncio
    async def test_create_tags_error(self, register_tools):
        """Test create_tags error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Invalid tag name")
            error.details = {"status": 400}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_tags")
            assert tool is not None
            result = await tool.fn(names=["bad-tag"])

            assert "error" in result


class TestDeleteTagsTool:
    """Tests for delete_tags tool."""

    @pytest.mark.asyncio
    async def test_delete_tags_success(self, register_tools):
        """Test deleting tags."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "delete_tags")
            assert tool is not None
            result = await tool.fn(names=["tag1", "tag2"])
            
            assert "message" in result
            assert "Deleted 2 tag" in result["message"]

    @pytest.mark.asyncio
    async def test_delete_tags_endpoint(self, register_tools):
        """Test delete_tags calls correct endpoint."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "delete_tags")
            assert tool is not None
            await tool.fn(names=["tag-a", "tag-b"])
            
            call_args = mock_client.delete.call_args
            assert "tag-a,tag-b" in call_args[1]["params"]["names"]

    @pytest.mark.asyncio
    async def test_delete_tags_error(self, register_tools):
        """Test delete_tags error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Tag not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_tags")
            assert tool is not None
            result = await tool.fn(names=["nonexistent"])

            assert "error" in result


class TestGetTagProjectsTool:
    """Tests for get_tag_projects tool."""

    @pytest.mark.asyncio
    async def test_get_tag_projects_success(self, register_tools):
        """Test getting projects with a tag."""
        mock_projects = [
            {"uuid": "proj-1", "name": "Project 1"},
        ]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_projects, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_tag_projects")
            assert tool is not None
            result = await tool.fn(tag_name="production")
            
            assert "projects" in result
            assert result["projects"] == mock_projects

    @pytest.mark.asyncio
    async def test_get_tag_projects_with_pagination(self, register_tools):
        """Test get_tag_projects with pagination."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=([], {"X-Total-Count": "150"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_tag_projects")
            assert tool is not None
            result = await tool.fn(tag_name="critical", page=3, page_size=50)
            
            assert result["page"] == 3
            assert result["total"] == 150

    @pytest.mark.asyncio
    async def test_get_tag_projects_error(self, register_tools):
        """Test get_tag_projects error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Tag not found")
            error.details = {"status": 404}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_tag_projects")
            assert tool is not None
            result = await tool.fn(tag_name="nonexistent")

            assert "error" in result


class TestTagProjectsTool:
    """Tests for tag_projects tool."""

    @pytest.mark.asyncio
    async def test_tag_projects_success(self, register_tools):
        """Test tagging projects."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "tag_projects")
            assert tool is not None
            result = await tool.fn(tag_name="production", project_uuids=["proj-1", "proj-2"])
            
            assert "message" in result
            assert "Tagged 2 project" in result["message"]

    @pytest.mark.asyncio
    async def test_tag_projects_payload(self, register_tools):
        """Test tag_projects sends correct payload."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "tag_projects")
            assert tool is not None
            await tool.fn(tag_name="test", project_uuids=["proj-a", "proj-b"])
            
            call_args = mock_client.post.call_args
            assert call_args[1]["data"] == ["proj-a", "proj-b"]

    @pytest.mark.asyncio
    async def test_tag_projects_error(self, register_tools):
        """Test tag_projects error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Invalid project")
            error.details = {"status": 400}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "tag_projects")
            assert tool is not None
            result = await tool.fn(tag_name="test", project_uuids=["bad-uuid"])

            assert "error" in result


class TestUntagProjectsTool:
    """Tests for untag_projects tool."""

    @pytest.mark.asyncio
    async def test_untag_projects_success(self, register_tools):
        """Test untagging projects."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "untag_projects")
            assert tool is not None
            result = await tool.fn(tag_name="production", project_uuids=["proj-1"])
            
            assert "message" in result
            assert "Untagged" in result["message"]

    @pytest.mark.asyncio
    async def test_untag_projects_error(self, register_tools):
        """Test untag_projects error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "untag_projects")
            assert tool is not None
            result = await tool.fn(tag_name="test", project_uuids=["proj-1"])

            assert "error" in result


class TestGetTagPoliciesTool:
    """Tests for get_tag_policies tool."""

    @pytest.mark.asyncio
    async def test_get_tag_policies_success(self, register_tools):
        """Test getting policies with a tag."""
        mock_policies = [{"uuid": "policy-1", "name": "Policy 1"}]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_policies, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_tag_policies")
            assert tool is not None
            result = await tool.fn(tag_name="security")
            
            assert "policies" in result
            assert result["policies"] == mock_policies

    @pytest.mark.asyncio
    async def test_get_tag_policies_error(self, register_tools):
        """Test get_tag_policies error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Tag not found")
            error.details = {"status": 404}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_tag_policies")
            assert tool is not None
            result = await tool.fn(tag_name="nonexistent")

            assert "error" in result


class TestTagPoliciesTool:
    """Tests for tag_policies tool."""

    @pytest.mark.asyncio
    async def test_tag_policies_success(self, register_tools):
        """Test tagging policies."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "tag_policies")
            assert tool is not None
            result = await tool.fn(tag_name="security", policy_uuids=["policy-1"])
            
            assert "message" in result


class TestUntagPoliciesTool:
    """Tests for untag_policies tool."""

    @pytest.mark.asyncio
    async def test_untag_policies_success(self, register_tools):
        """Test untagging policies."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "untag_policies")
            assert tool is not None
            result = await tool.fn(tag_name="test", policy_uuids=["policy-1"])
            
            assert "message" in result


class TestGetTagNotificationRulesTool:
    """Tests for get_tag_notification_rules tool."""

    @pytest.mark.asyncio
    async def test_get_tag_notification_rules_success(self, register_tools):
        """Test getting notification rules with a tag."""
        mock_rules = [{"uuid": "rule-1", "name": "Rule 1"}]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_rules, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_tag_notification_rules")
            assert tool is not None
            result = await tool.fn(tag_name="alerts")
            
            assert "notificationRules" in result


class TestGetPolicyTagsTool:
    """Tests for get_policy_tags tool."""

    @pytest.mark.asyncio
    async def test_get_policy_tags_success(self, register_tools):
        """Test getting tags for a policy."""
        mock_tags = [{"name": "security"}, {"name": "critical"}]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_tags, {"X-Total-Count": "2"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_policy_tags")
            assert tool is not None
            result = await tool.fn(policy_uuid="policy-1")
            
            assert "tags" in result
            assert result["tags"] == mock_tags

    @pytest.mark.asyncio
    async def test_get_policy_tags_error(self, register_tools):
        """Test get_policy_tags error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Policy not found")
            error.details = {"status": 404}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_policy_tags")
            assert tool is not None
            result = await tool.fn(policy_uuid="bad-uuid")

            assert "error" in result


class TestGetTagCollectionProjectsTool:
    """Tests for get_tag_collection_projects tool."""

    @pytest.mark.asyncio
    async def test_get_tag_collection_projects_success(self, register_tools):
        """Test getting collection projects for a tag."""
        mock_projects = [{"uuid": "proj-1", "name": "Collection Project"}]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_projects, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_tag_collection_projects")
            assert tool is not None
            result = await tool.fn(tag_name="collection-tag")
            
            assert "projects" in result
            assert result["projects"] == mock_projects
