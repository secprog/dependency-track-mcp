"""
Tests for tags tool error handling and edge cases.
Targets missing lines in tag_policies, untag_policies, and exception handling.
"""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.tools.tags import register_tag_tools
from tests.utils import find_tool


@pytest.fixture
def register_tools(mcp):
    """Register tag tools."""
    register_tag_tools(mcp)
    return mcp


class TestTagsErrorHandling:
    """Tests for tags error handling."""

    @pytest.mark.asyncio
    async def test_tag_policies_error(self, register_tools):
        """Test tag_policies error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Tag not found")
            error.details = {"status": 404}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "tag_policies")
            assert tool is not None
            result = await tool.fn(tag_name="nonexistent", policy_uuids=["policy-1"])

            assert "error" in result
            assert result["error"] == "Tag not found"
            assert "details" in result

    @pytest.mark.asyncio
    async def test_untag_policies_error(self, register_tools):
        """Test untag_policies error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Policy not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "untag_policies")
            assert tool is not None
            result = await tool.fn(tag_name="test", policy_uuids=["bad-policy"])

            assert "error" in result
            assert result["error"] == "Policy not found"
            assert "details" in result

    @pytest.mark.asyncio
    async def test_tag_policies_multiple_policies(self, register_tools):
        """Test tagging multiple policies."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "tag_policies")
            assert tool is not None
            policy_uuids = ["policy-1", "policy-2", "policy-3"]
            result = await tool.fn(tag_name="security", policy_uuids=policy_uuids)

            assert "message" in result
            assert "3" in result["message"]
            # Verify the correct endpoint was called with the policy UUIDs
            call_args = mock_client.post.call_args
            assert call_args is not None
            # Verify it was called with the right path
            assert "/tag/security/policy" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_untag_policies_multiple_policies(self, register_tools):
        """Test untagging multiple policies."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "untag_policies")
            assert tool is not None
            policy_uuids = ["policy-1", "policy-2"]
            result = await tool.fn(tag_name="archive", policy_uuids=policy_uuids)

            assert "message" in result
            assert "2" in result["message"]
            # Verify the correct endpoint was called with proper params
            call_args = mock_client.delete.call_args
            assert call_args is not None

    @pytest.mark.asyncio
    async def test_get_tag_notification_rules_error(self, register_tools):
        """Test get_tag_notification_rules error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Unauthorized")
            error.details = {"status": 401}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_tag_notification_rules")
            assert tool is not None
            result = await tool.fn(tag_name="test-tag")

            assert "error" in result
            assert result["error"] == "Unauthorized"
            assert "details" in result

    @pytest.mark.asyncio
    async def test_get_tag_collection_projects_error(self, register_tools):
        """Test get_tag_collection_projects error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Not found")
            error.details = {"status": 404}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_tag_collection_projects")
            assert tool is not None
            result = await tool.fn(tag_name="nonexistent")

            assert "error" in result
            assert result["error"] == "Not found"
            assert "details" in result
