"""Tests for policy violation tools."""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.tools.policies import register_policy_tools
from tests.utils import find_tool


@pytest.fixture
def register_tools(mcp):
    """Register policy tools."""
    register_policy_tools(mcp)
    return mcp


class TestListPolicyViolationsTool:
    """Tests for list_policy_violations tool."""

    @pytest.mark.asyncio
    async def test_list_violations_success(self, register_tools):
        """Test listing policy violations."""
        mock_data = [
            {
                "uuid": "viol-1",
                "type": "SECURITY",
                "component": {"name": "lodash"},
            }
        ]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_policy_violations")
            assert tool is not None
            result = await tool.fn(suppressed=True)
            
            assert "violations" in result
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_list_violations_error(self, register_tools):
        """Test list_policy_violations error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_policy_violations")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestListProjectPolicyViolationsTool:
    """Tests for list_project_policy_violations tool."""

    @pytest.mark.asyncio
    async def test_list_project_violations_success(self, register_tools):
        """Test listing project policy violations."""
        mock_data = [
            {
                "uuid": "viol-1",
                "type": "LICENSE",
                "component": {"name": "lodash"},
            }
        ]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_project_policy_violations")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")
            
            assert "violations" in result

    @pytest.mark.asyncio
    async def test_list_project_violations_error(self, register_tools):
        """Test list_project_policy_violations error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_project_policy_violations")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")

            assert "error" in result


class TestListComponentPolicyViolationsTool:
    """Tests for list_component_policy_violations tool."""

    @pytest.mark.asyncio
    async def test_list_component_violations_success(self, register_tools):
        """Test listing component policy violations."""
        mock_data = [{"uuid": "viol-1", "type": "OPERATIONAL"}]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_component_policy_violations")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")
            
            assert "violations" in result

    @pytest.mark.asyncio
    async def test_list_component_violations_error(self, register_tools):
        """Test list_component_policy_violations error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_component_policy_violations")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")

            assert "error" in result


class TestListPoliciesTool:
    """Tests for list_policies tool."""

    @pytest.mark.asyncio
    async def test_list_policies_success(self, register_tools):
        """Test listing policies."""
        mock_data = [{"uuid": "policy-1", "name": "Security Policy"}]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_policies")
            assert tool is not None
            result = await tool.fn()
            
            assert "policies" in result
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_list_policies_error(self, register_tools):
        """Test list_policies error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_policies")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result
