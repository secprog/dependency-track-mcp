"""Integration tests for the entire MCP server."""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.config import Settings
from dependency_track_mcp.tools.projects import register_project_tools
from dependency_track_mcp.tools.components import register_component_tools
from dependency_track_mcp.tools.vulnerabilities import register_vulnerability_tools
from dependency_track_mcp.tools.findings import register_finding_tools
from dependency_track_mcp.tools.metrics import register_metrics_tools
from dependency_track_mcp.tools.policies import register_policy_tools
from dependency_track_mcp.tools.bom import register_bom_tools
from dependency_track_mcp.tools.search import register_search_tools
from tests.utils import find_tool, get_registered_tools


class TestMCPServerIntegration:
    """Integration tests for the complete MCP server."""

    def test_all_tools_registered(self, mcp):
        """Test that all tool modules can be registered."""
        # Register all tools
        register_project_tools(mcp)
        register_component_tools(mcp)
        register_vulnerability_tools(mcp)
        register_finding_tools(mcp)
        register_metrics_tools(mcp)
        register_policy_tools(mcp)
        register_bom_tools(mcp)
        register_search_tools(mcp)
        
        # Verify tools are registered
        tools = get_registered_tools(mcp)
        assert len(tools) > 0
        tool_names = {tool.name for tool in tools}
        
        # Check key tools from each module
        assert "list_projects" in tool_names
        assert "list_project_components" in tool_names
        assert "get_vulnerability" in tool_names
        assert "list_project_findings" in tool_names
        assert "get_portfolio_metrics" in tool_names
        assert "list_policy_violations" in tool_names
        assert "upload_bom" in tool_names
        assert "search" in tool_names

    def test_client_singleton_with_multiple_instances(self, settings):
        """Test client singleton behavior."""
        client1 = DependencyTrackClient.get_instance(settings)
        client2 = DependencyTrackClient.get_instance()
        
        assert client1 is client2
        assert client1.settings == settings

    @pytest.mark.asyncio
    async def test_end_to_end_project_workflow(self, mcp):
        """Test a complete project management workflow."""
        # Register project tools
        register_project_tools(mcp)
        
        # Mock the client
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            
            # Mock the workflow responses
            mock_client.put = AsyncMock(
                return_value={"uuid": "proj-1", "name": "Test Project"}
            )
            mock_client.get = AsyncMock(
                return_value={"uuid": "proj-1", "name": "Test Project", "version": "1.0"}
            )
            mock_client.get_with_headers = AsyncMock(
                return_value=(
                    [{"uuid": "proj-1", "name": "Test Project"}],
                    {"X-Total-Count": "1"}
                )
            )
            mock_client.post = AsyncMock(
                return_value={"uuid": "proj-1", "name": "Updated"}
            )
            mock_client.delete = AsyncMock(return_value=None)
            
            mock_get_instance.return_value = mock_client
            
            # Get create_project tool
            create_tool = find_tool(mcp, "create_project")
            assert create_tool is not None
            create_result = await create_tool.fn(name="Test Project")
            assert "project" in create_result
            
            # Get list_projects tool
            list_tool = find_tool(mcp, "list_projects")
            assert list_tool is not None
            list_result = await list_tool.fn()
            assert "projects" in list_result
            
            # Get get_project tool
            get_tool = find_tool(mcp, "get_project")
            assert get_tool is not None
            get_result = await get_tool.fn(uuid="proj-1")
            assert "project" in get_result
            
            # Get update_project tool
            update_tool = find_tool(mcp, "update_project")
            assert update_tool is not None
            update_result = await update_tool.fn(uuid="proj-1", name="Updated")
            assert "project" in update_result
            
            # Get delete_project tool
            delete_tool = find_tool(mcp, "delete_project")
            assert delete_tool is not None
            delete_result = await delete_tool.fn(uuid="proj-1")
            assert "message" in delete_result

    @pytest.mark.asyncio
    async def test_end_to_end_vulnerability_workflow(self, mcp):
        """Test a complete vulnerability management workflow."""
        register_vulnerability_tools(mcp)
        register_finding_tools(mcp)
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            
            # Mock vulnerability responses
            mock_client.get = AsyncMock(
                return_value={
                    "uuid": "vuln-1",
                    "vulnId": "CVE-2021-44228",
                    "severity": "CRITICAL",
                }
            )
            mock_client.get_with_headers = AsyncMock(
                return_value=(
                    [{"uuid": "vuln-1", "vulnId": "CVE-2021-44228"}],
                    {"X-Total-Count": "1"}
                )
            )
            
            mock_get_instance.return_value = mock_client
            
            # Get vulnerability
            get_tool = find_tool(mcp, "get_vulnerability")
            assert get_tool is not None
            result = await get_tool.fn(source="NVD", vuln_id="CVE-2021-44228")
            assert "vulnerability" in result
            assert result["vulnerability"]["vulnId"] == "CVE-2021-44228"

    @pytest.mark.asyncio
    async def test_error_handling_integration(self, mcp):
        """Test error handling across the server."""
        register_project_tools(mcp)
        
        from dependency_track_mcp.exceptions import NotFoundError
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(
                side_effect=NotFoundError("Project not found")
            )
            mock_get_instance.return_value = mock_client
            
            # Tool should handle the error gracefully
            get_tool = find_tool(mcp, "get_project")
            assert get_tool is not None
            result = await get_tool.fn(uuid="nonexistent")
            
            # Error should be returned in result
            assert "error" in result

    def test_settings_integration(self, mock_env_vars):
        """Test settings loading from environment."""
        settings = Settings(url="https://test.example.com", api_key="test-api-key")
        assert settings.url == "https://test.example.com"
        assert settings.api_key == "test-api-key"

    @pytest.mark.asyncio
    async def test_multiple_tool_types(self, mcp):
        """Test that different tool types can coexist."""
        # Register tools from different modules
        register_project_tools(mcp)
        register_metrics_tools(mcp)
        register_search_tools(mcp)
        
        # Verify each tool type is present
        tool_names = {tool.name for tool in get_registered_tools(mcp)}
        
        assert any("project" in name for name in tool_names)
        assert any("metric" in name for name in tool_names)
        assert any("search" in name for name in tool_names)

    @pytest.mark.asyncio
    async def test_pagination_across_tools(self, mcp):
        """Test pagination support across different tools."""
        register_project_tools(mcp)
        register_component_tools(mcp)
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(
                    [{"uuid": "1"}, {"uuid": "2"}],
                    {"X-Total-Count": "100"}
                )
            )
            mock_get_instance.return_value = mock_client
            
            # Test pagination on projects
            list_tool = find_tool(mcp, "list_projects")
            assert list_tool is not None
            result = await list_tool.fn(page=2, page_size=50)
            assert result["page"] == 2
            assert result["page_size"] == 50
            assert result["total"] == 100
