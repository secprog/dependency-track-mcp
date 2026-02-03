"""Tests for component management tools."""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.tools.components import register_component_tools
from tests.utils import find_tool


@pytest.fixture
def register_tools(mcp):
    """Register component tools."""
    register_component_tools(mcp)
    return mcp


class TestListComponentsTool:
    """Tests for list_project_components tool."""

    @pytest.mark.asyncio
    async def test_list_components_success(self, register_tools):
        """Test listing components successfully."""
        mock_data = [{"uuid": "comp-1", "name": "lodash", "version": "4.17.21"}]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_project_components")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")
            
            assert "components" in result
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_list_components_error(self, register_tools):
        """Test listing components with error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_project_components")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")

            assert "error" in result


class TestGetComponentTool:
    """Tests for get_component tool."""

    @pytest.mark.asyncio
    async def test_get_component_success(self, register_tools):
        """Test getting component successfully."""
        mock_data = {"uuid": "comp-1", "name": "lodash", "version": "4.17.21"}
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_component")
            assert tool is not None
            result = await tool.fn(uuid="comp-1")
            
            assert result["component"]["uuid"] == "comp-1"

    @pytest.mark.asyncio
    async def test_get_component_error(self, register_tools):
        """Test getting component with error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_component")
            assert tool is not None
            result = await tool.fn(uuid="comp-1")

            assert "error" in result


class TestFindComponentByPurlTool:
    """Tests for find_component_by_purl tool."""

    @pytest.mark.asyncio
    async def test_find_by_purl_success(self, register_tools):
        """Test finding component by PURL."""
        mock_data = [{"uuid": "comp-1", "purl": "pkg:npm/lodash@4.17.21"}]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "find_component_by_purl")
            assert tool is not None
            result = await tool.fn(purl="pkg:npm/lodash@4.17.21")
            
            assert "components" in result

    @pytest.mark.asyncio
    async def test_find_by_purl_error(self, register_tools):
        """Test finding component by PURL with error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "find_component_by_purl")
            assert tool is not None
            result = await tool.fn(purl="pkg:npm/lodash@4.17.21")

            assert "error" in result


class TestFindComponentByHashTool:
    """Tests for find_component_by_hash tool."""

    @pytest.mark.asyncio
    async def test_find_by_hash_success(self, register_tools):
        """Test finding component by hash."""
        mock_data = [{"uuid": "comp-1", "sha256": "abc123"}]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "find_component_by_hash")
            assert tool is not None
            result = await tool.fn(hash_value="abc123")
            
            assert "components" in result

    @pytest.mark.asyncio
    async def test_find_by_hash_error(self, register_tools):
        """Test finding component by hash with error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "find_component_by_hash")
            assert tool is not None
            result = await tool.fn(hash_value="abc123")

            assert "error" in result


class TestGetDependencyGraphTool:
    """Tests for get_dependency_graph tool."""

    @pytest.mark.asyncio
    async def test_get_dependency_graph_success(self, register_tools):
        """Test getting dependency graph."""
        mock_data = {"edges": [], "nodes": []}
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_dependency_graph")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")
            
            assert "graph" in result

    @pytest.mark.asyncio
    async def test_get_dependency_graph_error(self, register_tools):
        """Test getting dependency graph with error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_dependency_graph")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")

            assert "error" in result


class TestGetComponentProjectsTool:
    """Tests for get_component_projects tool."""

    @pytest.mark.asyncio
    async def test_get_component_projects_success(self, register_tools):
        """Test getting projects using component."""
        mock_data = [{"uuid": "proj-1", "name": "Project 1"}]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_component_projects")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")
            
            assert "projects" in result
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_get_component_projects_error(self, register_tools):
        """Test getting component projects with error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_component_projects")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")

            assert "error" in result
