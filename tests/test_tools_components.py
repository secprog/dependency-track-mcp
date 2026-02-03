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


class TestCreateComponentTool:
    """Tests for create_component tool."""

    @pytest.mark.asyncio
    async def test_create_component_minimal(self, register_tools):
        """Test creating a component with minimal data."""
        mock_data = {"uuid": "comp-1", "name": "test-component"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_component")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1", name="test-component")
            
            assert "component" in result
            assert result["component"]["uuid"] == "comp-1"
            assert "message" in result

    @pytest.mark.asyncio
    async def test_create_component_full(self, register_tools):
        """Test creating a component with all fields."""
        mock_data = {"uuid": "comp-1", "name": "lodash", "version": "4.17.21"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_component")
            assert tool is not None
            result = await tool.fn(
                project_uuid="proj-1",
                name="lodash",
                version="4.17.21",
                group="lodash",
                purl="pkg:npm/lodash@4.17.21",
                description="A modern JavaScript utility library",
                license_name="MIT",
                classifier="LIBRARY"
            )
            
            assert "component" in result
            assert result["component"]["uuid"] == "comp-1"

    @pytest.mark.asyncio
    async def test_create_component_error(self, register_tools):
        """Test create_component error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(side_effect=DependencyTrackError("Creation failed"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_component")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1", name="test")

            assert "error" in result


class TestUpdateComponentTool:
    """Tests for update_component tool."""

    @pytest.mark.asyncio
    async def test_update_component_success(self, register_tools):
        """Test updating a component."""
        existing_data = {"uuid": "comp-1", "name": "old-name", "version": "1.0.0"}
        updated_data = {"uuid": "comp-1", "name": "new-name", "version": "2.0.0"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing_data)
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "update_component")
            assert tool is not None
            result = await tool.fn(uuid="comp-1", name="new-name", version="2.0.0")
            
            assert "component" in result
            assert result["component"]["name"] == "new-name"

    @pytest.mark.asyncio
    async def test_update_component_error(self, register_tools):
        """Test update_component error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Not found"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_component")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid", name="test")

            assert "error" in result


class TestDeleteComponentTool:
    """Tests for delete_component tool."""

    @pytest.mark.asyncio
    async def test_delete_component_success(self, register_tools):
        """Test deleting a component."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "delete_component")
            assert tool is not None
            result = await tool.fn(uuid="comp-1")
            
            assert "message" in result
            assert "comp-1" in result["message"]

    @pytest.mark.asyncio
    async def test_delete_component_error(self, register_tools):
        """Test delete_component error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(side_effect=DependencyTrackError("Delete failed"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_component")
            assert tool is not None
            result = await tool.fn(uuid="comp-1")

            assert "error" in result


class TestGetComponentDependencyGraphTool:
    """Tests for get_component_dependency_graph tool."""

    @pytest.mark.asyncio
    async def test_get_component_dependency_graph_success(self, register_tools):
        """Test getting component dependency graph."""
        mock_data = {"dependencies": []}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_component_dependency_graph")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1", component_uuids=["comp-1", "comp-2"])
            
            assert "graph" in result

    @pytest.mark.asyncio
    async def test_get_component_dependency_graph_error(self, register_tools):
        """Test get_component_dependency_graph error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Graph error"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_component_dependency_graph")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1", component_uuids=["comp-1"])

            assert "error" in result


class TestIdentifyInternalComponentsTool:
    """Tests for identify_internal_components tool."""

    @pytest.mark.asyncio
    async def test_identify_internal_components_success(self, register_tools):
        """Test identifying internal components."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "identify_internal_components")
            assert tool is not None
            result = await tool.fn()
            
            assert "message" in result

    @pytest.mark.asyncio
    async def test_identify_internal_components_error(self, register_tools):
        """Test identify_internal_components error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Identification failed"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "identify_internal_components")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestGetComponentDirectDependenciesTool:
    """Tests for get_component_direct_dependencies tool."""

    @pytest.mark.asyncio
    async def test_get_component_direct_dependencies_success(self, register_tools):
        """Test getting component direct dependencies."""
        mock_data = [{"uuid": "dep-1", "name": "dependency"}]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_component_direct_dependencies")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")
            
            assert "dependencies" in result

    @pytest.mark.asyncio
    async def test_get_component_direct_dependencies_error(self, register_tools):
        """Test get_component_direct_dependencies error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Dependencies error"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_component_direct_dependencies")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")

            assert "error" in result

