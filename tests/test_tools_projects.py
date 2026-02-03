"""Tests for project management tools."""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.exceptions import DependencyTrackError, NotFoundError
from dependency_track_mcp.tools.projects import register_project_tools
from tests.utils import find_tool


@pytest.fixture
def register_tools(mcp):
    """Register project tools."""
    register_project_tools(mcp)
    return mcp


class TestListProjectsTool:
    """Tests for list_projects tool."""

    @pytest.mark.asyncio
    async def test_list_projects_success(self, register_tools):
        """Test listing projects successfully."""
        mock_data = [{"uuid": "proj-1", "name": "Project 1"}]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_projects")
            assert tool is not None
            result = await tool.fn()
            
            assert "projects" in result
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_list_projects_with_filter(self, register_tools):
        """Test listing projects with filter."""
        mock_data = [{"uuid": "proj-1", "name": "Test"}]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_projects")
            assert tool is not None
            result = await tool.fn(name="Test", tag="prod", active=True)
            
            assert result["page"] == 1

    @pytest.mark.asyncio
    async def test_list_projects_error(self, register_tools):
        """Test listing projects with client error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_projects")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestGetProjectTool:
    """Tests for get_project tool."""

    @pytest.mark.asyncio
    async def test_get_project_success(self, register_tools):
        """Test getting project successfully."""
        mock_data = {"uuid": "proj-1", "name": "Project 1"}
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_project")
            assert tool is not None
            result = await tool.fn(uuid="proj-1")
            
            assert result["project"]["uuid"] == "proj-1"

    @pytest.mark.asyncio
    async def test_get_project_not_found(self, register_tools):
        """Test getting project that doesn't exist."""
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=NotFoundError("Not found"))
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_project")
            assert tool is not None
            result = await tool.fn(uuid="nonexistent")
            
            assert "error" in result

    @pytest.mark.asyncio
    async def test_get_project_error(self, register_tools):
        """Test get_project error handling."""
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_project")
            assert tool is not None
            result = await tool.fn(uuid="proj-1")

            assert "error" in result

    @pytest.mark.asyncio
    async def test_lookup_project_success(self, register_tools):
        """Test lookup_project tool."""
        mock_data = {"uuid": "proj-1", "name": "Project", "version": "1.0"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "lookup_project")
            assert tool is not None
            result = await tool.fn(name="Project", version="1.0")

            assert "project" in result

    @pytest.mark.asyncio
    async def test_lookup_project_error(self, register_tools):
        """Test lookup_project error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "lookup_project")
            assert tool is not None
            result = await tool.fn(name="Project", version="1.0")

            assert "error" in result


class TestCreateProjectTool:
    """Tests for create_project tool."""

    @pytest.mark.asyncio
    async def test_create_project_success(self, register_tools):
        """Test creating project successfully."""
        mock_data = {"uuid": "proj-1", "name": "New Project"}
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_project")
            assert tool is not None
            result = await tool.fn(name="New Project")
            
            assert result["message"] == "Project created successfully"
            assert result["project"]["uuid"] == "proj-1"

    @pytest.mark.asyncio
    async def test_create_project_with_tags(self, register_tools):
        """Test creating project with tags."""
        mock_data = {"uuid": "proj-1", "name": "New Project", "tags": [{"name": "prod"}]}
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_project")
            assert tool is not None
            result = await tool.fn(
                name="New Project",
                version="1.0",
                description="Desc",
                classifier="APPLICATION",
                tags=["prod"],
                parent_uuid="parent-1",
            )
            
            assert "project" in result

    @pytest.mark.asyncio
    async def test_create_project_error(self, register_tools):
        """Test create_project error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_project")
            assert tool is not None
            result = await tool.fn(name="New Project")

            assert "error" in result


class TestUpdateProjectTool:
    """Tests for update_project tool."""

    @pytest.mark.asyncio
    async def test_update_project_success(self, register_tools):
        """Test updating project successfully."""
        initial_data = {"uuid": "proj-1", "name": "Project 1", "version": "1.0"}
        updated_data = {"uuid": "proj-1", "name": "Updated", "version": "1.0"}
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=initial_data)
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "update_project")
            assert tool is not None
            result = await tool.fn(
                uuid="proj-1",
                name="Updated",
                version="1.0",
                description="New",
                active=False,
                tags=["prod"],
            )
            
            assert result["message"] == "Project updated successfully"

    @pytest.mark.asyncio
    async def test_update_project_error(self, register_tools):
        """Test update_project error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_project")
            assert tool is not None
            result = await tool.fn(uuid="proj-1", name="Updated")

            assert "error" in result


class TestDeleteProjectTool:
    """Tests for delete_project tool."""

    @pytest.mark.asyncio
    async def test_delete_project_success(self, register_tools):
        """Test deleting project successfully."""
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "delete_project")
            assert tool is not None
            result = await tool.fn(uuid="proj-1")
            
            assert "message" in result
            assert "deleted successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_delete_project_error(self, register_tools):
        """Test delete_project error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_project")
            assert tool is not None
            result = await tool.fn(uuid="proj-1")

            assert "error" in result

    @pytest.mark.asyncio
    async def test_get_project_children_success(self, register_tools):
        """Test get_project_children tool."""
        mock_data = [{"uuid": "child-1"}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(return_value=(mock_data, {"X-Total-Count": "1"}))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_project_children")
            assert tool is not None
            result = await tool.fn(uuid="proj-1", page=2, page_size=50)

            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_get_project_children_error(self, register_tools):
        """Test get_project_children error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_project_children")
            assert tool is not None
            result = await tool.fn(uuid="proj-1")

            assert "error" in result


class TestProjectChildrenTools:
    """Tests for project children tools."""

    @pytest.mark.asyncio
    async def test_get_project_children_by_classifier_success(self, register_tools):
        """Test get_project_children_by_classifier tool."""
        mock_data = [{"uuid": "child-1", "classifier": "APPLICATION"}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(return_value=(mock_data, {"X-Total-Count": "1"}))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_project_children_by_classifier")
            assert tool is not None
            result = await tool.fn(uuid="proj-1", classifier="APPLICATION")

            assert result["total"] == 1
            assert "children" in result

    @pytest.mark.asyncio
    async def test_get_project_children_by_classifier_error(self, register_tools):
        """Test get_project_children_by_classifier error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_project_children_by_classifier")
            assert tool is not None
            result = await tool.fn(uuid="proj-1", classifier="APPLICATION")

            assert "error" in result

    @pytest.mark.asyncio
    async def test_get_project_children_by_tag_success(self, register_tools):
        """Test get_project_children_by_tag tool."""
        mock_data = [{"uuid": "child-1", "tags": [{"name": "prod"}]}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(return_value=(mock_data, {"X-Total-Count": "1"}))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_project_children_by_tag")
            assert tool is not None
            result = await tool.fn(uuid="proj-1", tag="prod")

            assert result["total"] == 1
            assert "children" in result

    @pytest.mark.asyncio
    async def test_get_project_children_by_tag_error(self, register_tools):
        """Test get_project_children_by_tag error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_project_children_by_tag")
            assert tool is not None
            result = await tool.fn(uuid="proj-1", tag="prod")

            assert "error" in result


class TestProjectFilterTools:
    """Tests for project filtering tools."""

    @pytest.mark.asyncio
    async def test_list_projects_by_classifier_success(self, register_tools):
        """Test list_projects_by_classifier tool."""
        mock_data = [{"uuid": "proj-1", "classifier": "APPLICATION"}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(return_value=(mock_data, {"X-Total-Count": "1"}))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_projects_by_classifier")
            assert tool is not None
            result = await tool.fn(classifier="APPLICATION", page=1, page_size=50)

            assert result["total"] == 1
            assert "projects" in result

    @pytest.mark.asyncio
    async def test_list_projects_by_classifier_error(self, register_tools):
        """Test list_projects_by_classifier error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_projects_by_classifier")
            assert tool is not None
            result = await tool.fn(classifier="APPLICATION")

            assert "error" in result

    @pytest.mark.asyncio
    async def test_list_projects_by_tag_success(self, register_tools):
        """Test list_projects_by_tag tool."""
        mock_data = [{"uuid": "proj-1", "tags": [{"name": "prod"}]}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(return_value=(mock_data, {"X-Total-Count": "1"}))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_projects_by_tag")
            assert tool is not None
            result = await tool.fn(tag="prod")

            assert result["total"] == 1
            assert "projects" in result

    @pytest.mark.asyncio
    async def test_list_projects_by_tag_error(self, register_tools):
        """Test list_projects_by_tag error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_projects_by_tag")
            assert tool is not None
            result = await tool.fn(tag="prod")

            assert "error" in result

    @pytest.mark.asyncio
    async def test_get_latest_project_version_success(self, register_tools):
        """Test get_latest_project_version tool."""
        mock_data = {"uuid": "proj-1", "name": "Project", "version": "2.0"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_latest_project_version")
            assert tool is not None
            result = await tool.fn(name="Project")

            assert result["project"]["version"] == "2.0"

    @pytest.mark.asyncio
    async def test_get_latest_project_version_error(self, register_tools):
        """Test get_latest_project_version error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_latest_project_version")
            assert tool is not None
            result = await tool.fn(name="Project")

            assert "error" in result


class TestProjectOperationsTools:
    """Tests for project operations tools."""

    @pytest.mark.asyncio
    async def test_clone_project_success(self, register_tools):
        """Test clone_project tool."""
        mock_data = {"uuid": "proj-2", "name": "Cloned Project", "version": "2.0"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "clone_project")
            assert tool is not None
            result = await tool.fn(
                uuid="proj-1",
                version="2.0",
                include_tags=True,
                include_components=False,
            )

            assert result["project"]["version"] == "2.0"
            assert "message" in result

    @pytest.mark.asyncio
    async def test_clone_project_error(self, register_tools):
        """Test clone_project error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "clone_project")
            assert tool is not None
            result = await tool.fn(uuid="proj-1", version="2.0")

            assert "error" in result

    @pytest.mark.asyncio
    async def test_batch_delete_projects_success(self, register_tools):
        """Test batch_delete_projects tool."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "batch_delete_projects")
            assert tool is not None
            result = await tool.fn(uuids=["proj-1", "proj-2", "proj-3"])

            assert "message" in result
            assert "3 projects" in result["message"]

    @pytest.mark.asyncio
    async def test_batch_delete_projects_error(self, register_tools):
        """Test batch_delete_projects error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "batch_delete_projects")
            assert tool is not None
            result = await tool.fn(uuids=["proj-1"])

            assert "error" in result

    @pytest.mark.asyncio
    async def test_patch_project_success(self, register_tools):
        """Test patch_project tool."""
        mock_data = {"uuid": "proj-1", "name": "Patched", "active": False}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.patch = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "patch_project")
            assert tool is not None
            result = await tool.fn(
                uuid="proj-1",
                name="Patched",
                active=False,
                tags=["staging"],
            )

            assert result["project"]["name"] == "Patched"
            assert "message" in result

    @pytest.mark.asyncio
    async def test_patch_project_error(self, register_tools):
        """Test patch_project error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.patch = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "patch_project")
            assert tool is not None
            result = await tool.fn(uuid="proj-1", name="Patched")

            assert "error" in result

    @pytest.mark.asyncio
    async def test_list_projects_without_descendants_success(self, register_tools):
        """Test list_projects_without_descendants tool."""
        mock_data = [{"uuid": "proj-2", "name": "Other Project"}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(return_value=(mock_data, {"X-Total-Count": "1"}))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_projects_without_descendants")
            assert tool is not None
            result = await tool.fn(uuid="proj-1")

            assert result["total"] == 1
            assert "projects" in result

    @pytest.mark.asyncio
    async def test_list_projects_without_descendants_error(self, register_tools):
        """Test list_projects_without_descendants error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_projects_without_descendants")
            assert tool is not None
            result = await tool.fn(uuid="proj-1")

            assert "error" in result
