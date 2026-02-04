"""Tests for project property management tools."""

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


class TestListProjectPropertiesTool:
    """Tests for list_project_properties tool."""

    @pytest.mark.asyncio
    async def test_list_project_properties_success(self, register_tools):
        """Test listing project properties."""
        mock_properties = [
            {
                "uuid": "prop-1",
                "groupName": "metadata",
                "propertyName": "department",
                "propertyValue": "engineering",
                "propertyType": "STRING",
            },
            {
                "uuid": "prop-2",
                "groupName": "custom",
                "propertyName": "priority",
                "propertyValue": "1",
                "propertyType": "INTEGER",
            },
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_properties)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_project_properties")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-123")

            assert "properties" in result
            assert result["properties"] == mock_properties
            mock_client.get.assert_called_once_with("/project/proj-123/property")

    @pytest.mark.asyncio
    async def test_list_project_properties_empty(self, register_tools):
        """Test listing project properties when none exist."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=[])
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_project_properties")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-456")

            assert "properties" in result
            assert result["properties"] == []

    @pytest.mark.asyncio
    async def test_list_project_properties_error(self, register_tools):
        """Test list_project_properties error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Project not found")
            error.details = {"status": 404}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_project_properties")
            assert tool is not None
            result = await tool.fn(project_uuid="bad-uuid")

            assert "error" in result
            assert "Project not found" in str(result["error"])


class TestCreateProjectPropertyTool:
    """Tests for create_project_property tool."""

    @pytest.mark.asyncio
    async def test_create_project_property_success(self, register_tools):
        """Test creating a project property."""
        mock_property = {
            "uuid": "new-prop",
            "groupName": "metadata",
            "propertyName": "owner",
            "propertyValue": "team-a",
            "propertyType": "STRING",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_property)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_project_property")
            assert tool is not None
            result = await tool.fn(
                project_uuid="proj-123",
                group_name="metadata",
                property_name="owner",
                property_value="team-a",
            )

            assert "property" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()
            assert result["property"] == mock_property

    @pytest.mark.asyncio
    async def test_create_project_property_with_description(self, register_tools):
        """Test creating project property with description."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={"uuid": "prop-1"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_project_property")
            assert tool is not None
            await tool.fn(
                project_uuid="proj-123",
                group_name="custom",
                property_name="test",
                property_value="value",
                property_type="STRING",
                description="Test property description",
            )

            call_args = mock_client.put.call_args
            payload = call_args[1]["data"]
            assert payload["description"] == "Test property description"
            assert payload["groupName"] == "custom"
            assert payload["propertyName"] == "test"
            assert payload["propertyValue"] == "value"

    @pytest.mark.asyncio
    async def test_create_project_property_with_type(self, register_tools):
        """Test creating project property with different types."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={"uuid": "prop-1"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_project_property")
            assert tool is not None
            await tool.fn(
                project_uuid="proj-123",
                group_name="custom",
                property_name="url",
                property_value="https://example.com",
                property_type="URL",
            )

            call_args = mock_client.put.call_args
            payload = call_args[1]["data"]
            assert payload["propertyType"] == "URL"

    @pytest.mark.asyncio
    async def test_create_project_property_error(self, register_tools):
        """Test create_project_property error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Property already exists")
            error.details = {"status": 409}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_project_property")
            assert tool is not None
            result = await tool.fn(
                project_uuid="proj-123",
                group_name="metadata",
                property_name="owner",
                property_value="team-a",
            )

            assert "error" in result
            assert "Property already exists" in str(result["error"])


class TestUpdateProjectPropertyTool:
    """Tests for update_project_property tool."""

    @pytest.mark.asyncio
    async def test_update_project_property_success(self, register_tools):
        """Test updating a project property."""
        mock_property = {
            "groupName": "metadata",
            "propertyName": "owner",
            "propertyValue": "team-b",
            "propertyType": "STRING",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_property)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_project_property")
            assert tool is not None
            result = await tool.fn(
                project_uuid="proj-123",
                group_name="metadata",
                property_name="owner",
                property_value="team-b",
            )

            assert "property" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_update_project_property_payload(self, register_tools):
        """Test update_project_property sends correct payload."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value={})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_project_property")
            assert tool is not None
            await tool.fn(
                project_uuid="proj-123",
                group_name="custom",
                property_name="count",
                property_value="100",
                property_type="INTEGER",
            )

            call_args = mock_client.post.call_args
            payload = call_args[1]["data"]
            assert payload["groupName"] == "custom"
            assert payload["propertyName"] == "count"
            assert payload["propertyValue"] == "100"
            assert payload["propertyType"] == "INTEGER"

    @pytest.mark.asyncio
    async def test_update_project_property_error(self, register_tools):
        """Test update_project_property error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Property not found")
            error.details = {"status": 404}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_project_property")
            assert tool is not None
            result = await tool.fn(
                project_uuid="proj-123",
                group_name="bad",
                property_name="notfound",
                property_value="value",
            )

            assert "error" in result
            assert "Property not found" in str(result["error"])


class TestDeleteProjectPropertyTool:
    """Tests for delete_project_property tool."""

    @pytest.mark.asyncio
    async def test_delete_project_property_success(self, register_tools):
        """Test deleting a project property."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_project_property")
            assert tool is not None
            result = await tool.fn(
                project_uuid="proj-123", group_name="metadata", property_name="owner"
            )

            assert "message" in result
            assert "deleted" in result["message"].lower()
            call_args = mock_client.delete.call_args
            assert call_args[0][0] == "/project/proj-123/property"
            assert call_args[1]["params"]["groupName"] == "metadata"
            assert call_args[1]["params"]["propertyName"] == "owner"

    @pytest.mark.asyncio
    async def test_delete_project_property_error(self, register_tools):
        """Test delete_project_property error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Property not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_project_property")
            assert tool is not None
            result = await tool.fn(
                project_uuid="proj-123", group_name="bad", property_name="notfound"
            )

            assert "error" in result
            assert "Property not found" in str(result["error"])
