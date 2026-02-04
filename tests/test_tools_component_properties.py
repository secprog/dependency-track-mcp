"""Tests for component property management tools."""

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


class TestListComponentPropertiesTool:
    """Tests for list_component_properties tool."""

    @pytest.mark.asyncio
    async def test_list_component_properties_success(self, register_tools):
        """Test listing component properties."""
        mock_properties = [
            {
                "uuid": "prop-1",
                "groupName": "security",
                "propertyName": "owner",
                "propertyValue": "team-a",
                "propertyType": "STRING",
            },
            {
                "uuid": "prop-2",
                "groupName": "custom",
                "propertyName": "critical",
                "propertyValue": "true",
                "propertyType": "BOOLEAN",
            },
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_properties)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_component_properties")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-123")

            assert "properties" in result
            assert result["properties"] == mock_properties
            mock_client.get.assert_called_once_with("/component/comp-123/property")

    @pytest.mark.asyncio
    async def test_list_component_properties_empty(self, register_tools):
        """Test listing component properties when none exist."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=[])
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_component_properties")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-456")

            assert "properties" in result
            assert result["properties"] == []

    @pytest.mark.asyncio
    async def test_list_component_properties_error(self, register_tools):
        """Test list_component_properties error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Component not found")
            error.details = {"status": 404}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_component_properties")
            assert tool is not None
            result = await tool.fn(component_uuid="bad-uuid")

            assert "error" in result
            assert "Component not found" in str(result["error"])


class TestCreateComponentPropertyTool:
    """Tests for create_component_property tool."""

    @pytest.mark.asyncio
    async def test_create_component_property_success(self, register_tools):
        """Test creating a component property."""
        mock_property = {
            "uuid": "new-prop",
            "groupName": "security",
            "propertyName": "owner",
            "propertyValue": "team-a",
            "propertyType": "STRING",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_property)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_component_property")
            assert tool is not None
            result = await tool.fn(
                component_uuid="comp-123",
                group_name="security",
                property_name="owner",
                property_value="team-a",
            )

            assert "property" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()
            assert result["property"] == mock_property

    @pytest.mark.asyncio
    async def test_create_component_property_with_description(self, register_tools):
        """Test creating component property with description."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={"uuid": "prop-1"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_component_property")
            assert tool is not None
            await tool.fn(
                component_uuid="comp-123",
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
    async def test_create_component_property_with_type(self, register_tools):
        """Test creating component property with different types."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={"uuid": "prop-1"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_component_property")
            assert tool is not None
            await tool.fn(
                component_uuid="comp-123",
                group_name="custom",
                property_name="count",
                property_value="42",
                property_type="INTEGER",
            )

            call_args = mock_client.put.call_args
            payload = call_args[1]["data"]
            assert payload["propertyType"] == "INTEGER"

    @pytest.mark.asyncio
    async def test_create_component_property_error(self, register_tools):
        """Test create_component_property error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Property already exists")
            error.details = {"status": 409}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_component_property")
            assert tool is not None
            result = await tool.fn(
                component_uuid="comp-123",
                group_name="security",
                property_name="owner",
                property_value="team-a",
            )

            assert "error" in result
            assert "Property already exists" in str(result["error"])


class TestDeleteComponentPropertyTool:
    """Tests for delete_component_property tool."""

    @pytest.mark.asyncio
    async def test_delete_component_property_success(self, register_tools):
        """Test deleting a component property."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_component_property")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-123", property_uuid="prop-456")

            assert "message" in result
            assert "deleted" in result["message"].lower()
            mock_client.delete.assert_called_once_with("/component/comp-123/property/prop-456")

    @pytest.mark.asyncio
    async def test_delete_component_property_error(self, register_tools):
        """Test delete_component_property error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Property not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_component_property")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-123", property_uuid="bad-uuid")

            assert "error" in result
            assert "Property not found" in str(result["error"])
