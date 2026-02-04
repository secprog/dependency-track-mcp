"""Tests for configuration property management tools."""

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


class TestListConfigPropertiesTool:
    """Tests for list_config_properties tool."""

    @pytest.mark.asyncio
    async def test_list_config_properties_success(self, register_tools):
        """Test listing configuration properties."""
        mock_properties = [
            {
                "groupName": "general",
                "propertyName": "base.url",
                "propertyValue": "https://example.com",
            },
            {
                "groupName": "scanner",
                "propertyName": "ossindex.enabled",
                "propertyValue": "true",
            },
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_properties)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_config_properties")
            assert tool is not None
            result = await tool.fn()

            assert "properties" in result
            assert result["properties"] == mock_properties
            mock_client.get.assert_called_once_with("/configProperty")

    @pytest.mark.asyncio
    async def test_list_config_properties_error(self, register_tools):
        """Test list_config_properties error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Access denied")
            error.details = {"status": 403}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_config_properties")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result
            assert "Access denied" in str(result["error"])


class TestGetPublicConfigPropertyTool:
    """Tests for get_public_config_property tool."""

    @pytest.mark.asyncio
    async def test_get_public_config_property_success(self, register_tools):
        """Test getting a public configuration property."""
        mock_property = {
            "groupName": "general",
            "propertyName": "base.url",
            "propertyValue": "https://example.com",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_property)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_public_config_property")
            assert tool is not None
            result = await tool.fn(group_name="general", property_name="base.url")

            assert "property" in result
            assert result["property"] == mock_property
            mock_client.get.assert_called_once_with("/configProperty/public/general/base.url")

    @pytest.mark.asyncio
    async def test_get_public_config_property_error(self, register_tools):
        """Test get_public_config_property error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Property not found")
            error.details = {"status": 404}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_public_config_property")
            assert tool is not None
            result = await tool.fn(group_name="bad", property_name="notfound")

            assert "error" in result
            assert "Property not found" in str(result["error"])


class TestUpdateConfigPropertyTool:
    """Tests for update_config_property tool."""

    @pytest.mark.asyncio
    async def test_update_config_property_success(self, register_tools):
        """Test updating a configuration property."""
        mock_property = {
            "groupName": "general",
            "propertyName": "base.url",
            "propertyValue": "https://new-url.com",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_property)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_config_property")
            assert tool is not None
            result = await tool.fn(
                group_name="general",
                property_name="base.url",
                property_value="https://new-url.com",
            )

            assert "property" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()
            assert result["property"] == mock_property

    @pytest.mark.asyncio
    async def test_update_config_property_payload(self, register_tools):
        """Test update_config_property sends correct payload."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value={})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_config_property")
            assert tool is not None
            await tool.fn(
                group_name="scanner",
                property_name="ossindex.enabled",
                property_value="false",
            )

            call_args = mock_client.post.call_args
            payload = call_args[1]["data"]
            assert payload["groupName"] == "scanner"
            assert payload["propertyName"] == "ossindex.enabled"
            assert payload["propertyValue"] == "false"

    @pytest.mark.asyncio
    async def test_update_config_property_error(self, register_tools):
        """Test update_config_property error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Invalid property value")
            error.details = {"status": 400}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_config_property")
            assert tool is not None
            result = await tool.fn(
                group_name="general",
                property_name="base.url",
                property_value="invalid-url",
            )

            assert "error" in result
            assert "Invalid property value" in str(result["error"])


class TestUpdateConfigPropertiesBatchTool:
    """Tests for update_config_properties_batch tool."""

    @pytest.mark.asyncio
    async def test_update_config_properties_batch_success(self, register_tools):
        """Test updating multiple configuration properties."""
        mock_properties = [
            {"groupName": "general", "propertyName": "base.url", "propertyValue": "https://a.com"},
            {"groupName": "scanner", "propertyName": "enabled", "propertyValue": "true"},
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_properties)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_config_properties_batch")
            assert tool is not None
            result = await tool.fn(properties=mock_properties)

            assert "properties" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()
            mock_client.post.assert_called_once_with(
                "/configProperty/aggregate", data=mock_properties
            )

    @pytest.mark.asyncio
    async def test_update_config_properties_batch_empty(self, register_tools):
        """Test batch update with empty list."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=[])
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_config_properties_batch")
            assert tool is not None
            result = await tool.fn(properties=[])

            assert "properties" in result
            assert result["properties"] == []

    @pytest.mark.asyncio
    async def test_update_config_properties_batch_error(self, register_tools):
        """Test update_config_properties_batch error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Validation failed")
            error.details = {"status": 400}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_config_properties_batch")
            assert tool is not None
            result = await tool.fn(
                properties=[
                    {"groupName": "bad", "propertyName": "test", "propertyValue": "invalid"}
                ]
            )

            assert "error" in result
            assert "Validation failed" in str(result["error"])
