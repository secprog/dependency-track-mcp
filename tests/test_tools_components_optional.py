"""
Tests for components tool optional field coverage.
Targets missing lines in update_component optional field handling.
"""
import pytest
from unittest.mock import AsyncMock, patch

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.tools.components import register_component_tools
from tests.utils import find_tool


@pytest.fixture
def register_tools(mcp):
    """Register component tools."""
    register_component_tools(mcp)
    return mcp


class TestComponentsOptionalFields:
    """Tests for components optional field handling."""

    @pytest.mark.asyncio
    async def test_update_component_with_group(self, register_tools):
        """Test updating component with group field."""
        existing_data = {
            "uuid": "comp-1",
            "name": "test",
            "version": "1.0.0",
            "group": "old-group",
        }
        updated_data = {
            "uuid": "comp-1",
            "name": "test",
            "version": "1.0.0",
            "group": "new-group",
        }

        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing_data)
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_component")
            assert tool is not None
            result = await tool.fn(uuid="comp-1", group="new-group")

            assert "component" in result
            assert result["component"]["group"] == "new-group"
            # Verify that group was included in the post call
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["group"] == "new-group"

    @pytest.mark.asyncio
    async def test_update_component_with_purl(self, register_tools):
        """Test updating component with purl field."""
        existing_data = {
            "uuid": "comp-1",
            "name": "test",
            "version": "1.0.0",
            "purl": "pkg:npm/old@1.0.0",
        }
        updated_data = {
            "uuid": "comp-1",
            "name": "test",
            "version": "1.0.0",
            "purl": "pkg:npm/new@2.0.0",
        }

        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing_data)
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_component")
            assert tool is not None
            result = await tool.fn(uuid="comp-1", purl="pkg:npm/new@2.0.0")

            assert "component" in result
            assert result["component"]["purl"] == "pkg:npm/new@2.0.0"
            # Verify that purl was included in the post call
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["purl"] == "pkg:npm/new@2.0.0"

    @pytest.mark.asyncio
    async def test_update_component_with_cpe(self, register_tools):
        """Test updating component with cpe field."""
        existing_data = {
            "uuid": "comp-1",
            "name": "test",
            "version": "1.0.0",
            "cpe": "cpe:2.3:a:vendor:product:old:*:*:*:*:*:*:*",
        }
        updated_data = {
            "uuid": "comp-1",
            "name": "test",
            "version": "1.0.0",
            "cpe": "cpe:2.3:a:vendor:product:new:*:*:*:*:*:*:*",
        }

        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing_data)
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_component")
            assert tool is not None
            result = await tool.fn(
                uuid="comp-1", cpe="cpe:2.3:a:vendor:product:new:*:*:*:*:*:*:*"
            )

            assert "component" in result
            assert result["component"]["cpe"] == "cpe:2.3:a:vendor:product:new:*:*:*:*:*:*:*"
            # Verify that cpe was included in the post call
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["cpe"] == "cpe:2.3:a:vendor:product:new:*:*:*:*:*:*:*"

    @pytest.mark.asyncio
    async def test_update_component_with_description(self, register_tools):
        """Test updating component with description field."""
        existing_data = {
            "uuid": "comp-1",
            "name": "test",
            "version": "1.0.0",
            "description": "old description",
        }
        updated_data = {
            "uuid": "comp-1",
            "name": "test",
            "version": "1.0.0",
            "description": "new description",
        }

        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing_data)
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_component")
            assert tool is not None
            result = await tool.fn(uuid="comp-1", description="new description")

            assert "component" in result
            assert result["component"]["description"] == "new description"
            # Verify that description was included in the post call
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["description"] == "new description"

    @pytest.mark.asyncio
    async def test_update_component_with_license(self, register_tools):
        """Test updating component with license_name field."""
        existing_data = {
            "uuid": "comp-1",
            "name": "test",
            "version": "1.0.0",
            "license": "MIT",
        }
        updated_data = {
            "uuid": "comp-1",
            "name": "test",
            "version": "1.0.0",
            "license": "Apache-2.0",
        }

        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing_data)
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_component")
            assert tool is not None
            result = await tool.fn(uuid="comp-1", license_name="Apache-2.0")

            assert "component" in result
            assert result["component"]["license"] == "Apache-2.0"
            # Verify that license was included in the post call
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["license"] == "Apache-2.0"

    @pytest.mark.asyncio
    async def test_update_component_all_optional_fields(self, register_tools):
        """Test updating component with all optional fields."""
        existing_data = {
            "uuid": "comp-1",
            "name": "old-name",
            "version": "1.0.0",
            "group": "old-group",
            "purl": "pkg:npm/old@1.0.0",
            "cpe": "cpe:2.3:a:vendor:product:old:*:*:*:*:*:*:*",
            "description": "old description",
            "license": "MIT",
        }
        updated_data = {
            "uuid": "comp-1",
            "name": "new-name",
            "version": "2.0.0",
            "group": "new-group",
            "purl": "pkg:npm/new@2.0.0",
            "cpe": "cpe:2.3:a:vendor:product:new:*:*:*:*:*:*:*",
            "description": "new description",
            "license": "Apache-2.0",
        }

        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing_data)
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_component")
            assert tool is not None
            result = await tool.fn(
                uuid="comp-1",
                name="new-name",
                version="2.0.0",
                group="new-group",
                purl="pkg:npm/new@2.0.0",
                cpe="cpe:2.3:a:vendor:product:new:*:*:*:*:*:*:*",
                description="new description",
                license_name="Apache-2.0",
            )

            assert "component" in result
            # Verify that all fields were included in the post call
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["name"] == "new-name"
            assert posted_data["version"] == "2.0.0"
            assert posted_data["group"] == "new-group"
            assert posted_data["purl"] == "pkg:npm/new@2.0.0"
            assert posted_data["cpe"] == "cpe:2.3:a:vendor:product:new:*:*:*:*:*:*:*"
            assert posted_data["description"] == "new description"
            assert posted_data["license"] == "Apache-2.0"

    @pytest.mark.asyncio
    async def test_update_component_partial_optional_fields(self, register_tools):
        """Test updating component with some optional fields (not all)."""
        existing_data = {
            "uuid": "comp-1",
            "name": "test",
            "version": "1.0.0",
            "group": "group",
            "purl": "pkg:npm/old@1.0.0",
            "cpe": "cpe:2.3:a:vendor:product:old:*:*:*:*:*:*:*",
            "description": "description",
            "license": "MIT",
        }
        updated_data = {
            "uuid": "comp-1",
            "name": "test",
            "version": "1.0.0",
            "group": "new-group",
            "purl": "pkg:npm/old@1.0.0",
            "cpe": "cpe:2.3:a:vendor:product:new:*:*:*:*:*:*:*",
            "description": "description",
            "license": "MIT",
        }

        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing_data)
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_component")
            assert tool is not None
            result = await tool.fn(
                uuid="comp-1",
                group="new-group",
                cpe="cpe:2.3:a:vendor:product:new:*:*:*:*:*:*:*",
            )

            assert "component" in result
            # Verify that only specified fields were modified
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["group"] == "new-group"
            assert posted_data["cpe"] == "cpe:2.3:a:vendor:product:new:*:*:*:*:*:*:*"
            # Other fields should remain unchanged
            assert posted_data["purl"] == "pkg:npm/old@1.0.0"
            assert posted_data["license"] == "MIT"

    @pytest.mark.asyncio
    async def test_create_component_with_classifier(self, register_tools):
        """Test creating component with classifier field."""
        mock_data = {
            "uuid": "comp-1",
            "name": "lodash",
            "version": "4.17.21",
            "classifier": "LIBRARY",
        }

        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_component")
            assert tool is not None
            result = await tool.fn(
                project_uuid="proj-1",
                name="lodash",
                version="4.17.21",
                classifier="LIBRARY",
            )

            assert "component" in result
            assert result["component"]["classifier"] == "LIBRARY"
            # Verify that classifier was included in the put call
            call_args = mock_client.put.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["classifier"] == "LIBRARY"
