"""Tests for components.py create_component cpe field coverage."""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.tools.components import register_component_tools
from tests.utils import find_tool


@pytest.fixture
def register_tools(mcp):
    """Register component tools."""
    register_component_tools(mcp)
    return mcp


class TestComponentsCreateComponentCPE:
    """Tests for create_component cpe field."""

    @pytest.mark.asyncio
    async def test_create_component_with_cpe(self, register_tools):
        """Test creating component with CPE field to cover line 211."""
        mock_data = {
            "uuid": "comp-1",
            "name": "test-lib",
            "cpe": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_component")
            assert tool is not None
            result = await tool.fn(
                project_uuid="proj-1",
                name="test-lib",
                cpe="cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
            )

            assert "component" in result
            assert result["component"]["cpe"] == "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
            # Verify that cpe was included in the put call
            call_args = mock_client.put.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["cpe"] == "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
