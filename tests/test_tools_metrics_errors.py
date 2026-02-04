"""
Tests for metrics tool error handling.
Targets missing exception handling lines.
"""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.tools.metrics import register_metrics_tools
from tests.utils import find_tool


@pytest.fixture
def register_tools(mcp):
    """Register metrics tools."""
    register_metrics_tools(mcp)
    return mcp


class TestMetricsErrorHandling:
    """Tests for metrics error handling."""

    @pytest.mark.asyncio
    async def test_refresh_component_metrics_error(self, register_tools):
        """Test refresh_component_metrics error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Component not found")
            error.details = {"status": 404}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "refresh_component_metrics")
            assert tool is not None
            result = await tool.fn(component_uuid="bad-uuid")

            assert "error" in result
            assert result["error"] == "Component not found"
            assert "details" in result

    @pytest.mark.asyncio
    async def test_refresh_project_metrics_error(self, register_tools):
        """Test refresh_project_metrics error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Project not found")
            error.details = {"status": 404}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "refresh_project_metrics")
            assert tool is not None
            result = await tool.fn(project_uuid="bad-uuid")

            assert "error" in result
            assert result["error"] == "Project not found"
            assert "details" in result
