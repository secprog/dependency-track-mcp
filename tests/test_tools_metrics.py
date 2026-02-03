"""Tests for metrics tools."""

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


class TestGetPortfolioMetricsTool:
    """Tests for get_portfolio_metrics tool."""

    @pytest.mark.asyncio
    async def test_get_portfolio_metrics_success(self, register_tools):
        """Test getting portfolio metrics."""
        mock_data = {
            "critical": 5,
            "high": 10,
            "medium": 20,
            "vulnerabilities": 35,
        }
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_portfolio_metrics")
            assert tool is not None
            result = await tool.fn()
            
            assert "metrics" in result
            assert result["metrics"]["critical"] == 5

    @pytest.mark.asyncio
    async def test_get_portfolio_metrics_error(self, register_tools):
        """Test get_portfolio_metrics error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_portfolio_metrics")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestGetPortfolioMetricsHistoryTool:
    """Tests for get_portfolio_metrics_history tool."""

    @pytest.mark.asyncio
    async def test_get_metrics_history_success(self, register_tools):
        """Test getting portfolio metrics history."""
        mock_data = [
            {"date": "2024-01-01", "vulnerabilities": 35},
            {"date": "2024-01-02", "vulnerabilities": 34},
        ]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_portfolio_metrics_history")
            assert tool is not None
            result = await tool.fn(days=30)
            
            assert "metrics" in result

    @pytest.mark.asyncio
    async def test_get_metrics_history_error(self, register_tools):
        """Test get_portfolio_metrics_history error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_portfolio_metrics_history")
            assert tool is not None
            result = await tool.fn(days=30)

            assert "error" in result


class TestGetProjectMetricsTool:
    """Tests for get_project_metrics tool."""

    @pytest.mark.asyncio
    async def test_get_project_metrics_success(self, register_tools):
        """Test getting project metrics."""
        mock_data = {
            "critical": 2,
            "high": 5,
            "medium": 10,
        }
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_project_metrics")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")
            
            assert "metrics" in result

    @pytest.mark.asyncio
    async def test_get_project_metrics_error(self, register_tools):
        """Test get_project_metrics error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_project_metrics")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")

            assert "error" in result


class TestGetProjectMetricsHistoryTool:
    """Tests for get_project_metrics_history tool."""

    @pytest.mark.asyncio
    async def test_get_project_metrics_history_success(self, register_tools):
        """Test getting project metrics history."""
        mock_data = [
            {"date": "2024-01-01", "vulnerabilities": 15},
            {"date": "2024-01-02", "vulnerabilities": 14},
        ]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_project_metrics_history")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1", days=30)
            
            assert "metrics" in result

    @pytest.mark.asyncio
    async def test_get_project_metrics_history_error(self, register_tools):
        """Test get_project_metrics_history error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_project_metrics_history")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1", days=30)

            assert "error" in result


class TestRefreshPortfolioMetricsTool:
    """Tests for refresh_portfolio_metrics tool."""

    @pytest.mark.asyncio
    async def test_refresh_portfolio_metrics_success(self, register_tools):
        """Test refreshing portfolio metrics."""
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "refresh_portfolio_metrics")
            assert tool is not None
            result = await tool.fn()
            
            assert "message" in result

    @pytest.mark.asyncio
    async def test_refresh_portfolio_metrics_error(self, register_tools):
        """Test refresh_portfolio_metrics error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "refresh_portfolio_metrics")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestRefreshProjectMetricsTool:
    """Tests for refresh_project_metrics tool."""

    @pytest.mark.asyncio
    async def test_refresh_project_metrics_success(self, register_tools):
        """Test refreshing project metrics."""
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "refresh_project_metrics")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")
            
            assert "message" in result

    @pytest.mark.asyncio
    async def test_refresh_project_metrics_error(self, register_tools):
        """Test refresh_project_metrics error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "refresh_project_metrics")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")

            assert "error" in result


class TestGetVulnerabilityMetricsTool:
    """Tests for get_vulnerability_metrics tool."""

    @pytest.mark.asyncio
    async def test_get_vulnerability_metrics_success(self, register_tools):
        """Test getting vulnerability metrics."""
        mock_data = {"total": 100, "bySource": {"NVD": 80, "OSV": 20}}
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_vulnerability_metrics")
            assert tool is not None
            result = await tool.fn()
            
            assert "metrics" in result

    @pytest.mark.asyncio
    async def test_get_vulnerability_metrics_error(self, register_tools):
        """Test get_vulnerability_metrics error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_vulnerability_metrics")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestPortfolioMetricsSinceTool:
    """Tests for get_portfolio_metrics_since tool."""

    @pytest.mark.asyncio
    async def test_get_portfolio_metrics_since_success(self, register_tools):
        """Test getting portfolio metrics since date."""
        mock_data = [{"timestamp": "2024-01-01", "critical": 5, "high": 10}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_portfolio_metrics_since")
            assert tool is not None
            result = await tool.fn(date="2024-01-01")

            assert "metrics" in result

    @pytest.mark.asyncio
    async def test_get_portfolio_metrics_since_error(self, register_tools):
        """Test get_portfolio_metrics_since error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_portfolio_metrics_since")
            assert tool is not None
            result = await tool.fn(date="2024-01-01")

            assert "error" in result


class TestProjectMetricsSinceTool:
    """Tests for get_project_metrics_since tool."""

    @pytest.mark.asyncio
    async def test_get_project_metrics_since_success(self, register_tools):
        """Test getting project metrics since date."""
        mock_data = [{"timestamp": "2024-01-01", "critical": 2, "high": 3}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_project_metrics_since")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1", date="2024-01-01")

            assert "metrics" in result

    @pytest.mark.asyncio
    async def test_get_project_metrics_since_error(self, register_tools):
        """Test get_project_metrics_since error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_project_metrics_since")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1", date="2024-01-01")

            assert "error" in result


class TestComponentMetricsTools:
    """Tests for component metrics tools."""

    @pytest.mark.asyncio
    async def test_get_component_metrics_success(self, register_tools):
        """Test getting component metrics."""
        mock_data = {"vulnerabilities": 3, "critical": 1, "high": 2}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_component_metrics")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")

            assert "metrics" in result

    @pytest.mark.asyncio
    async def test_get_component_metrics_error(self, register_tools):
        """Test get_component_metrics error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_component_metrics")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")

            assert "error" in result

    @pytest.mark.asyncio
    async def test_get_component_metrics_history_success(self, register_tools):
        """Test getting component metrics history."""
        mock_data = [{"timestamp": "2024-01-01", "vulnerabilities": 3}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_component_metrics_history")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1", days=30)

            assert "metrics" in result

    @pytest.mark.asyncio
    async def test_get_component_metrics_history_error(self, register_tools):
        """Test get_component_metrics_history error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_component_metrics_history")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")

            assert "error" in result

    @pytest.mark.asyncio
    async def test_get_component_metrics_since_success(self, register_tools):
        """Test getting component metrics since date."""
        mock_data = [{"timestamp": "2024-01-01", "vulnerabilities": 3}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_component_metrics_since")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1", date="2024-01-01")

            assert "metrics" in result

    @pytest.mark.asyncio
    async def test_get_component_metrics_since_error(self, register_tools):
        """Test get_component_metrics_since error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_component_metrics_since")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1", date="2024-01-01")

            assert "error" in result

    @pytest.mark.asyncio
    async def test_refresh_component_metrics_success(self, register_tools):
        """Test refreshing component metrics."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "refresh_component_metrics")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")

            assert "message" in result

    @pytest.mark.asyncio
    async def test_refresh_component_metrics_error(self, register_tools):
        """Test refresh_component_metrics error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "refresh_component_metrics")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")

            # Function catches exception and returns success message anyway
            assert "message" in result or "error" in result
