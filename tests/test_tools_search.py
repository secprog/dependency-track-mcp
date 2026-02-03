"""Tests for search tools."""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.tools.search import register_search_tools
from tests.utils import find_tool


@pytest.fixture
def register_tools(mcp):
    """Register search tools."""
    register_search_tools(mcp)
    return mcp


class TestSearchTool:
    """Tests for global search tool."""

    @pytest.mark.asyncio
    async def test_search_success(self, register_tools):
        """Test global search."""
        mock_data = {
            "projects": [{"uuid": "proj-1", "name": "Project 1"}],
            "components": [{"uuid": "comp-1", "name": "lodash"}],
        }
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "search")
            assert tool is not None
            result = await tool.fn(query="lodash")
            
            assert "results" in result
            assert result["query"] == "lodash"

    @pytest.mark.asyncio
    async def test_search_error(self, register_tools):
        """Test search error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "search")
            assert tool is not None
            result = await tool.fn(query="oops")

            assert "error" in result


class TestSearchProjectsTool:
    """Tests for project search tool."""

    @pytest.mark.asyncio
    async def test_search_projects_success(self, register_tools):
        """Test searching for projects."""
        mock_data = [{"uuid": "proj-1", "name": "Test Project"}]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "search_projects")
            assert tool is not None
            result = await tool.fn(query="Test")
            
            assert "projects" in result
            assert result["query"] == "Test"

    @pytest.mark.asyncio
    async def test_search_projects_error(self, register_tools):
        """Test search_projects error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "search_projects")
            assert tool is not None
            result = await tool.fn(query="Test")

            assert "error" in result


class TestSearchComponentsTool:
    """Tests for component search tool."""

    @pytest.mark.asyncio
    async def test_search_components_success(self, register_tools):
        """Test searching for components."""
        mock_data = [{"uuid": "comp-1", "name": "lodash", "version": "4.17.21"}]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "search_components")
            assert tool is not None
            result = await tool.fn(query="lodash")
            
            assert "components" in result
            assert result["query"] == "lodash"

    @pytest.mark.asyncio
    async def test_search_components_error(self, register_tools):
        """Test search_components error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "search_components")
            assert tool is not None
            result = await tool.fn(query="lodash")

            assert "error" in result


class TestSearchVulnerabilitiesTool:
    """Tests for vulnerability search tool."""

    @pytest.mark.asyncio
    async def test_search_vulnerabilities_success(self, register_tools):
        """Test searching for vulnerabilities."""
        mock_data = [{"uuid": "vuln-1", "vulnId": "CVE-2021-44228"}]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "search_vulnerabilities")
            assert tool is not None
            result = await tool.fn(query="CVE-2021-44228")
            
            assert "vulnerabilities" in result

    @pytest.mark.asyncio
    async def test_search_vulnerabilities_error(self, register_tools):
        """Test search_vulnerabilities error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "search_vulnerabilities")
            assert tool is not None
            result = await tool.fn(query="CVE-2021-44228")

            assert "error" in result


class TestSearchLicensesTool:
    """Tests for license search tool."""

    @pytest.mark.asyncio
    async def test_search_licenses_success(self, register_tools):
        """Test searching for licenses."""
        mock_data = [{"uuid": "lic-1", "name": "MIT License", "spdxLicenseId": "MIT"}]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "search_licenses")
            assert tool is not None
            result = await tool.fn(query="MIT")
            
            assert "licenses" in result
            assert result["query"] == "MIT"

    @pytest.mark.asyncio
    async def test_search_licenses_error(self, register_tools):
        """Test search_licenses error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "search_licenses")
            assert tool is not None
            result = await tool.fn(query="MIT")

            assert "error" in result


class TestSearchServicesTool:
    """Tests for search_services tool."""

    @pytest.mark.asyncio
    async def test_search_services_success(self, register_tools):
        """Test searching for services."""
        mock_data = [{"uuid": "svc-1", "name": "API Service", "version": "1.0"}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(return_value=(mock_data, {"X-Total-Count": "1"}))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "search_services")
            assert tool is not None
            result = await tool.fn(query="API")

            assert "services" in result
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_search_services_error(self, register_tools):
        """Test search_services error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "search_services")
            assert tool is not None
            result = await tool.fn(query="API")

            assert "error" in result


class TestSearchVulnerableSoftwareTool:
    """Tests for search_vulnerable_software tool."""

    @pytest.mark.asyncio
    async def test_search_vulnerable_software_success(self, register_tools):
        """Test searching for vulnerable software."""
        mock_data = [{"cpe": "cpe:2.3:a:apache:log4j:2.14.1", "vulnerabilities": []}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(return_value=(mock_data, {"X-Total-Count": "1"}))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "search_vulnerable_software")
            assert tool is not None
            result = await tool.fn(query="log4j")

            assert "vulnerableSoftware" in result
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_search_vulnerable_software_error(self, register_tools):
        """Test search_vulnerable_software error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "search_vulnerable_software")
            assert tool is not None
            result = await tool.fn(query="log4j")

            assert "error" in result


class TestReindexSearchTool:
    """Tests for reindex_search tool."""

    @pytest.mark.asyncio
    async def test_reindex_search_success(self, register_tools):
        """Test triggering search reindex."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "reindex_search")
            assert tool is not None
            result = await tool.fn()

            assert "message" in result

    @pytest.mark.asyncio
    async def test_reindex_search_error(self, register_tools):
        """Test reindex_search error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "reindex_search")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result
