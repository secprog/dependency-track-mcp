"""Tests for license management tools."""

import pytest
from unittest.mock import AsyncMock, patch

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.exceptions import DependencyTrackError
from tests.utils import find_tool


@pytest.fixture
def register_tools():
    """Fixture that registers all tools."""
    from dependency_track_mcp.server import mcp
    return mcp


class TestListLicensesTool:
    """Tests for list_licenses tool."""

    @pytest.mark.asyncio
    async def test_list_licenses_success(self, register_tools):
        """Test listing all licenses with metadata."""
        mock_licenses = [
            {"spdxId": "MIT", "name": "MIT License"},
            {"spdxId": "Apache-2.0", "name": "Apache License 2.0"},
        ]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_licenses, {"X-Total-Count": "2"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_licenses")
            assert tool is not None
            result = await tool.fn()
            
            assert "licenses" in result
            assert result["licenses"] == mock_licenses
            assert result["total"] == 2
            assert result["page"] == 1
            assert result["page_size"] == 100
            mock_client.get_with_headers.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_licenses_with_pagination(self, register_tools):
        """Test list_licenses with custom pagination."""
        mock_licenses = [{"spdxId": "MIT", "name": "MIT License"}]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_licenses, {"X-Total-Count": "500"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_licenses")
            assert tool is not None
            result = await tool.fn(page=5, page_size=50)
            
            assert result["page"] == 5
            assert result["page_size"] == 50
            assert result["total"] == 500
            call_args = mock_client.get_with_headers.call_args
            assert call_args[1]["params"] == {"pageNumber": 5, "pageSize": 50}

    @pytest.mark.asyncio
    async def test_list_licenses_error(self, register_tools):
        """Test list_licenses error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Failed to fetch licenses")
            error.details = {"status": 500}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_licenses")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result
            assert "details" in result


class TestListLicensesConciseTool:
    """Tests for list_licenses_concise tool."""

    @pytest.mark.asyncio
    async def test_list_licenses_concise_success(self, register_tools):
        """Test listing licenses in concise format."""
        mock_licenses = [
            {"spdxId": "MIT"},
            {"spdxId": "Apache-2.0"},
        ]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_licenses, {"X-Total-Count": "2"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_licenses_concise")
            assert tool is not None
            result = await tool.fn()
            
            assert "licenses" in result
            assert result["licenses"] == mock_licenses
            assert result["total"] == 2
            mock_client.get_with_headers.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_licenses_concise_endpoint(self, register_tools):
        """Test list_licenses_concise calls correct endpoint."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(return_value=([], {"X-Total-Count": "0"}))
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_licenses_concise")
            assert tool is not None
            await tool.fn()
            
            call_args = mock_client.get_with_headers.call_args
            assert "/license/concise" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_list_licenses_concise_with_pagination(self, register_tools):
        """Test list_licenses_concise with pagination."""
        mock_licenses = []
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_licenses, {"X-Total-Count": "1000"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_licenses_concise")
            assert tool is not None
            result = await tool.fn(page=3, page_size=25)
            
            assert result["page"] == 3
            assert result["page_size"] == 25
            assert result["total"] == 1000

    @pytest.mark.asyncio
    async def test_list_licenses_concise_error(self, register_tools):
        """Test list_licenses_concise error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Service unavailable")
            error.details = {"status": 503}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_licenses_concise")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result
            assert "details" in result

    @pytest.mark.asyncio
    async def test_list_licenses_concise_empty_result(self, register_tools):
        """Test list_licenses_concise with empty results."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=([], {"X-Total-Count": "0"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_licenses_concise")
            assert tool is not None
            result = await tool.fn()
            
            assert result["licenses"] == []
            assert result["total"] == 0
