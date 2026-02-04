"""Tests for CWE tools."""

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


class TestListCWEsTool:
    """Tests for list_cwes tool."""

    @pytest.mark.asyncio
    async def test_list_cwes_success(self, register_tools):
        """Test listing CWEs."""
        mock_data = [
            {"cweId": 79, "name": "Cross-site Scripting (XSS)"},
            {"cweId": 89, "name": "SQL Injection"},
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "2"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_cwes")
            assert tool is not None
            result = await tool.fn()

            assert "cwes" in result
            assert result["total"] == 2
            assert len(result["cwes"]) == 2

    @pytest.mark.asyncio
    async def test_list_cwes_with_pagination(self, register_tools):
        """Test listing CWEs with pagination."""
        mock_data = [{"cweId": 79, "name": "XSS"}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "100"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_cwes")
            assert tool is not None
            result = await tool.fn(page=2, page_size=50)

            assert "cwes" in result
            assert result["page"] == 2
            assert result["page_size"] == 50
            assert result["total"] == 100

    @pytest.mark.asyncio
    async def test_list_cwes_error(self, register_tools):
        """Test list_cwes error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                side_effect=DependencyTrackError("Connection error")
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_cwes")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestGetCWETool:
    """Tests for get_cwe tool."""

    @pytest.mark.asyncio
    async def test_get_cwe_success(self, register_tools):
        """Test getting a specific CWE."""
        mock_data = {
            "cweId": 79,
            "name": (
                "Improper Neutralization of Input During Web Page Generation "
                "('Cross-site Scripting')"
            ),
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_cwe")
            assert tool is not None
            result = await tool.fn(cwe_id=79)

            assert "cwe" in result
            assert result["cwe"]["cweId"] == 79
            mock_client.get.assert_called_once_with("/cwe/79")

    @pytest.mark.asyncio
    async def test_get_cwe_error(self, register_tools):
        """Test get_cwe error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("CWE not found"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_cwe")
            assert tool is not None
            result = await tool.fn(cwe_id=99999)

            assert "error" in result
            assert "CWE not found" in result["error"]
