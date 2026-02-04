"""Tests for calculator tools."""

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


class TestCalculateCVSSTool:
    """Tests for calculate_cvss tool."""

    @pytest.mark.asyncio
    async def test_calculate_cvss_success(self, register_tools):
        """Test calculating CVSS scores."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        mock_data = {
            "baseScore": 9.8,
            "impactSubScore": 5.9,
            "exploitabilitySubScore": 3.9,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "calculate_cvss")
            assert tool is not None
            result = await tool.fn(vector=vector)

            assert "cvss" in result
            assert result["cvss"]["baseScore"] == 9.8
            mock_client.get.assert_called_once_with("/calculator/cvss", params={"vector": vector})

    @pytest.mark.asyncio
    async def test_calculate_cvss_error(self, register_tools):
        """Test calculate_cvss error handling."""
        vector = "INVALID"

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Invalid vector"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "calculate_cvss")
            assert tool is not None
            result = await tool.fn(vector=vector)

            assert "error" in result
            assert "Invalid vector" in result["error"]


class TestCalculateOwaspRRTool:
    """Tests for calculate_owasp_rr tool."""

    @pytest.mark.asyncio
    async def test_calculate_owasp_rr_success(self, register_tools):
        """Test calculating OWASP Risk Rating scores."""
        vector = "SL:5/M:5/O:5/S:5/ED:5/EE:5/A:5/ID:5/LC:5/LI:5/LAV:5/LAC:5/FD:5/RD:5/NC:5/PV:5"
        mock_data = {
            "likelihoodScore": 9.0,
            "technicalImpactScore": 10.0,
            "businessImpactScore": 10.0,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "calculate_owasp_rr")
            assert tool is not None
            result = await tool.fn(vector=vector)

            assert "owaspRR" in result
            assert result["owaspRR"]["likelihoodScore"] == 9.0
            mock_client.get.assert_called_once_with("/calculator/owasp", params={"vector": vector})

    @pytest.mark.asyncio
    async def test_calculate_owasp_rr_error(self, register_tools):
        """Test calculate_owasp_rr error handling."""
        vector = "INVALID"

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Invalid vector"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "calculate_owasp_rr")
            assert tool is not None
            result = await tool.fn(vector=vector)

            assert "error" in result
            assert "Invalid vector" in result["error"]
