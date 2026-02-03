"""Tests for vulnerability tools."""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.tools.vulnerabilities import register_vulnerability_tools
from tests.utils import find_tool


@pytest.fixture
def register_tools(mcp):
    """Register vulnerability tools."""
    register_vulnerability_tools(mcp)
    return mcp


class TestGetVulnerabilityTool:
    """Tests for get_vulnerability tool."""

    @pytest.mark.asyncio
    async def test_get_vulnerability_success(self, register_tools):
        """Test getting vulnerability successfully."""
        mock_data = {
            "uuid": "vuln-1",
            "vulnId": "CVE-2021-44228",
            "severity": "CRITICAL",
        }
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_vulnerability")
            assert tool is not None
            result = await tool.fn(source="NVD", vuln_id="CVE-2021-44228")
            
            assert result["vulnerability"]["vulnId"] == "CVE-2021-44228"

    @pytest.mark.asyncio
    async def test_get_vulnerability_error(self, register_tools):
        """Test get_vulnerability error handling."""
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_vulnerability")
            assert tool is not None
            result = await tool.fn(source="NVD", vuln_id="CVE-2021-44228")

            assert "error" in result


class TestGetAffectedProjectsTool:
    """Tests for get_affected_projects tool."""

    @pytest.mark.asyncio
    async def test_get_affected_projects_success(self, register_tools):
        """Test getting affected projects."""
        mock_data = [{"uuid": "proj-1", "name": "Project 1"}]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_affected_projects")
            assert tool is not None
            result = await tool.fn(source="NVD", vuln_id="CVE-2021-44228")
            
            assert "projects" in result
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_get_affected_projects_error(self, register_tools):
        """Test get_affected_projects error handling."""
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_affected_projects")
            assert tool is not None
            result = await tool.fn(source="NVD", vuln_id="CVE-2021-44228")

            assert "error" in result


class TestListComponentVulnerabilitiesTool:
    """Tests for list_component_vulnerabilities tool."""

    @pytest.mark.asyncio
    async def test_list_vulnerabilities_success(self, register_tools):
        """Test listing component vulnerabilities."""
        mock_data = [
            {"uuid": "vuln-1", "vulnId": "CVE-2021-44228", "severity": "CRITICAL"}
        ]
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_component_vulnerabilities")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")
            
            assert "vulnerabilities" in result
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_list_vulnerabilities_error(self, register_tools):
        """Test list_component_vulnerabilities error handling."""
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_component_vulnerabilities")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")

            assert "error" in result
