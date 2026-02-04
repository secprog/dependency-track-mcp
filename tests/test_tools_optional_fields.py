"""Additional tests for tools to improve coverage of optional parameters."""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.tools.vulnerabilities import register_vulnerability_tools
from tests.utils import find_tool


@pytest.fixture
def vulnerabilities_tools(mcp):
    """Register vulnerability tools."""
    register_vulnerability_tools(mcp)
    return mcp


class TestVulnerabilitiesOptionalFields:
    """Test vulnerabilities tool with all optional fields."""

    @pytest.mark.asyncio
    async def test_create_vulnerability_all_optional_fields(self, vulnerabilities_tools):
        """Test creating vulnerability with all optional fields."""
        mock_data = {"uuid": "vuln-1", "vulnId": "INTERNAL-2024-001"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(vulnerabilities_tools, "create_vulnerability")
            result = await tool.fn(
                vuln_id="INTERNAL-2024-001",
                title="Test Vulnerability",
                description="Test description",
                severity="HIGH",
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_ids=[79, 89],
                recommendation="Apply patch",
            )

            assert "vulnerability" in result
            # Verify that all fields were sent
            call_args = mock_client.put.call_args
            assert call_args[1]["data"]["description"] == "Test description"
            assert call_args[1]["data"]["severity"] == "HIGH"
            assert (
                call_args[1]["data"]["cvssV3Vector"]
                == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            )
            assert len(call_args[1]["data"]["cwes"]) == 2
            assert call_args[1]["data"]["recommendation"] == "Apply patch"

    @pytest.mark.asyncio
    async def test_update_vulnerability_all_optional_fields(self, vulnerabilities_tools):
        """Test updating vulnerability with all optional fields."""
        mock_data = {"uuid": "vuln-1", "title": "Updated"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value={"uuid": "vuln-1"})
            mock_client.post = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(vulnerabilities_tools, "update_vulnerability")
            result = await tool.fn(
                uuid="vuln-1",
                title="Updated Title",
                description="Updated description",
                severity="MEDIUM",
                cvss_v3_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                recommendation="Updated recommendation",
            )

            assert "vulnerability" in result
            # Verify that fields were updated
            call_args = mock_client.post.call_args
            assert call_args[1]["data"]["title"] == "Updated Title"
            assert call_args[1]["data"]["description"] == "Updated description"
            assert call_args[1]["data"]["severity"] == "MEDIUM"
            assert (
                call_args[1]["data"]["cvssV3Vector"]
                == "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            )
            assert call_args[1]["data"]["recommendation"] == "Updated recommendation"

    @pytest.mark.asyncio
    async def test_create_vulnerability_minimal_fields(self, vulnerabilities_tools):
        """Test creating vulnerability with only required fields."""
        mock_data = {"uuid": "vuln-1", "vulnId": "INTERNAL-2024-001"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(vulnerabilities_tools, "create_vulnerability")
            result = await tool.fn(vuln_id="INTERNAL-2024-001", title="Test Vulnerability")

            assert "vulnerability" in result
            # Verify that optional fields were not sent
            call_args = mock_client.put.call_args
            data = call_args[1]["data"]
            assert "description" not in data
            assert "severity" not in data
            assert "cvssV3Vector" not in data

    @pytest.mark.asyncio
    async def test_update_vulnerability_partial_fields(self, vulnerabilities_tools):
        """Test updating vulnerability with only some optional fields."""
        mock_data = {"uuid": "vuln-1", "title": "Updated"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value={"uuid": "vuln-1"})
            mock_client.post = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(vulnerabilities_tools, "update_vulnerability")
            result = await tool.fn(uuid="vuln-1", severity="CRITICAL")

            assert "vulnerability" in result
            # Verify that only severity was updated
            call_args = mock_client.post.call_args
            data = call_args[1]["data"]
            assert data["severity"] == "CRITICAL"
