"""Tests for finding and analysis tools."""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.tools.findings import register_finding_tools
from tests.utils import find_tool


@pytest.fixture
def register_tools(mcp):
    """Register finding tools."""
    register_finding_tools(mcp)
    return mcp


class TestListProjectFindingsTool:
    """Tests for list_project_findings tool."""

    @pytest.mark.asyncio
    async def test_list_findings_success(self, register_tools):
        """Test listing project findings successfully."""
        mock_data = [
            {
                "component": {"uuid": "comp-1", "name": "lodash"},
                "vulnerability": {"uuid": "vuln-1", "vulnId": "CVE-2021-44228"},
            }
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_project_findings")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")

            assert "findings" in result
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_list_findings_error(self, register_tools):
        """Test listing findings with error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_project_findings")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")

            assert "error" in result


class TestGetFindingAnalysisTool:
    """Tests for get_finding_analysis tool."""

    @pytest.mark.asyncio
    async def test_get_analysis_success(self, register_tools):
        """Test getting finding analysis."""
        mock_data = {"state": "RESOLVED", "justification": "CODE_NOT_PRESENT"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_finding_analysis")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1", vulnerability_uuid="vuln-1")

            assert "analysis" in result

    @pytest.mark.asyncio
    async def test_get_analysis_error(self, register_tools):
        """Test get_finding_analysis error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_finding_analysis")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1", vulnerability_uuid="vuln-1")

            assert "error" in result


class TestUpdateFindingAnalysisTool:
    """Tests for update_finding_analysis tool."""

    @pytest.mark.asyncio
    async def test_update_analysis_success(self, register_tools):
        """Test updating finding analysis."""
        mock_data = {"state": "RESOLVED", "justification": "CODE_NOT_PRESENT"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_finding_analysis")
            assert tool is not None
            result = await tool.fn(
                project_uuid="proj-1",
                component_uuid="comp-1",
                vulnerability_uuid="vuln-1",
                state="RESOLVED",
            )

            assert result["message"] == "Analysis decision recorded successfully"

    @pytest.mark.asyncio
    async def test_update_analysis_error(self, register_tools):
        """Test update_finding_analysis error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_finding_analysis")
            assert tool is not None
            result = await tool.fn(
                project_uuid="proj-1",
                component_uuid="comp-1",
                vulnerability_uuid="vuln-1",
                state="RESOLVED",
            )

            assert "error" in result

    @pytest.mark.asyncio
    async def test_update_analysis_invalid_state(self, register_tools):
        """Test updating analysis with invalid state."""
        tool = find_tool(register_tools, "update_finding_analysis")
        assert tool is not None
        result = await tool.fn(
            project_uuid="proj-1",
            component_uuid="comp-1",
            vulnerability_uuid="vuln-1",
            state="INVALID_STATE",
        )

        assert "error" in result

    @pytest.mark.asyncio
    async def test_update_analysis_invalid_justification(self, register_tools):
        """Test update_finding_analysis with invalid justification."""
        tool = find_tool(register_tools, "update_finding_analysis")
        assert tool is not None
        result = await tool.fn(
            project_uuid="proj-1",
            component_uuid="comp-1",
            vulnerability_uuid="vuln-1",
            justification="BAD_JUSTIFICATION",
        )

        assert "error" in result

    @pytest.mark.asyncio
    async def test_update_analysis_invalid_response(self, register_tools):
        """Test update_finding_analysis with invalid response."""
        tool = find_tool(register_tools, "update_finding_analysis")
        assert tool is not None
        result = await tool.fn(
            project_uuid="proj-1",
            component_uuid="comp-1",
            vulnerability_uuid="vuln-1",
            response="BAD_RESPONSE",
        )

        assert "error" in result

    @pytest.mark.asyncio
    async def test_update_analysis_with_details(self, register_tools):
        """Test update_finding_analysis with optional fields."""
        mock_data = {"state": "RESOLVED"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_finding_analysis")
            assert tool is not None
            result = await tool.fn(
                project_uuid="proj-1",
                component_uuid="comp-1",
                vulnerability_uuid="vuln-1",
                state="RESOLVED",
                justification="CODE_NOT_PRESENT",
                response="UPDATE",
                details="Details",
                comment="Comment",
                suppressed=True,
            )

            assert "analysis" in result


class TestListFindingsGroupedTool:
    """Tests for list_findings_grouped tool."""

    @pytest.mark.asyncio
    async def test_list_findings_grouped_success(self, register_tools):
        """Test listing findings grouped by vulnerability."""
        mock_data = [{"vulnId": "CVE-2021-44228", "count": 5}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_findings_grouped")
            assert tool is not None
            result = await tool.fn()

            assert "findings" in result

    @pytest.mark.asyncio
    async def test_list_findings_grouped_error(self, register_tools):
        """Test list_findings_grouped with error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_findings_grouped")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestListAllFindingsTool:
    """Tests for list_all_findings tool."""

    @pytest.mark.asyncio
    async def test_list_all_findings_success(self, register_tools):
        """Test listing all findings."""
        mock_data = [{"component": {"name": "lodash"}}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_all_findings")
            assert tool is not None
            result = await tool.fn()

            assert "findings" in result
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_list_all_findings_error(self, register_tools):
        """Test list_all_findings with error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_all_findings")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestAnalyzeProjectTool:
    """Tests for analyze_project tool."""

    @pytest.mark.asyncio
    async def test_analyze_project_success(self, register_tools):
        """Test triggering project analysis."""
        mock_data = {"token": "abc123"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "analyze_project")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")

            assert "token" in result
            assert "message" in result

    @pytest.mark.asyncio
    async def test_analyze_project_error(self, register_tools):
        """Test analyze_project with error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "analyze_project")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")

            assert "error" in result


class TestExportProjectFindingsTool:
    """Tests for export_project_findings tool."""

    @pytest.mark.asyncio
    async def test_export_project_findings_success(self, register_tools):
        """Test exporting project findings."""
        mock_data = {"version": "1.0", "findings": []}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "export_project_findings")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")

            assert "findings" in result

    @pytest.mark.asyncio
    async def test_export_project_findings_error(self, register_tools):
        """Test export_project_findings with error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "export_project_findings")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")

            assert "error" in result
