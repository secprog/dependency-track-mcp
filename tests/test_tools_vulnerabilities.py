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


class TestListVulnerabilitiesTool:
    """Tests for list_vulnerabilities tool."""

    @pytest.mark.asyncio
    async def test_list_vulnerabilities_success(self, register_tools):
        """Test listing all vulnerabilities."""
        mock_data = [{"uuid": "vuln-1", "vulnId": "CVE-2021-44228"}]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_vulnerabilities")
            assert tool is not None
            result = await tool.fn()
            
            assert "vulnerabilities" in result
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_list_vulnerabilities_error(self, register_tools):
        """Test list_vulnerabilities error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Error"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_vulnerabilities")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestGetVulnerabilityByUuidTool:
    """Tests for get_vulnerability_by_uuid tool."""

    @pytest.mark.asyncio
    async def test_get_vulnerability_by_uuid_success(self, register_tools):
        """Test getting vulnerability by UUID."""
        mock_data = {"uuid": "vuln-1", "vulnId": "CVE-2021-44228"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_vulnerability_by_uuid")
            assert tool is not None
            result = await tool.fn(uuid="vuln-1")
            
            assert "vulnerability" in result
            assert result["vulnerability"]["uuid"] == "vuln-1"

    @pytest.mark.asyncio
    async def test_get_vulnerability_by_uuid_error(self, register_tools):
        """Test get_vulnerability_by_uuid error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Not found"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_vulnerability_by_uuid")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid")

            assert "error" in result


class TestListProjectVulnerabilitiesTool:
    """Tests for list_project_vulnerabilities tool."""

    @pytest.mark.asyncio
    async def test_list_project_vulnerabilities_success(self, register_tools):
        """Test listing project vulnerabilities."""
        mock_data = [{"uuid": "vuln-1", "vulnId": "CVE-2021-44228"}]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_project_vulnerabilities")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")
            
            assert "vulnerabilities" in result
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_list_project_vulnerabilities_error(self, register_tools):
        """Test list_project_vulnerabilities error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Error"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_project_vulnerabilities")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")

            assert "error" in result


class TestCreateVulnerabilityTool:
    """Tests for create_vulnerability tool."""

    @pytest.mark.asyncio
    async def test_create_vulnerability_success(self, register_tools):
        """Test creating a vulnerability."""
        mock_data = {"uuid": "vuln-1", "vulnId": "INTERNAL-2024-001"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_vulnerability")
            assert tool is not None
            result = await tool.fn(vuln_id="INTERNAL-2024-001", title="Test Vulnerability")
            
            assert "vulnerability" in result

    @pytest.mark.asyncio
    async def test_create_vulnerability_error(self, register_tools):
        """Test create_vulnerability error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(side_effect=DependencyTrackError("Creation failed"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_vulnerability")
            assert tool is not None
            result = await tool.fn(vuln_id="INTERNAL-2024-001", title="Test")

            assert "error" in result


class TestUpdateVulnerabilityTool:
    """Tests for update_vulnerability tool."""

    @pytest.mark.asyncio
    async def test_update_vulnerability_success(self, register_tools):
        """Test updating a vulnerability."""
        mock_data = {"uuid": "vuln-1", "title": "Updated Title"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "update_vulnerability")
            assert tool is not None
            result = await tool.fn(uuid="vuln-1", title="Updated Title")
            
            assert "vulnerability" in result

    @pytest.mark.asyncio
    async def test_update_vulnerability_error(self, register_tools):
        """Test update_vulnerability error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=DependencyTrackError("Update failed"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_vulnerability")
            assert tool is not None
            result = await tool.fn(uuid="vuln-1", title="Updated")

            assert "error" in result


class TestDeleteVulnerabilityTool:
    """Tests for delete_vulnerability tool."""

    @pytest.mark.asyncio
    async def test_delete_vulnerability_success(self, register_tools):
        """Test deleting a vulnerability."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "delete_vulnerability")
            assert tool is not None
            result = await tool.fn(uuid="vuln-1")
            
            assert "message" in result

    @pytest.mark.asyncio
    async def test_delete_vulnerability_error(self, register_tools):
        """Test delete_vulnerability error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(side_effect=DependencyTrackError("Delete failed"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_vulnerability")
            assert tool is not None
            result = await tool.fn(uuid="vuln-1")

            assert "error" in result


class TestGenerateVulnIdTool:
    """Tests for generate_vuln_id tool."""

    @pytest.mark.asyncio
    async def test_generate_vuln_id_success(self, register_tools):
        """Test generating a vulnerability ID."""
        mock_data = "INTERNAL-2024-001"
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "generate_vuln_id")
            assert tool is not None
            result = await tool.fn()
            
            assert "vuln_id" in result

    @pytest.mark.asyncio
    async def test_generate_vuln_id_error(self, register_tools):
        """Test generate_vuln_id error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Generation failed"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "generate_vuln_id")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestAssignVulnerabilityToComponentTool:
    """Tests for assign_vulnerability_to_component tool."""

    @pytest.mark.asyncio
    async def test_assign_vulnerability_success(self, register_tools):
        """Test assigning vulnerability to component."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "assign_vulnerability_to_component")
            assert tool is not None
            result = await tool.fn(
                component_uuid="comp-1",
                vuln_id="CVE-2021-44228",
                source="NVD"
            )
            
            assert "message" in result

    @pytest.mark.asyncio
    async def test_assign_vulnerability_error(self, register_tools):
        """Test assign_vulnerability_to_component error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=DependencyTrackError("Assignment failed"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "assign_vulnerability_to_component")
            assert tool is not None
            result = await tool.fn(
                component_uuid="comp-1",
                vuln_id="CVE-2021-44228",
                source="NVD"
            )

            assert "error" in result


class TestUnassignVulnerabilityFromComponentTool:
    """Tests for unassign_vulnerability_from_component tool."""

    @pytest.mark.asyncio
    async def test_unassign_vulnerability_success(self, register_tools):
        """Test unassigning vulnerability from component."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "unassign_vulnerability_from_component")
            assert tool is not None
            result = await tool.fn(
                component_uuid="comp-1",
                vuln_id="CVE-2021-44228",
                source="NVD"
            )
            
            assert "message" in result

    @pytest.mark.asyncio
    async def test_unassign_vulnerability_error(self, register_tools):
        """Test unassign_vulnerability_from_component error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(side_effect=DependencyTrackError("Unassignment failed"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "unassign_vulnerability_from_component")
            assert tool is not None
            result = await tool.fn(
                component_uuid="comp-1",
                vuln_id="CVE-2021-44228",
                source="NVD"
            )

            assert "error" in result


class TestAssignVulnerabilityByUuidTool:
    """Tests for assign_vulnerability_by_uuid tool."""

    @pytest.mark.asyncio
    async def test_assign_by_uuid_success(self, register_tools):
        """Test assigning vulnerability by UUID."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "assign_vulnerability_by_uuid")
            assert tool is not None
            result = await tool.fn(
                component_uuid="comp-1",
                vulnerability_uuid="vuln-1"
            )
            
            assert "message" in result

    @pytest.mark.asyncio
    async def test_assign_by_uuid_error(self, register_tools):
        """Test assign_vulnerability_by_uuid error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=DependencyTrackError("Assignment failed"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "assign_vulnerability_by_uuid")
            assert tool is not None
            result = await tool.fn(
                component_uuid="comp-1",
                vulnerability_uuid="vuln-1"
            )

            assert "error" in result


class TestUnassignVulnerabilityByUuidTool:
    """Tests for unassign_vulnerability_by_uuid tool."""

    @pytest.mark.asyncio
    async def test_unassign_by_uuid_success(self, register_tools):
        """Test unassigning vulnerability by UUID."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "unassign_vulnerability_by_uuid")
            assert tool is not None
            result = await tool.fn(
                component_uuid="comp-1",
                vulnerability_uuid="vuln-1"
            )
            
            assert "message" in result

    @pytest.mark.asyncio
    async def test_unassign_by_uuid_error(self, register_tools):
        """Test unassign_vulnerability_by_uuid error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(side_effect=DependencyTrackError("Unassignment failed"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "unassign_vulnerability_by_uuid")
            assert tool is not None
            result = await tool.fn(
                component_uuid="comp-1",
                vulnerability_uuid="vuln-1"
            )

            assert "error" in result
