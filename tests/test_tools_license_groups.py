"""Tests for license group management tools."""

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


class TestListLicenseGroupsTool:
    """Tests for list_license_groups tool."""

    @pytest.mark.asyncio
    async def test_list_license_groups_success(self, register_tools):
        """Test listing all license groups."""
        mock_groups = [
            {"uuid": "group-1", "name": "Permissive"},
            {"uuid": "group-2", "name": "Restrictive"},
        ]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_groups, {"X-Total-Count": "2"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_license_groups")
            assert tool is not None
            result = await tool.fn()
            
            assert "licenseGroups" in result
            assert result["licenseGroups"] == mock_groups
            assert result["total"] == 2
            assert result["page"] == 1

    @pytest.mark.asyncio
    async def test_list_license_groups_with_pagination(self, register_tools):
        """Test list_license_groups with pagination."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=([], {"X-Total-Count": "100"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_license_groups")
            assert tool is not None
            result = await tool.fn(page=2, page_size=25)
            
            assert result["page"] == 2
            assert result["page_size"] == 25
            call_args = mock_client.get_with_headers.call_args
            assert call_args[1]["params"]["pageNumber"] == 2
            assert call_args[1]["params"]["pageSize"] == 25

    @pytest.mark.asyncio
    async def test_list_license_groups_error(self, register_tools):
        """Test list_license_groups error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Access denied")
            error.details = {"status": 403}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_license_groups")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result
            assert "details" in result


class TestGetLicenseGroupTool:
    """Tests for get_license_group tool."""

    @pytest.mark.asyncio
    async def test_get_license_group_success(self, register_tools):
        """Test getting a specific license group."""
        mock_group = {
            "uuid": "group-1",
            "name": "Permissive",
            "riskWeight": 1,
            "licenses": [{"spdxId": "MIT"}, {"spdxId": "Apache-2.0"}],
        }
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_group)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_license_group")
            assert tool is not None
            result = await tool.fn(uuid="group-1")
            
            assert "licenseGroup" in result
            assert result["licenseGroup"] == mock_group
            mock_client.get.assert_called_once_with("/licenseGroup/group-1")

    @pytest.mark.asyncio
    async def test_get_license_group_error(self, register_tools):
        """Test get_license_group error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Group not found")
            error.details = {"status": 404}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_license_group")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid")

            assert "error" in result
            assert "details" in result


class TestCreateLicenseGroupTool:
    """Tests for create_license_group tool."""

    @pytest.mark.asyncio
    async def test_create_license_group_success(self, register_tools):
        """Test creating a license group."""
        mock_group = {"uuid": "new-group", "name": "Custom Group", "riskWeight": 5}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_group)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_license_group")
            assert tool is not None
            result = await tool.fn(name="Custom Group")
            
            assert "licenseGroup" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_create_license_group_with_risk_weight(self, register_tools):
        """Test create_license_group with custom risk weight."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={"uuid": "new-group"})
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_license_group")
            assert tool is not None
            await tool.fn(name="High Risk Group", risk_weight=9)
            
            call_args = mock_client.put.call_args
            assert call_args[1]["data"]["riskWeight"] == 9
            assert call_args[1]["data"]["name"] == "High Risk Group"

    @pytest.mark.asyncio
    async def test_create_license_group_error(self, register_tools):
        """Test create_license_group error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Duplicate name")
            error.details = {"status": 400}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_license_group")
            assert tool is not None
            result = await tool.fn(name="Duplicate")

            assert "error" in result
            assert "details" in result


class TestUpdateLicenseGroupTool:
    """Tests for update_license_group tool."""

    @pytest.mark.asyncio
    async def test_update_license_group_success(self, register_tools):
        """Test updating a license group."""
        existing = {"uuid": "group-1", "name": "Old Name", "riskWeight": 5}
        updated = {"uuid": "group-1", "name": "New Name", "riskWeight": 7}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing)
            mock_client.post = AsyncMock(return_value=updated)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "update_license_group")
            assert tool is not None
            result = await tool.fn(uuid="group-1", name="New Name", risk_weight=7)
            
            assert "licenseGroup" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_update_license_group_partial(self, register_tools):
        """Test update_license_group with partial updates."""
        existing = {"uuid": "group-1", "name": "Old Name", "riskWeight": 5}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing)
            mock_client.post = AsyncMock(return_value=existing)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "update_license_group")
            assert tool is not None
            await tool.fn(uuid="group-1", name="New Name")
            
            # Verify only name was updated in the request
            call_args = mock_client.post.call_args
            assert call_args[1]["data"]["name"] == "New Name"

    @pytest.mark.asyncio
    async def test_update_license_group_error(self, register_tools):
        """Test update_license_group error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Group not found")
            error.details = {"status": 404}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_license_group")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid", name="New Name")

            assert "error" in result


class TestDeleteLicenseGroupTool:
    """Tests for delete_license_group tool."""

    @pytest.mark.asyncio
    async def test_delete_license_group_success(self, register_tools):
        """Test deleting a license group."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "delete_license_group")
            assert tool is not None
            result = await tool.fn(uuid="group-1")
            
            assert "message" in result
            assert "deleted" in result["message"].lower()
            mock_client.delete.assert_called_once_with("/licenseGroup/group-1")

    @pytest.mark.asyncio
    async def test_delete_license_group_error(self, register_tools):
        """Test delete_license_group error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Group not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_license_group")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid")

            assert "error" in result


class TestAddLicenseToGroupTool:
    """Tests for add_license_to_group tool."""

    @pytest.mark.asyncio
    async def test_add_license_to_group_success(self, register_tools):
        """Test adding a license to a group."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "add_license_to_group")
            assert tool is not None
            result = await tool.fn(group_uuid="group-1", license_uuid="license-1")
            
            assert "message" in result
            assert "successfully" in result["message"].lower()
            mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_license_to_group_error(self, register_tools):
        """Test add_license_to_group error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("License already in group")
            error.details = {"status": 400}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_license_to_group")
            assert tool is not None
            result = await tool.fn(group_uuid="group-1", license_uuid="license-1")

            assert "error" in result


class TestRemoveLicenseFromGroupTool:
    """Tests for remove_license_from_group tool."""

    @pytest.mark.asyncio
    async def test_remove_license_from_group_success(self, register_tools):
        """Test removing a license from a group."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "remove_license_from_group")
            assert tool is not None
            result = await tool.fn(group_uuid="group-1", license_uuid="license-1")
            
            assert "message" in result
            assert "successfully" in result["message"].lower()
            mock_client.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_license_from_group_error(self, register_tools):
        """Test remove_license_from_group error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("License not in group")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_license_from_group")
            assert tool is not None
            result = await tool.fn(group_uuid="group-1", license_uuid="license-1")

            assert "error" in result
