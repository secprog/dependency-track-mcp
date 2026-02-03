"""Tests for service component tools."""

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


class TestListProjectServicesTool:
    """Tests for list_project_services tool."""

    @pytest.mark.asyncio
    async def test_list_project_services_success(self, register_tools):
        """Test listing all services in a project."""
        mock_services = [
            {"uuid": "svc-1", "name": "API Gateway"},
            {"uuid": "svc-2", "name": "Database"},
        ]
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_services, {"X-Total-Count": "2"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_project_services")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-uuid")
            
            assert "services" in result
            assert result["services"] == mock_services
            assert result["total"] == 2
            assert result["page"] == 1
            call_args = mock_client.get_with_headers.call_args
            assert "/service/project/proj-uuid" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_list_project_services_with_pagination(self, register_tools):
        """Test list_project_services with pagination."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=([], {"X-Total-Count": "50"})
            )
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "list_project_services")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-uuid", page=2, page_size=25)
            
            assert result["page"] == 2
            assert result["page_size"] == 25
            call_args = mock_client.get_with_headers.call_args
            assert call_args[1]["params"]["pageNumber"] == 2

    @pytest.mark.asyncio
    async def test_list_project_services_error(self, register_tools):
        """Test list_project_services error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Project not found")
            error.details = {"status": 404}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_project_services")
            assert tool is not None
            result = await tool.fn(project_uuid="bad-uuid")

            assert "error" in result
            assert "details" in result


class TestGetServiceTool:
    """Tests for get_service tool."""

    @pytest.mark.asyncio
    async def test_get_service_success(self, register_tools):
        """Test getting a specific service."""
        mock_service = {
            "uuid": "svc-1",
            "name": "API Gateway",
            "version": "1.0.0",
            "endpoints": ["https://api.example.com"],
        }
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_service)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "get_service")
            assert tool is not None
            result = await tool.fn(uuid="svc-1")
            
            assert "service" in result
            assert result["service"] == mock_service
            mock_client.get.assert_called_once_with("/service/svc-1")

    @pytest.mark.asyncio
    async def test_get_service_error(self, register_tools):
        """Test get_service error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Service not found")
            error.details = {"status": 404}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_service")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid")

            assert "error" in result
            assert "details" in result


class TestCreateServiceTool:
    """Tests for create_service tool."""

    @pytest.mark.asyncio
    async def test_create_service_success(self, register_tools):
        """Test creating a service in a project."""
        mock_service = {"uuid": "svc-new", "name": "New Service"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_service)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_service")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-uuid", name="New Service")
            
            assert "service" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()
            call_args = mock_client.put.call_args
            assert "/service/project/proj-uuid" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_create_service_with_all_options(self, register_tools):
        """Test create_service with all optional parameters."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={"uuid": "svc-new"})
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_service")
            assert tool is not None
            await tool.fn(
                project_uuid="proj-uuid",
                name="Database",
                version="5.7",
                group="backend",
                description="MySQL Database",
                endpoints=["db.example.com:3306"],
                authenticated=True,
                x_trust_boundary=True,
                provider_name="MySQL",
                provider_url="https://mysql.com",
            )
            
            call_args = mock_client.put.call_args
            payload = call_args[1]["data"]
            assert payload["name"] == "Database"
            assert payload["version"] == "5.7"
            assert payload["group"] == "backend"
            assert payload["endpoints"] == ["db.example.com:3306"]
            assert payload["authenticated"] is True
            assert payload["xTrustBoundary"] is True
            assert payload["provider"]["name"] == "MySQL"

    @pytest.mark.asyncio
    async def test_create_service_minimal(self, register_tools):
        """Test create_service with minimal parameters."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={"uuid": "svc-new"})
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "create_service")
            assert tool is not None
            await tool.fn(project_uuid="proj-uuid", name="Simple Service")
            
            call_args = mock_client.put.call_args
            payload = call_args[1]["data"]
            assert payload["name"] == "Simple Service"
            assert "project" in payload
            assert len(payload) >= 2

    @pytest.mark.asyncio
    async def test_create_service_error(self, register_tools):
        """Test create_service error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Project not found")
            error.details = {"status": 404}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_service")
            assert tool is not None
            result = await tool.fn(project_uuid="bad-uuid", name="Service")

            assert "error" in result


class TestUpdateServiceTool:
    """Tests for update_service tool."""

    @pytest.mark.asyncio
    async def test_update_service_success(self, register_tools):
        """Test updating a service."""
        existing = {"uuid": "svc-1", "name": "Old Name", "version": "1.0"}
        updated = {"uuid": "svc-1", "name": "New Name", "version": "2.0"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing)
            mock_client.post = AsyncMock(return_value=updated)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "update_service")
            assert tool is not None
            result = await tool.fn(uuid="svc-1", name="New Name", version="2.0")
            
            assert "service" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_update_service_partial(self, register_tools):
        """Test update_service with partial updates."""
        existing = {"uuid": "svc-1", "name": "Old Name", "version": "1.0"}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing)
            mock_client.post = AsyncMock(return_value=existing)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "update_service")
            assert tool is not None
            await tool.fn(uuid="svc-1", name="New Name")
            
            call_args = mock_client.get.call_args
            assert "svc-1" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_update_service_with_endpoints(self, register_tools):
        """Test update_service with endpoints."""
        existing = {"uuid": "svc-1", "endpoints": ["old-url"]}
        
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing)
            mock_client.post = AsyncMock(return_value=existing)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "update_service")
            assert tool is not None
            await tool.fn(uuid="svc-1", endpoints=["new-url1", "new-url2"])
            
            call_args = mock_client.post.call_args
            assert call_args[1]["data"]["endpoints"] == ["new-url1", "new-url2"]

    @pytest.mark.asyncio
    async def test_update_service_error(self, register_tools):
        """Test update_service error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Service not found")
            error.details = {"status": 404}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_service")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid", name="New Name")

            assert "error" in result


class TestDeleteServiceTool:
    """Tests for delete_service tool."""

    @pytest.mark.asyncio
    async def test_delete_service_success(self, register_tools):
        """Test deleting a service."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "delete_service")
            assert tool is not None
            result = await tool.fn(uuid="svc-1")
            
            assert "message" in result
            assert "deleted" in result["message"].lower()
            mock_client.delete.assert_called_once_with("/service/svc-1")

    @pytest.mark.asyncio
    async def test_delete_service_error(self, register_tools):
        """Test delete_service error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Service not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_service")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid")

            assert "error" in result
