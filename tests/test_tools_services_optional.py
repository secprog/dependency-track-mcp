"""
Tests for services tool optional field coverage.
Targets missing lines in update_service optional field handling.
"""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.tools.services import register_service_tools
from tests.utils import find_tool


@pytest.fixture
def register_tools(mcp):
    """Register service tools."""
    register_service_tools(mcp)
    return mcp


class TestServicesOptionalFields:
    """Tests for services optional field handling."""

    @pytest.mark.asyncio
    async def test_update_service_with_endpoints(self, register_tools):
        """Test updating service with endpoints field."""
        existing_data = {
            "uuid": "svc-1",
            "name": "Test Service",
            "endpoints": ["http://old.example.com"],
        }
        updated_data = {
            "uuid": "svc-1",
            "name": "Test Service",
            "endpoints": ["http://new.example.com"],
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing_data)
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_service")
            assert tool is not None
            result = await tool.fn(uuid="svc-1", endpoints=["http://new.example.com"])

            assert "service" in result
            # Verify that endpoints was included in the post call
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["endpoints"] == ["http://new.example.com"]

    @pytest.mark.asyncio
    async def test_update_service_with_authenticated(self, register_tools):
        """Test updating service with authenticated field."""
        existing_data = {
            "uuid": "svc-1",
            "name": "Test Service",
            "authenticated": False,
        }
        updated_data = {
            "uuid": "svc-1",
            "name": "Test Service",
            "authenticated": True,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing_data)
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_service")
            assert tool is not None
            result = await tool.fn(uuid="svc-1", authenticated=True)

            assert "service" in result
            # Verify that authenticated was included in the post call
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["authenticated"] is True

    @pytest.mark.asyncio
    async def test_update_service_with_trust_boundary(self, register_tools):
        """Test updating service with x_trust_boundary field."""
        existing_data = {
            "uuid": "svc-1",
            "name": "Test Service",
            "xTrustBoundary": False,
        }
        updated_data = {
            "uuid": "svc-1",
            "name": "Test Service",
            "xTrustBoundary": True,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing_data)
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_service")
            assert tool is not None
            result = await tool.fn(uuid="svc-1", x_trust_boundary=True)

            assert "service" in result
            # Verify that xTrustBoundary was included in the post call
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["xTrustBoundary"] is True

    @pytest.mark.asyncio
    async def test_update_service_all_optional_fields(self, register_tools):
        """Test updating service with all optional fields."""
        existing_data = {
            "uuid": "svc-1",
            "name": "Old Name",
            "version": "1.0.0",
            "group": "old-group",
            "description": "old description",
            "endpoints": ["http://old.example.com"],
            "authenticated": False,
            "xTrustBoundary": False,
        }
        updated_data = {
            "uuid": "svc-1",
            "name": "New Name",
            "version": "2.0.0",
            "group": "new-group",
            "description": "new description",
            "endpoints": ["http://new.example.com"],
            "authenticated": True,
            "xTrustBoundary": True,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing_data)
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_service")
            assert tool is not None
            result = await tool.fn(
                uuid="svc-1",
                name="New Name",
                version="2.0.0",
                group="new-group",
                description="new description",
                endpoints=["http://new.example.com"],
                authenticated=True,
                x_trust_boundary=True,
            )

            assert "service" in result
            # Verify that all fields were included
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert posted_data["name"] == "New Name"
            assert posted_data["version"] == "2.0.0"
            assert posted_data["group"] == "new-group"
            assert posted_data["description"] == "new description"
            assert posted_data["endpoints"] == ["http://new.example.com"]
            assert posted_data["authenticated"] is True
            assert posted_data["xTrustBoundary"] is True
