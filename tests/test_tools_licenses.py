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



    class TestGetLicenseTool:
        """Tests for get_license tool."""

        @pytest.mark.asyncio
        async def test_get_license_success(self, register_tools):
            """Test getting a specific license by ID."""
            mock_license = {
                "spdxId": "MIT",
                "name": "MIT License",
                "licenseText": "Permission is hereby granted...",
            }
        
            with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_license)
                mock_get_instance.return_value = mock_client
            
                tool = find_tool(register_tools, "get_license")
                assert tool is not None
                result = await tool.fn(license_id="MIT")
            
                assert "license" in result
                assert result["license"] == mock_license
                mock_client.get.assert_called_once_with("/license/MIT")

        @pytest.mark.asyncio
        async def test_get_license_not_found(self, register_tools):
            """Test getting a license that doesn't exist."""
            with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
                mock_client = AsyncMock()
                error = DependencyTrackError("License not found")
                error.details = {"status": 404}
                mock_client.get = AsyncMock(side_effect=error)
                mock_get_instance.return_value = mock_client

                tool = find_tool(register_tools, "get_license")
                assert tool is not None
                result = await tool.fn(license_id="UNKNOWN")

                assert "error" in result
                assert "details" in result
                mock_client.get.assert_called_once_with("/license/UNKNOWN")

        @pytest.mark.asyncio
        async def test_get_license_error(self, register_tools):
            """Test get_license error handling."""
            with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
                mock_client = AsyncMock()
                error = DependencyTrackError("Service error")
                error.details = {"status": 500, "message": "Internal error"}
                mock_client.get = AsyncMock(side_effect=error)
                mock_get_instance.return_value = mock_client

                tool = find_tool(register_tools, "get_license")
                assert tool is not None
                result = await tool.fn(license_id="MIT")

                assert "error" in result
                assert result["error"] == "Service error"


    class TestCreateLicenseTool:
        """Tests for create_license tool."""

        @pytest.mark.asyncio
        async def test_create_license_minimal(self, register_tools):
            """Test creating a license with minimal parameters."""
            mock_license = {
                "uuid": "123e4567-e89b-12d3-a456-426614174000",
                "name": "Custom License",
            }
        
            with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
                mock_client = AsyncMock()
                mock_client.put = AsyncMock(return_value=mock_license)
                mock_get_instance.return_value = mock_client
            
                tool = find_tool(register_tools, "create_license")
                assert tool is not None
                result = await tool.fn(name="Custom License")
            
                assert "license" in result
                assert "message" in result
                assert result["license"] == mock_license
            
                call_args = mock_client.put.call_args
                payload = call_args[1]["data"]
                assert payload["name"] == "Custom License"
                assert payload["isOsiApproved"] is False

        @pytest.mark.asyncio
        async def test_create_license_with_all_options(self, register_tools):
            """Test creating a license with all options."""
            mock_license = {
                "uuid": "123e4567-e89b-12d3-a456-426614174000",
                "name": "Custom License",
                "licenseId": "CUSTOM-1.0",
            }
        
            with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
                mock_client = AsyncMock()
                mock_client.put = AsyncMock(return_value=mock_license)
                mock_get_instance.return_value = mock_client
            
                tool = find_tool(register_tools, "create_license")
                assert tool is not None
                result = await tool.fn(
                    name="Custom License",
                    license_id="CUSTOM-1.0",
                    license_text="Full license text...",
                    header="Header...",
                    template="Template...",
                    comment="This is custom",
                    see_also=["https://example.com/license"],
                    is_osi_approved=True,
                    is_fsf_libre=False,
                    is_deprecated_license_id=False,
                )
            
                assert "license" in result
                assert "message" in result
            
                call_args = mock_client.put.call_args
                payload = call_args[1]["data"]
                assert payload["name"] == "Custom License"
                assert payload["licenseId"] == "CUSTOM-1.0"
                assert payload["licenseText"] == "Full license text..."
                assert payload["header"] == "Header..."
                assert payload["template"] == "Template..."
                assert payload["comment"] == "This is custom"
                assert payload["seeAlso"] == ["https://example.com/license"]
                assert payload["isOsiApproved"] is True

        @pytest.mark.asyncio
        async def test_create_license_error(self, register_tools):
            """Test create_license error handling."""
            with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
                mock_client = AsyncMock()
                error = DependencyTrackError("Invalid license data")
                error.details = {"status": 400, "message": "Validation failed"}
                mock_client.put = AsyncMock(side_effect=error)
                mock_get_instance.return_value = mock_client

                tool = find_tool(register_tools, "create_license")
                assert tool is not None
                result = await tool.fn(name="Invalid License")

                assert "error" in result
                assert "details" in result


    class TestDeleteLicenseTool:
        """Tests for delete_license tool."""

        @pytest.mark.asyncio
        async def test_delete_license_success(self, register_tools):
            """Test deleting a license."""
            with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
                mock_client = AsyncMock()
                mock_client.delete = AsyncMock()
                mock_get_instance.return_value = mock_client
            
                tool = find_tool(register_tools, "delete_license")
                assert tool is not None
                result = await tool.fn(license_id="CUSTOM-1.0")
            
                assert "message" in result
                assert "deleted successfully" in result["message"]
                mock_client.delete.assert_called_once_with("/license/CUSTOM-1.0")

        @pytest.mark.asyncio
        async def test_delete_license_not_found(self, register_tools):
            """Test deleting a license that doesn't exist."""
            with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
                mock_client = AsyncMock()
                error = DependencyTrackError("License not found")
                error.details = {"status": 404}
                mock_client.delete = AsyncMock(side_effect=error)
                mock_get_instance.return_value = mock_client

                tool = find_tool(register_tools, "delete_license")
                assert tool is not None
                result = await tool.fn(license_id="UNKNOWN")

                assert "error" in result
                assert "details" in result

        @pytest.mark.asyncio
        async def test_delete_license_protected(self, register_tools):
            """Test deleting a protected (SPDX) license."""
            with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
                mock_client = AsyncMock()
                error = DependencyTrackError("Cannot delete SPDX license")
                error.details = {"status": 403, "message": "License is protected"}
                mock_client.delete = AsyncMock(side_effect=error)
                mock_get_instance.return_value = mock_client

                tool = find_tool(register_tools, "delete_license")
                assert tool is not None
                result = await tool.fn(license_id="MIT")

                assert "error" in result
